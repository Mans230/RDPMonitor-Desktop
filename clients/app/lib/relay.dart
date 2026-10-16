import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart' show AEADParameters, AESEngine, GCMBlockCipher, KeyParameter;

class RelayException implements Exception {
  final String message;
  const RelayException(this.message);
  @override
  String toString() => message;
}

final _uuid = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');
final _token = RegExp(r'^[A-Za-z0-9_-]{43}$');
String _id(dynamic value) {
  if (value is! String || !_uuid.hasMatch(value)) throw const RelayException('Invalid relay identifier.');
  return value;
}
Uint8List _secret(dynamic value) {
  try {
    if (value is! String || !_token.hasMatch(value)) throw const FormatException();
    final bytes = base64Url.decode('$value=');
    if (bytes.length != 32 || _encode(bytes) != value) throw const FormatException();
    return bytes;
  } catch (_) {
    throw const RelayException('Invalid relay credential.');
  }
}
String _encode(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
bool _keys(Map<String, dynamic> value, Set<String> keys) => value.length == keys.length && keys.every(value.containsKey);

/// HTTP is permitted only in debug builds, and only to a numeric loopback IP.
String normalizeRelayOrigin(String value) {
  try {
    if (value.isEmpty || value.length > 2048 || RegExp(r'[\x00-\x20\x7f\\]').hasMatch(value)) throw const FormatException();
    // Normalize the raw hostname before Uri percent-escapes Unicode hosts.
    final parts = RegExp(r'^(https?)://(\[[^\]]+\]|[^/:?#]+)(?::([0-9]+))?/?$', caseSensitive: false).firstMatch(value);
    if (parts == null || parts[2]!.contains('%') || parts[2]!.contains('@')) throw const FormatException();
    final rawHost = parts[2]!;
    final host = rawHost.startsWith('[') ? rawHost.substring(1, rawHost.length - 1).toLowerCase() : DomainUtils.toIDN(rawHost.toLowerCase());
    final uri = Uri.parse(value);
    final ip = InternetAddress.tryParse(host);
    if (uri.scheme != 'https' && !(kDebugMode && uri.scheme == 'http' && ip != null && ip.isLoopback)) throw const FormatException();
    if (uri.port < 1 || uri.port > 65535) throw const FormatException();
    return Uri(scheme: uri.scheme, host: host, port: uri.hasPort && uri.port != (uri.scheme == 'https' ? 443 : 80) ? uri.port : null).toString();
  } catch (_) {
    throw const RelayException('Relay must be an HTTPS origin without credentials or a path.');
  }
}

class RelayRoute {
  final String origin;
  final String routeId;
  final String token;
  RelayRoute({required String origin, required String routeId, required String token})
      : origin = normalizeRelayOrigin(origin), routeId = _id(routeId), token = token {
    _secret(token);
  }
  factory RelayRoute.fromJson(Map<String, dynamic> value) {
    if (!_keys(value, {'origin', 'routeId', 'token'}) || value['origin'] is! String || value['token'] is! String) {
      throw const RelayException('Invalid protected relay route.');
    }
    final route = RelayRoute(origin: value['origin'], routeId: _id(value['routeId']), token: value['token']);
    if (route.origin != value['origin']) throw const RelayException('Relay route origin is not canonical.');
    return route;
  }
  Map<String, dynamic> toJson() => {'origin': origin, 'routeId': routeId, 'token': token};
}

class RelayPreferences {
  static const _key = 'rdpmonitor.relay-administration.v1';
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
  );
  final String origin;
  final String adminKey;
  RelayPreferences({required String origin, required this.adminKey}) : origin = normalizeRelayOrigin(origin) {
    _secret(adminKey);
  }
  static Future<RelayPreferences?> load() async {
    final raw = await _storage.read(key: _key);
    if (raw == null) return null;
    try {
      final value = jsonDecode(raw);
      if (value is! Map<String, dynamic> || !_keys(value, {'origin', 'adminKey'}) || value['origin'] is! String || value['adminKey'] is! String) {
        throw const FormatException();
      }
      return RelayPreferences(origin: value['origin'], adminKey: value['adminKey']);
    } catch (_) {
      throw const RelayException('Protected relay settings are invalid. Replace them in relay settings.');
    }
  }
  Future<void> save() async {
    final raw = jsonEncode({'origin': origin, 'adminKey': adminKey});
    await _storage.write(key: _key, value: raw);
    if (await _storage.read(key: _key) != raw) throw const RelayException('Protected relay settings could not be verified.');
  }
  static Future<void> clear() => _storage.delete(key: _key);
}

class _Invitation {
  final String origin;
  final Uint8List secret;
  _Invitation(this.origin, this.secret);
  static _Invitation parse(String value, String kind) {
    try {
      if (value.length > 4096) throw const FormatException();
      final uri = Uri.parse(value.trim());
      final query = uri.queryParametersAll;
      if (uri.scheme != 'rdpmonitor' || uri.authority != kind || uri.path.isNotEmpty ||
          uri.query.split('&').any((part) => part.isEmpty || !part.contains('=')) ||
          query.length != 2 || query['v']?.length != 1 || query['v']?.single != '1' || query['relay']?.length != 1) {
        throw const FormatException();
      }
      return _Invitation(normalizeRelayOrigin(query['relay']!.single), _secret(uri.fragment));
    } catch (_) {
      throw const RelayException('Connection invitation is invalid or uses an unsupported version.');
    }
  }
}

class RelayInstallationInvitation {
  final String invitation;
  final DateTime expires;
  const RelayInstallationInvitation({required this.invitation, required this.expires});
}

class RelayAdminClient {
  final _RelayHttp _http;
  RelayAdminClient({required String origin, required String adminKey}) : _http = _RelayHttp(normalizeRelayOrigin(origin), token: adminKey) {
    _secret(adminKey);
  }
  Future<RelayInstallationInvitation> createInstallationInvitation({int ttlSeconds = 900}) async {
    if (ttlSeconds < 1 || ttlSeconds > 3600) throw const RelayException('Invitation lifetime must be between 1 and 3600 seconds.');
    final value = await _http.request('POST', '/api/v1/installations', body: {'ttl_seconds': ttlSeconds});
    if (value['invitation'] is! String || value['expires'] is! int) throw const RelayException('Relay returned an invalid installation invitation.');
    final invitation = _Invitation.parse(value['invitation'], 'install');
    if (invitation.origin != _http.origin) throw const RelayException('Relay returned an invitation for a different origin.');
    return RelayInstallationInvitation(invitation: value['invitation'], expires: DateTime.fromMillisecondsSinceEpoch((value['expires'] as int) * 1000, isUtc: true));
  }
  Future<List<Map<String, dynamic>>> agents() async {
    final value = await _http.request('GET', '/api/v1/agents');
    if (value['agents'] is! List || (value['agents'] as List).length > 256) throw const RelayException('Relay returned an invalid agent list.');
    return (value['agents'] as List).map((entry) {
      if (entry is! Map<String, dynamic>) throw const RelayException('Relay returned an invalid agent record.');
      _id(entry['route_id']);
      _id(entry['agent_id']);
      if (entry['name'] is! String || entry['online'] is! bool || entry['revoked'] is! bool || entry['created_at'] is! int) {
        throw const RelayException('Relay returned an invalid agent record.');
      }
      return Map<String, dynamic>.from(entry);
    }).toList();
  }
  Future<void> revokeAgent(String routeId) async {
    final value = await _http.request('DELETE', '/api/v1/agents/${_id(routeId)}');
    if (value['revoked'] != true) throw const RelayException('Relay did not confirm revocation.');
  }
  void close() => _http.close();
}

class _RelayHttp {
  final String origin;
  final String? token;
  final HttpClient _client = HttpClient()..connectionTimeout = const Duration(seconds: 15)..findProxy = ((_) => 'DIRECT');
  bool _closed = false;
  _RelayHttp(this.origin, {this.token});
  Future<Map<String, dynamic>> request(String method, String path, {Map<String, dynamic>? body}) async {
    if (_closed) throw const RelayException('Relay connection is closed.');
    try {
      return await _request(method, path, body).timeout(const Duration(seconds: 25), onTimeout: () {
        close();
        throw const RelayException('Relay request timed out.');
      });
    } on RelayException { rethrow; } catch (_) { throw const RelayException('Secure relay connection failed.'); }
  }
  Future<Map<String, dynamic>> _request(String method, String path, Map<String, dynamic>? body) async {
    final request = await _client.openUrl(method, Uri.parse(origin).replace(path: path));
    if (_closed) { request.abort(); throw const RelayException('Relay connection is closed.'); }
    request.followRedirects = false;
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    if (token != null) request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
    if (body != null) {
      final bytes = utf8.encode(jsonEncode(body));
      if (bytes.length > 16384) { request.abort(); throw const RelayException('Relay request exceeds the size limit.'); }
      request.headers.contentType = ContentType.json;
      request.add(bytes);
    }
    final response = await request.close();
    final bytes = await response.fold<List<int>>([], (buffer, chunk) {
      if (buffer.length + chunk.length > 262144) { close(); throw const RelayException('Relay response exceeds the size limit.'); }
      buffer.addAll(chunk);
      return buffer;
    });
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw RelayException('Relay request failed (${response.statusCode}). Check availability and credential expiry.');
    }
    final value = jsonDecode(utf8.decode(bytes));
    if (value is! Map<String, dynamic>) throw const RelayException('Relay returned an invalid response.');
    return value;
  }
  void close() { _closed = true; _client.close(force: true); }
}

/// Authenticated bootstrap data. Only ciphertext and SHA256(secret) cross the broker API.
class RelayPairing {
  final String agentId;
  final String fingerprint;
  final String pairingCode;
  final String name;
  final DateTime expires;
  final RelayRoute route;
  String get endpoint => 'https://$agentId.rdpmonitor.invalid';
  RelayPairing._(this.agentId, this.fingerprint, this.pairingCode, this.name, this.expires, this.route);

  static Future<RelayPairing> lookup(String connectionCode) async {
    final invitation = _Invitation.parse(connectionCode, 'pair');
    final http = _RelayHttp(invitation.origin);
    try {
      final lookup = sha256.convert(invitation.secret).toString();
      final value = await http.request('GET', '/api/v1/pairings/$lookup');
      if (!_keys(value, {'ciphertext'}) || value['ciphertext'] is! String) throw const RelayException('Relay returned an invalid connection envelope.');
      return decode(connectionCode, value['ciphertext']);
    } finally { http.close(); }
  }

  /// Pure protocol entry point, also used to check cross-language security vectors.
  static RelayPairing decode(String connectionCode, String ciphertext, {DateTime? now}) {
    final invitation = _Invitation.parse(connectionCode, 'pair');
    Map<String, dynamic> payload;
    try {
      if (ciphertext.length < 38 || ciphertext.length > 10923 || !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(ciphertext)) throw const FormatException();
      final raw = base64Url.decode(base64Url.normalize(ciphertext));
      if (raw.length < 28 || raw.length > 8192 || _encode(raw) != ciphertext) throw const FormatException();
      final cipher = GCMBlockCipher(AESEngine())..init(false, AEADParameters(KeyParameter(invitation.secret), 128,
        Uint8List.sublistView(raw, 0, 12), Uint8List.fromList(utf8.encode('RDPMonitor.Pairing.v1\n${invitation.origin}'))));
      final decoded = jsonDecode(utf8.decode(cipher.process(Uint8List.sublistView(raw, 12))));
      if (decoded is! Map<String, dynamic>) throw const FormatException();
      payload = decoded;
    } catch (_) {
      throw const RelayException('Connection code could not be authenticated.');
    }
    if (!_keys(payload, {'v', 'agent_id', 'route_id', 'fingerprint', 'pairing_code', 'route_token', 'expires', 'name'}) ||
        payload['v'] is! int || payload['v'] != 1) {
      throw const RelayException('Connection code uses an unsupported payload.');
    }
    final agentId = _id(payload['agent_id']);
    final routeId = _id(payload['route_id']);
    if (payload['fingerprint'] is! String || !RegExp(r'^[0-9a-f]{64}$').hasMatch(payload['fingerprint'])) throw const RelayException('Connection code has an invalid fingerprint.');
    if (payload['pairing_code'] is! String || !RegExp(r'^[A-Za-z0-9_-]{16,128}$').hasMatch(payload['pairing_code'])) throw const RelayException('Connection code has an invalid enrollment capability.');
    _secret(payload['route_token']);
    if (payload['name'] is! String || (payload['name'] as String).runes.isEmpty || (payload['name'] as String).runes.length > 128 || RegExp(r'[\x00-\x1f]').hasMatch(payload['name'])) {
      throw const RelayException('Connection code has an invalid machine name.');
    }
    final current = (now ?? DateTime.now()).millisecondsSinceEpoch / 1000;
    final expiry = payload['expires'];
    if (expiry is! int || expiry <= current || expiry > current + 600) throw const RelayException('Connection code expired or has an invalid lifetime. Check both machines’ clocks.');
    return RelayPairing._(agentId, payload['fingerprint'], payload['pairing_code'], payload['name'],
      DateTime.fromMillisecondsSinceEpoch(expiry * 1000, isUtc: true), RelayRoute(origin: invitation.origin, routeId: routeId, token: payload['route_token']));
  }
}

/// Owns all bridges for one HttpClient; never shares the agent TLS context with the broker.
class RelayTransport {
  final RelayRoute route;
  final Uri agentOrigin;
  final SecurityContext context;
  final bool Function(X509Certificate)? onBadCertificate;
  final Set<_RelayBridge> _bridges = {};
  bool _closed = false;
  RelayTransport({required this.route, required this.agentOrigin, required this.context, this.onBadCertificate});

  void attach(HttpClient client) {
    client.findProxy = (_) => 'DIRECT';
    client.connectionFactory = (uri, proxyHost, proxyPort) {
      if (_closed || uri.scheme != 'https' || uri.host != agentOrigin.host || uri.port != agentOrigin.port || proxyHost != null || _bridges.length >= 16) {
        return Future.error(const RelayException('Relay connection is closed or its destination is invalid.'));
      }
      late final _RelayBridge bridge;
      bridge = _RelayBridge(route, agentOrigin, context, onBadCertificate, () => _bridges.remove(bridge));
      _bridges.add(bridge);
      // Return promptly: HttpClient starts connectionTimeout only after obtaining this task.
      final task = ConnectionTask.fromSocket<Socket>(bridge.socket, bridge.close);
      bridge.start();
      return Future.value(task);
    };
  }
  void close() {
    if (_closed) return;
    _closed = true;
    for (final bridge in _bridges.toList()) { bridge.close(); }
  }
}

class _RelayBridge {
  final RelayRoute route;
  final Uri agentOrigin;
  final SecurityContext context;
  final bool Function(X509Certificate)? onBadCertificate;
  final void Function() onClose;
  final Completer<Socket> _ready = Completer<Socket>();
  final Completer<Socket> _accepted = Completer<Socket>();
  final HttpClient _outer = HttpClient()..connectionTimeout = const Duration(seconds: 15)..findProxy = ((_) => 'DIRECT');
  ServerSocket? _listener;
  StreamSubscription<Socket>? _listenerSubscription;
  ConnectionTask<Socket>? _localTask;
  Socket? _local;
  Socket? _peer;
  Socket? _outerSocket;
  SecureSocket? _secure;
  WebSocket? _websocket;
  Timer? _deadline;
  bool _closed = false;
  Future<Socket> get socket => _ready.future;
  _RelayBridge(this.route, this.agentOrigin, this.context, this.onBadCertificate, this.onClose);

  void start() {
    _deadline = Timer(const Duration(seconds: 15), close);
    unawaited(_start());
  }
  void _check() { if (_closed) throw const RelayException('Relay connection was cancelled.'); }

  Future<void> _start() async {
    try {
      final websocket = await _upgrade();
      _websocket = websocket;
      if (_closed) { await websocket.close(); return; }
      websocket.pingInterval = const Duration(seconds: 20);
      final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      _listener = listener;
      if (_closed) { await listener.close(); return; }
      _listenerSubscription = listener.listen((peer) {
        if (_closed || _peer != null) { peer.destroy(); return; }
        _peer = peer;
        _accepted.complete(peer);
        unawaited(listener.close());
      }, onError: (Object error) { close(); });
      final task = await Socket.startConnect(InternetAddress.loopbackIPv4, listener.port);
      _localTask = task;
      if (_closed) task.cancel();
      final local = await task.socket;
      _local = local;
      if (_closed) { local.destroy(); return; }
      final peer = await _accepted.future;
      _check();
      // Another local process cannot substitute a socket into the TLS bridge.
      if (peer.remotePort != local.port || !peer.remoteAddress.isLoopback) throw const RelayException('Relay loopback connection was interrupted.');
      final outgoing = websocket.addStream(_chunks(peer));
      final incoming = peer.addStream(_binary(websocket));
      unawaited(_pump(outgoing));
      unawaited(_pump(incoming));
      unawaited(_finishWebSocket(outgoing, incoming, websocket));
      // A factory replaces Dart's TLS connector. Never return the plaintext local socket.
      final secure = await SecureSocket.secure(local, host: agentOrigin.host, context: context, onBadCertificate: onBadCertificate);
      _secure = secure;
      if (_closed) { secure.destroy(); return; }
      _deadline?.cancel();
      _ready.complete(secure);
    } catch (_) { close(); }
  }

  Future<WebSocket> _upgrade() async {
    final request = await _outer.getUrl(Uri.parse(route.origin).replace(path: '/api/v1/connect/${route.routeId}'));
    if (_closed) { request.abort(); _check(); }
    request.followRedirects = false;
    final random = Random.secure();
    final nonce = base64Encode(List<int>.generate(16, (_) => random.nextInt(256)));
    request.headers
      ..set(HttpHeaders.authorizationHeader, 'Bearer ${route.token}')
      ..set(HttpHeaders.connectionHeader, 'Upgrade')
      ..set(HttpHeaders.upgradeHeader, 'websocket')
      ..set('Sec-WebSocket-Key', nonce)
      ..set('Sec-WebSocket-Version', '13');
    final response = await request.close();
    _check();
    final expected = base64Encode(sha1.convert(utf8.encode('${nonce}258EAFA5-E914-47DA-95CA-C5AB0DC85B11')).bytes);
    if (response.statusCode != HttpStatus.switchingProtocols ||
        !(response.headers[HttpHeaders.connectionHeader] ?? []).any((v) => v.split(',').any((token) => token.trim().toLowerCase() == 'upgrade')) ||
        response.headers.value(HttpHeaders.upgradeHeader)?.toLowerCase() != 'websocket' ||
        response.headers.value('Sec-WebSocket-Accept') != expected ||
        response.headers.value('Sec-WebSocket-Extensions') != null || response.headers.value('Sec-WebSocket-Protocol') != null) {
      throw const RelayException('Relay refused the tunnel connection.');
    }
    final socket = await response.detachSocket();
    _outerSocket = socket;
    if (_closed) { socket.destroy(); _check(); }
    // No extensions were offered. Bound messages before the SDK assembles their payload.
    return WebSocket.fromUpgradedSocket(socket, serverSide: false, compression: CompressionOptions.compressionOff, maxPayloadLength: 65536);
  }

  Stream<List<int>> _chunks(Socket source) async* {
    await for (final data in source) {
      for (var offset = 0; offset < data.length; offset += 65536) {
        if (_closed) return;
        yield Uint8List.sublistView(data, offset, min(offset + 65536, data.length));
      }
    }
  }
  Stream<List<int>> _binary(WebSocket source) async* {
    await for (final message in source) {
      if (_closed) return;
      if (message is! List<int> || message.length > 65536) throw const RelayException('Relay sent an invalid tunnel frame.');
      yield message;
    }
  }
  Future<void> _pump(Future<void> pump) async {
    try { await pump; } catch (_) { /* The whole transport closes on either pump failure. */ }
    finally { close(); }
  }
  Future<void> _finishWebSocket(Future<void> outgoing, Future<void> incoming, WebSocket websocket) async {
    try { await Future.wait([outgoing, incoming]); } catch (_) { /* Already surfaced through transport teardown. */ }
    try { await websocket.close(); } catch (_) { /* The owned underlying socket is already destroyed. */ }
  }
  void close() {
    if (_closed) return;
    _closed = true;
    _deadline?.cancel();
    _localTask?.cancel();
    _secure?.destroy();
    _local?.destroy();
    _peer?.destroy();
    _websocket?.pingInterval = null;
    _outerSocket?.destroy();
    _outer.close(force: true);
    final subscription = _listenerSubscription;
    if (subscription != null) unawaited(_ignore(subscription.cancel()));
    final listener = _listener;
    if (listener != null) unawaited(_ignore(listener.close()));
    if (!_ready.isCompleted) _ready.completeError(const RelayException('Relay connection failed or was cancelled.'));
    // Unblock setup awaiting accept without creating an unobserved error future.
    if (!_accepted.isCompleted) {
      final local = _local;
      if (local != null) _accepted.complete(local);
    }
    onClose();
  }
  Future<void> _ignore(Future<dynamic> future) async { try { await future; } catch (_) { /* Synchronous close has already revoked ownership. */ } }
}
