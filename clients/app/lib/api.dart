import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:basic_utils/basic_utils.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter/foundation.dart' show compute;
import 'relay.dart';

Map<String, dynamic> object(dynamic value) => value is Map ? Map<String, dynamic>.from(value) : <String, dynamic>{};
List<Map<String, dynamic>> records(dynamic value) => value is List ? value.map(object).toList() : [];
String requestId() {
  final random = Random.secure();
  final bytes = List.generate(16, (_) => random.nextInt(256));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  final hex = bytes.map((v) => v.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}';
}
String normalizedPin(String value) => value.replaceAll(RegExp(r'[^a-fA-F0-9]'), '').toLowerCase();
Map<String, String> createIdentity(String commonName) {
  final pair = CryptoUtils.generateRSAKeyPair(keySize: 2048);
  final key = pair.privateKey as RSAPrivateKey;
  return {'key': CryptoUtils.encodeRSAPrivateKeyToPem(key),
    'csr': X509Utils.generateRsaCsrPem({'CN': commonName}, key, pair.publicKey as RSAPublicKey)};
}

class ApiException implements Exception {
  final String message;
  final int? status;
  final String? correlation;
  ApiException(this.message, {this.status, this.correlation});
  @override
  String toString() => '$message${correlation == null ? '' : ' (reference: $correlation)'}';
}

// Contract dates are local calendar days, never certificate instants or UTC timestamps.
DateTime? parseCalendarDate(dynamic value) {
  if (value == null) return null;
  if (value is! String || !RegExp(r'^\d{4}-\d{2}-\d{2}$').hasMatch(value)) {
    throw const FormatException('Use a calendar date in YYYY-MM-DD format.');
  }
  final year = int.parse(value.substring(0, 4));
  final month = int.parse(value.substring(5, 7));
  final day = int.parse(value.substring(8, 10));
  final date = DateTime(year, month, day);
  if (year < 1 || date.year != year || date.month != month || date.day != day) {
    throw const FormatException('Invalid calendar date.');
  }
  return date;
}

String calendarDate(DateTime date) =>
  '${date.year.toString().padLeft(4, '0')}-${date.month.toString().padLeft(2, '0')}-${date.day.toString().padLeft(2, '0')}';

// Parse decimal input as integers; binary floating point must never round billing metadata.
int? parseCostMinor(String input) {
  final value = input.trim();
  if (value.isEmpty) return null;
  if (!RegExp(r'^\d+(?:\.\d{1,2})?$').hasMatch(value)) {
    throw const FormatException('Enter a nonnegative amount with at most two decimal places.');
  }
  final parts = value.split('.');
  final minor = BigInt.parse(parts[0]) * BigInt.from(100) +
    BigInt.parse(parts.length == 1 ? '0' : parts[1].padRight(2, '0'));
  if (minor > BigInt.parse('9223372036854775807')) {
    throw const FormatException('Amount is too large.');
  }
  return minor.toInt();
}

String costDecimal(int minor) => '${minor ~/ 100}.${(minor % 100).toString().padLeft(2, '0')}';

class MachineProfile {
  final String id;
  String name;
  String group;
  String endpoint;
  final String certificate;
  final String privateKey;
  final String ca;
  final String fingerprint;
  final String deviceId;
  final String role;
  final RelayRoute? relay;
  DateTime? expiresOn;
  DateTime? renewOn;
  int? costMinor;
  String currency;
  String billingPeriod;
  MachineProfile({required this.id, required this.name, required this.group, required this.endpoint,
    required this.certificate, required this.privateKey, required this.ca, required this.fingerprint,
    required this.deviceId, required this.role, this.relay, this.expiresOn, this.renewOn,
    this.costMinor, this.currency = 'USD', this.billingPeriod = 'monthly'});
  factory MachineProfile.fromJson(Map<String, dynamic> j) => MachineProfile(id: j['id'], name: j['name'], group: j['group'] ?? '',
    endpoint: j['endpoint'], certificate: j['certificate'], privateKey: j['privateKey'], ca: j['ca'],
    fingerprint: j['fingerprint'], deviceId: j['deviceId'], role: j['role'] ?? 'unknown',
    relay: j['relay'] == null ? null : RelayRoute.fromJson(Map<String, dynamic>.from(j['relay'])),
    expiresOn: parseCalendarDate(j['expiresOn']), renewOn: parseCalendarDate(j['renewOn']),
    costMinor: _storedCost(j['costMinor']), currency: _storedCurrency(j['currency']),
    billingPeriod: _storedPeriod(j['billingPeriod']));
  Map<String, dynamic> toJson() => {'id': id, 'name': name, 'group': group, 'endpoint': endpoint,
    'certificate': certificate, 'privateKey': privateKey, 'ca': ca, 'fingerprint': fingerprint, 'deviceId': deviceId, 'role': role,
    if (relay != null) 'relay': relay!.toJson(),
    if (expiresOn != null) 'expiresOn': calendarDate(expiresOn!),
    if (renewOn != null) 'renewOn': calendarDate(renewOn!),
    if (costMinor != null) 'costMinor': costMinor,
    'currency': currency, 'billingPeriod': billingPeriod};

  MachineProfile withCredentials({required String certificate, required String privateKey,
    required String ca, required String deviceId, required String role}) =>
    MachineProfile(id: id, name: name, group: group, endpoint: endpoint,
      certificate: certificate, privateKey: privateKey, ca: ca, fingerprint: fingerprint,
      deviceId: deviceId, role: role, relay: relay, expiresOn: expiresOn, renewOn: renewOn,
      costMinor: costMinor, currency: currency, billingPeriod: billingPeriod);

  static int? _storedCost(dynamic value) {
    if (value == null) return null;
    if (value is! int || value < 0) throw const FormatException('Invalid stored cost.');
    return value;
  }
  static String _storedCurrency(dynamic value) {
    if (value == null) return 'USD';
    if (value is! String || !RegExp(r'^[A-Z]{3}$').hasMatch(value)) {
      throw const FormatException('Invalid stored currency.');
    }
    return value;
  }
  static String _storedPeriod(dynamic value) {
    if (value == null) return 'monthly';
    if (!['monthly', 'yearly', 'one-time'].contains(value)) throw const FormatException('Invalid stored billing period.');
    return value as String;
  }
}

class ProfileVault {
  // AES-GCM with Credential Manager-protected key on Windows; Android Keystore and iOS Keychain.
  final FlutterSecureStorage storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
  );
  Future<List<MachineProfile>> load() async {
    final slot = await storage.read(key: 'rdpmonitor.profile-slot');
    if (slot == null) return [];
    final raw = await storage.read(key: 'rdpmonitor.profiles.$slot');
    if (raw == null) throw ApiException('The secure profile record is missing. Restore local access before enrolling again.');
    dynamic decoded;
    try { decoded = jsonDecode(raw); } catch (_) { throw ApiException('The secure profile record is unreadable. Restore local access before enrolling again.'); }
    // Fail closed: a truncated or tampered record must never be read as "no
    // profiles", or the next save silently overwrites the stored profiles.
    if (decoded is! List || decoded.any((entry) => entry is! Map)) {
      throw ApiException('The secure profile record is invalid. Restore local access before enrolling again.');
    }
    return decoded.map((entry) => MachineProfile.fromJson(object(entry))).toList();
  }
  Future<void> save(List<MachineProfile> profiles) async {
    final oldSlot = await storage.read(key: 'rdpmonitor.profile-slot');
    final slot = oldSlot == '0' ? '1' : '0';
    final data = jsonEncode(profiles.map((p) => p.toJson()).toList());
    await storage.write(key: 'rdpmonitor.profiles.$slot', value: data);
    if (await storage.read(key: 'rdpmonitor.profiles.$slot') != data) throw ApiException('Secure profile write could not be verified.');
    await storage.write(key: 'rdpmonitor.profile-slot', value: slot);
    if (oldSlot != null) {
      // The pointer write is the commit. Cleanup must not report a failed save
      // after committing, which would make callers roll back only in memory.
      // A retained previous generation stays in the OS vault and is overwritten next save.
      try { await storage.delete(key: 'rdpmonitor.profiles.$oldSlot'); } catch (_) { /* committed */ }
    }
  }
}

Uri serverUri(String endpoint) {
  final uri = Uri.tryParse(endpoint.trim());
  if (uri == null || uri.scheme != 'https' || uri.host.isEmpty || uri.userInfo.isNotEmpty || (uri.path.isNotEmpty && uri.path != '/') || uri.hasQuery || uri.hasFragment) {
    throw ApiException('Use an HTTPS origin, for example https://server.example:9443. Credentials and paths are not allowed.');
  }
  return uri;
}

class AgentApi {
  final MachineProfile profile;
  late final HttpClient _client;
  RelayTransport? _relayTransport;
  AgentApi(this.profile) {
    if (profile.relay != null && serverUri(profile.endpoint).toString() != 'https://${profile.id}.rdpmonitor.invalid') {
      throw ApiException('The protected relay profile has an invalid agent origin.');
    }
    final context = SecurityContext(withTrustedRoots: false);
    if (Platform.isIOS) {
      final der = base64Decode(profile.ca.replaceAll(RegExp(r'-----[^-]+-----|\s'), ''));
      context.setTrustedCertificatesBytes(der);
      final password = requestId();
      final p12 = Pkcs12Utils.generatePkcs12(profile.privateKey, [profile.certificate, profile.ca],
        password: password, certPbe: 'PBE-SHA1-3DES');
      context.usePrivateKeyBytes(p12, password: password);
    } else {
      context.setTrustedCertificatesBytes(utf8.encode(profile.ca));
      context.useCertificateChainBytes(utf8.encode(profile.certificate));
      context.usePrivateKeyBytes(utf8.encode(profile.privateKey));
    }
    _client = HttpClient(context: context)..connectionTimeout = const Duration(seconds: 15)..idleTimeout = const Duration(seconds: 20);
    final route = profile.relay;
    if (route != null) {
      _relayTransport = RelayTransport(route: route, agentOrigin: serverUri(profile.endpoint), context: context)..attach(_client);
    }
    // Normal connections use issued CA, hostname verification, and mutual TLS. Never accept arbitrary certificates.
  }
  Uri uri(String path, [Map<String, String>? query]) => serverUri(profile.endpoint).replace(path: '/api/v1$path', queryParameters: query);
  Future<HttpClientResponse> _send(String method, String path, {dynamic body, Map<String, String>? query}) async {
    final request = await _client.openUrl(method, uri(path, query)).timeout(const Duration(seconds: 20));
    request.followRedirects = false;
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    if (body != null) {
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(body));
    }
    return request.close().timeout(const Duration(seconds: 30));
  }
  static const int _maxErrorBodyBytes = 8 * 1024;
  static const int _maxBodyBytes = 64 * 1024;
  Future<String> _body(HttpClientResponse response, [int limit = _maxBodyBytes]) async {
    // Read at most `limit` bytes so a hostile or broken peer cannot make the client
    // buffer an unbounded body before it has validated the status code.
    final bytes = await response.fold<List<int>>([], (buffer, chunk) {
      if (buffer.length < limit) buffer.addAll(chunk.take(limit - buffer.length));
      return buffer;
    });
    return utf8.decode(bytes, allowMalformed: true);
  }
  Future<Map<String, dynamic>> call(String method, String path, {dynamic body, Map<String, String>? query}) async {
    try {
      final response = await _send(method, path, body: body, query: query);
      final bytes = await response.fold<List<int>>([], (buffer, chunk) {
        if (buffer.length + chunk.length > 32 * 1024 * 1024) throw ApiException('Response exceeds the client safety limit.');
        buffer.addAll(chunk); return buffer;
      }).timeout(const Duration(seconds: 30));
      Map<String, dynamic> value;
      try { value = object(jsonDecode(utf8.decode(bytes))); } catch (_) { throw ApiException('Agent returned an invalid response.', status: response.statusCode); }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        final error = object(value['error']);
        throw ApiException(error['message']?.toString() ?? 'Agent request failed.', status: response.statusCode, correlation: error['correlation_id']?.toString());
      }
      return value;
    } on ApiException { rethrow; } catch (error) { throw ApiException('Secure connection failed: $error'); }
  }
  Future<void> download(String id, File destination, {String? expectedHash}) async {
    final response = await _send('GET', '/artifacts/${Uri.encodeComponent(id)}');
    if (response.statusCode != 200) {
      final text = await _body(response, _maxErrorBodyBytes);
      throw ApiException('Artifact download failed (${response.statusCode}): $text');
    }
    final temp = File('${destination.path}.rdpmonitor-${requestId()}.partial');
    try {
      final sink = temp.openWrite();
      try { await sink.addStream(response.timeout(const Duration(seconds: 60))); } finally { await sink.close(); }
      if (expectedHash != null && expectedHash.isNotEmpty) {
        final actual = await sha256.bind(temp.openRead()).first;
        if (actual.toString().toLowerCase() != expectedHash.toLowerCase()) throw ApiException('Artifact SHA256 did not match. Download discarded.');
      }
      if (await destination.exists()) await destination.delete();
      await temp.rename(destination.path);
    } catch (_) { if (await temp.exists()) await temp.delete(); rethrow; }
  }
  void close() {
    _relayTransport?.close();
    _client.close(force: true);
  }

  Future<Map<String, dynamic>> uploadChunk(String id, int offset, List<int> bytes) async {
    final request = await _client.putUrl(uri('/uploads/${Uri.encodeComponent(id)}', {'offset': '$offset'})).timeout(const Duration(seconds: 20));
    request.followRedirects = false;
    request.headers.contentType = ContentType.binary;
    request.contentLength = bytes.length;
    request.add(bytes);
    final response = await request.close().timeout(const Duration(seconds: 45));
    final value = object(jsonDecode(await _body(response)));
    if (response.statusCode < 200 || response.statusCode >= 300) throw ApiException(object(value['error'])['message']?.toString() ?? 'Upload chunk failed.', status: response.statusCode);
    return object(value['upload']);
  }

  Future<MachineProfile> renew() async {
    final identity = await compute(createIdentity, profile.deviceId);
    final result = await call('POST', '/devices/renew', body: {'csr': identity['csr']});
    final device = object(result['device']);
    return profile.withCredentials(certificate: result['certificate'], privateKey: identity['key']!,
      ca: result['ca_certificate'] ?? profile.ca,
      deviceId: device['id'] ?? profile.deviceId, role: device['role'] ?? profile.role);
  }

  static Future<MachineProfile> enroll({required String endpoint, required String fingerprint, required String code,
    required String name, required String group, required String deviceName}) =>
      _enroll(endpoint: endpoint, fingerprint: fingerprint, code: code, name: name, group: group, deviceName: deviceName);

  static Future<MachineProfile> enrollRelay({required String connectionCode, required String name,
    required String group, required String deviceName, Future<void> Function(MachineProfile)? onIssued,
    Future<void> Function()? onEnrolling}) async {
    final pairing = await RelayPairing.lookup(connectionCode);
    return _enroll(endpoint: pairing.endpoint, fingerprint: pairing.fingerprint, code: pairing.pairingCode,
      name: name.trim().isEmpty ? pairing.name : name, group: group, deviceName: deviceName,
      relay: pairing.route, expectedAgentId: pairing.agentId, expires: pairing.expires,
      onIssued: onIssued, onEnrolling: onEnrolling);
  }

  static Future<MachineProfile> _enroll({required String endpoint, required String fingerprint, required String code,
    required String name, required String group, required String deviceName, RelayRoute? relay,
    String? expectedAgentId, DateTime? expires, Future<void> Function(MachineProfile)? onIssued,
    Future<void> Function()? onEnrolling}) async {
    final origin = serverUri(endpoint);
    final pin = normalizedPin(fingerprint);
    if (pin.length != 64) throw ApiException('Enter the complete 64-digit SHA256 server fingerprint shown on the agent.');
    final context = SecurityContext(withTrustedRoots: false);
    bool acceptFingerprint(X509Certificate cert) => sha256.convert(cert.der).toString() == pin;
    final client = HttpClient(context: context)..connectionTimeout = const Duration(seconds: 15);
    client.badCertificateCallback = (cert, host, port) => host == origin.host && port == origin.port && acceptFingerprint(cert);
    final transport = relay == null ? null : (RelayTransport(route: relay, agentOrigin: origin,
      context: context, onBadCertificate: acceptFingerprint)..attach(client));
    Future<Map<String, dynamic>> pinned(String method, String path, [Map<String, dynamic>? body]) async {
      final request = await client.openUrl(method, origin.replace(path: '/api/v1$path'));
      request.followRedirects = false;
      // A rootless context admits TLS only through the exact-fingerprint callback.
      // The handshake completes before openUrl returns and before sending the code.
      if (body != null) { request.headers.contentType = ContentType.json; request.write(jsonEncode(body)); }
      final response = await request.close().timeout(const Duration(seconds: 30));
      final certificate = response.certificate;
      if (certificate == null || sha256.convert(certificate.der).toString() != pin) throw ApiException('Server fingerprint mismatch.');
      final bytes = await response.fold<List<int>>([], (buffer, chunk) {
        if (buffer.length + chunk.length > 128 * 1024) {
          throw ApiException('Enrollment response exceeds the client safety limit.');
        }
        buffer.addAll(chunk); return buffer;
      }).timeout(const Duration(seconds: 30));
      final value = object(jsonDecode(utf8.decode(bytes)));
      if (response.statusCode < 200 || response.statusCode >= 300) throw ApiException(object(value['error'])['message']?.toString() ?? 'Enrollment failed.', status: response.statusCode);
      return value;
    }
    try {
      final health = await pinned('GET', '/health');
      if (expectedAgentId != null && health['agent_id'] != expectedAgentId) throw ApiException('Connection code agent identity mismatch.');
      final identity = await compute(createIdentity, deviceName.trim());
      if (expires != null && !DateTime.now().isBefore(expires)) throw ApiException('Connection code expired before enrollment. Generate a new code on the agent.');
      if (onEnrolling != null) await onEnrolling();
      final result = await pinned('POST', '/enroll', {'code': code.trim(), 'name': deviceName.trim(), 'csr': identity['csr']!});
      if (expectedAgentId != null && result['agent_id'] != expectedAgentId) throw ApiException('Enrolled agent identity mismatch.');
      final device = object(result['device']);
      final profile = MachineProfile(id: result['agent_id']?.toString() ?? health['agent_id'].toString(), name: name.trim(), group: group.trim(), endpoint: origin.toString(),
        certificate: result['certificate'], privateKey: identity['key']!, ca: result['ca_certificate'], fingerprint: pin,
        deviceId: device['id'], role: device['role'] ?? 'unknown', relay: relay);
      // Parse and load certificates before admitting a profile to secure storage.
      X509Utils.x509CertificateFromPem(profile.certificate);
      X509Utils.x509CertificateFromPem(profile.ca);
      final probe = AgentApi(profile);
      try {
        // Keep the issued identity recoverable before the one-use enrollment's final probe.
        if (onIssued != null) await onIssued(profile);
        await probe.call('GET', '/health');
      } finally { probe.close(); }
      return profile;
    } finally { transport?.close(); client.close(force: true); }
  }
}
