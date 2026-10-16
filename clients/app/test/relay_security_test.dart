import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/export.dart' show AEADParameters, AESEngine, GCMBlockCipher, KeyParameter;
import 'package:rdpmonitor/api.dart';
import 'package:rdpmonitor/relay.dart';

// Public deterministic interoperability material, never deployment credentials.
const _secret = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const _routeId = '22222222-2222-4222-8222-222222222222';
const _agentId = '11111111-1111-4111-8111-111111111111';
const _origin = 'https://relay.example';
const _pythonCiphertext = 'AAECAwQFBgcICQoLPCC3fKCLtkTkJbWxk9hJXLLntgXBVm5NCVbIsSxYMZ85IZ_NgvAjqUWVTty5thkJ33tMrz-u07NN8lk7ItLN3sAM9krg4RZNPjLDAIjqfJhK46cWVFlxCZ-c_K0akdvsqZk7h8Ygqnv8fVzTKhRDHtgGAMqBpEf7L541rOCHDG_ZM2Kn1rapMmqAKsBfuy6jVJWBVFdw8WigfYYWl7fL1LHR922dir4bhwK6n7H0pJe_vqtL-cId2zq8r6MU543RZyn5jlK4uLtYOr-L3y-t24IfiBdfadaYBejF9nN7u891AfiNlE92UTcY0WyXK15jmqGLR68Cu4glWVVBpqhwsyb8yqKv6GUMRe1ANYUfCDjohvjvrKnzwARbCA5-m9EubyHkavOGi37bRWs2QPzDvNOZNCwF1_9i1EtcbtpXCNmHwSYZxCQT3-yaDBkNuSVAvzihpqYl-EVZvnQrQ2avBYjL7-YbKM8';
final _now = DateTime.fromMillisecondsSinceEpoch(1800000000000, isUtc: true);
String _code([String origin = _origin]) => Uri(scheme: 'rdpmonitor', host: 'pair', queryParameters: {'relay': origin, 'v': '1'}, fragment: _secret).toString();
Map<String, dynamic> _payload() => {'v': 1, 'agent_id': _agentId, 'route_id': _routeId, 'fingerprint': 'ab' * 32,
  'pairing_code': 'test_enrollment_capability_123456', 'route_token': _secret, 'expires': 1800000300, 'name': 'Fixture agent'};
String _encrypt(Map<String, dynamic> payload) {
  final nonce = Uint8List.fromList(List.generate(12, (index) => index));
  final cipher = GCMBlockCipher(AESEngine())..init(true, AEADParameters(KeyParameter(base64Url.decode('$_secret=')), 128,
    nonce, Uint8List.fromList(utf8.encode('RDPMonitor.Pairing.v1\n$_origin'))));
  return base64Url.encode([...nonce, ...cipher.process(Uint8List.fromList(utf8.encode(jsonEncode(payload))))]).replaceAll('=', '');
}

class _Identity {
  final String key;
  final String certificate;
  _Identity(String host) : this._(createIdentity(host), host);
  _Identity._(Map<String, String> identity, String host)
      : key = identity['key']!, certificate = X509Utils.generateSelfSignedCertificate(
          CryptoUtils.rsaPrivateKeyFromPem(identity['key']!), identity['csr']!, 2,
          sans: [host], cA: true, notBefore: DateTime.now().subtract(const Duration(hours: 1)));
  void use(SecurityContext context) {
    context.useCertificateChainBytes(utf8.encode(certificate));
    context.usePrivateKeyBytes(utf8.encode(key));
  }
}

class _Harness {
  final HttpServer agent;
  final HttpServer broker;
  final Set<Socket> tcp = {};
  final Set<Future<void>> sessions = {};
  final Completer<void> upgradeSeen = Completer<void>();
  final Completer<void> releaseUpgrade = Completer<void>();
  final bool delayUpgrade;
  int requests = 0;
  int streams = 0;
  int maxFrame = 0;
  bool sawClientCertificate = false;
  bool wireValid = true;
  bool plaintextVisible = false;
  _Harness._(this.agent, this.broker, this.delayUpgrade);
  RelayRoute get route => RelayRoute(origin: 'http://127.0.0.1:${broker.port}', routeId: _routeId, token: _secret);
  static Future<_Harness> start(_Identity server, _Identity client, {bool delayUpgrade = false}) async {
    final context = SecurityContext(withTrustedRoots: false);
    server.use(context);
    context.setTrustedCertificatesBytes(utf8.encode(client.certificate));
    context.setClientAuthoritiesBytes(utf8.encode(client.certificate));
    final agent = await HttpServer.bindSecure(InternetAddress.loopbackIPv4, 0, context, requestClientCertificate: true);
    final broker = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final harness = _Harness._(agent, broker, delayUpgrade);
    agent.listen((request) { unawaited(harness._agentRequest(request)); });
    broker.listen((request) {
      final session = harness._brokerRequest(request);
      harness.sessions.add(session);
      unawaited(session.whenComplete(() => harness.sessions.remove(session)));
    });
    return harness;
  }
  Future<void> _agentRequest(HttpRequest request) async {
    try {
      requests++;
      sawClientCertificate = request.certificate != null;
      final bytes = await request.fold<List<int>>([], (buffer, chunk) => buffer..addAll(chunk));
      request.response.add(bytes);
      await request.response.close();
    } catch (_) { /* Teardown can interrupt a deliberately cancelled request. */ }
  }
  Future<void> _brokerRequest(HttpRequest request) async {
    try {
      wireValid = wireValid && request.uri.path == '/api/v1/connect/$_routeId' && !request.uri.hasQuery &&
        request.headers.value(HttpHeaders.authorizationHeader) == 'Bearer $_secret' &&
        request.headers.value('Sec-WebSocket-Extensions') == null;
      if (!upgradeSeen.isCompleted) upgradeSeen.complete();
      if (delayUpgrade) await releaseUpgrade.future;
      final ws = await WebSocketTransformer.upgrade(request, compression: CompressionOptions.compressionOff);
      streams++;
      final socket = await Socket.connect(InternetAddress.loopbackIPv4, agent.port);
      tcp.add(socket);
      Future<void> outbound() async {
        try { await ws.addStream(socket); } catch (_) { /* Expected on tunnel teardown. */ }
        finally { socket.destroy(); }
      }
      Future<void> inbound() async {
        try {
          await socket.addStream(ws.map((message) {
            if (message is! List<int> || message.length > 65536) {
              wireValid = false;
              throw const FormatException('Invalid tunnel frame');
            }
            final bytes = message;
            plaintextVisible = plaintextVisible || utf8.decode(bytes, allowMalformed: true).contains('private-enrollment-capability');
            if (bytes.length > maxFrame) maxFrame = bytes.length;
            return bytes;
          }));
        } catch (_) { /* Expected on tunnel teardown. */ }
        finally { socket.destroy(); }
      }
      await Future.wait([outbound(), inbound()]);
      await ws.close();
    } catch (_) { /* A cancelled upgrade closes the original HTTP request. */ }
  }
  Future<void> close() async {
    if (!releaseUpgrade.isCompleted) releaseUpgrade.complete();
    for (final socket in tcp) { socket.destroy(); }
    await broker.close(force: true);
    await agent.close(force: true);
    await Future.wait(sessions.toList()).timeout(const Duration(seconds: 5));
  }
}

void main() {
  test('Python AES-256-GCM envelope decrypts with exact origin AAD', () {
    final pairing = RelayPairing.decode(_code(), _pythonCiphertext, now: _now);
    expect(pairing.agentId, _agentId);
    expect(pairing.route.routeId, _routeId);
    expect(pairing.endpoint, 'https://$_agentId.rdpmonitor.invalid');
    expect(pairing.name, 'Fixture agent');
    expect(pairing.fingerprint, 'ab' * 32);
    expect(pairing.expires.millisecondsSinceEpoch, 1800000300000);
  });
  test('Envelope tamper, wrong secret, changed origin and expiry fail closed', () {
    final raw = base64Url.decode(base64Url.normalize(_pythonCiphertext));
    raw[20] ^= 1;
    final tampered = base64Url.encode(raw).replaceAll('=', '');
    expect(() => RelayPairing.decode(_code(), tampered, now: _now), throwsA(isA<RelayException>()));
    expect(() => RelayPairing.decode(_code().replaceFirst(_secret, '__________________________________________8'), _pythonCiphertext, now: _now), throwsA(isA<RelayException>()));
    expect(() => RelayPairing.decode(_code('https://other.example'), _pythonCiphertext, now: _now), throwsA(isA<RelayException>()));
    expect(() => RelayPairing.decode(_code(), _pythonCiphertext, now: _now.add(const Duration(seconds: 300))), throwsA(isA<RelayException>()));
  });
  test('Authenticated payload still rejects extra keys, wrong types and invalid bounds', () {
    final invalid = <Map<String, dynamic>>[
      {..._payload(), 'extra': true}, {..._payload(), 'v': true}, {..._payload(), 'expires': 1800000601},
      {..._payload(), 'route_id': _routeId.toUpperCase().replaceFirst('2', 'Z')},
      {..._payload(), 'route_token': 'A' * 42}, {..._payload(), 'fingerprint': 'AB' * 32},
      {..._payload(), 'pairing_code': 'short'}, {..._payload(), 'name': 'line\nbreak'},
    ];
    for (final payload in invalid) {
      expect(() => RelayPairing.decode(_code(), _encrypt(payload), now: _now), throwsA(isA<RelayException>()));
    }
    for (final code in [_code().replaceFirst('&v=1', '&v=1&v=1'), _code().replaceFirst('#', '&#'), '${_code()}=']) {
      expect(() => RelayPairing.decode(code, _pythonCiphertext, now: _now), throwsA(isA<RelayException>()));
    }
  });
  test('Relay origins and durable route records are strict', () {
    expect(normalizeRelayOrigin('https://RELAY.example:443/'), _origin);
    expect(normalizeRelayOrigin('https://bücher.example'), 'https://xn--bcher-kva.example');
    for (final origin in ['http://remote.example', 'http://localhost', 'https://user:password@relay.example', 'https://relay.example/path', 'https://relay.example?token=secret']) {
      expect(() => normalizeRelayOrigin(origin), throwsA(isA<RelayException>()));
    }
    final route = RelayRoute(origin: _origin, routeId: _routeId, token: _secret);
    expect(() => RelayRoute.fromJson({...route.toJson(), 'extra': true}), throwsA(isA<RelayException>()));
    expect(() => RelayRoute.fromJson({...route.toJson(), 'token': '${_secret.substring(0, 42)}9'}), throwsA(isA<RelayException>()));
  });

  late _Identity serverIdentity;
  late _Identity clientIdentity;
  setUpAll(() {
    serverIdentity = _Identity('agent.rdpmonitor.invalid');
    clientIdentity = _Identity('test-client');
  });
  test('Each HTTP connection carries inner TLS and client identity through bounded binary frames', () async {
    final harness = await _Harness.start(serverIdentity, clientIdentity);
    final context = SecurityContext(withTrustedRoots: false)..setTrustedCertificatesBytes(utf8.encode(serverIdentity.certificate));
    clientIdentity.use(context);
    final client = HttpClient(context: context)..connectionTimeout = const Duration(seconds: 5)..maxConnectionsPerHost = 2;
    final origin = Uri.parse('https://agent.rdpmonitor.invalid');
    final transport = RelayTransport(route: harness.route, agentOrigin: origin, context: context)..attach(client);
    try {
      Future<void> request(int value) async {
        final body = Uint8List(200000)..fillRange(0, 200000, value);
        final request = await client.postUrl(origin.replace(path: '/secret'));
        request.contentLength = body.length;
        request.add(body);
        final response = await request.close();
        expect(response.certificate, isNotNull);
        final expected = sha256.convert(base64Decode(serverIdentity.certificate.replaceAll(RegExp(r'-----[^-]+-----|\s'), ''))).toString();
        expect(sha256.convert(response.certificate!.der).toString(), expected);
        expect(await response.fold<List<int>>([], (buffer, chunk) => buffer..addAll(chunk)), body);
      }
      await Future.wait([request(17), request(39)]);
      expect(harness.streams, 2);
      expect(harness.requests, 2);
      expect(harness.sawClientCertificate, isTrue);
      expect(harness.maxFrame, inInclusiveRange(1, 65536));
      expect(harness.wireValid, isTrue);
    } finally { transport.close(); client.close(force: true); await harness.close(); }
  });
  test('Enrollment explicitly supplies its exact pin to inner TLS, not outer relay trust', () async {
    final harness = await _Harness.start(serverIdentity, clientIdentity);
    final context = SecurityContext(withTrustedRoots: false);
    final client = HttpClient(context: context)..connectionTimeout = const Duration(seconds: 5);
    final origin = Uri.parse('https://agent.rdpmonitor.invalid');
    final expected = sha256.convert(base64Decode(serverIdentity.certificate.replaceAll(RegExp(r'-----[^-]+-----|\s'), ''))).toString();
    var checkedPin = false;
    final transport = RelayTransport(route: harness.route, agentOrigin: origin, context: context,
      onBadCertificate: (certificate) {
        checkedPin = true;
        return sha256.convert(certificate.der).toString() == expected;
      })..attach(client);
    try {
      final request = await client.postUrl(origin.replace(path: '/enroll'));
      request.write('private-enrollment-capability');
      final response = await request.close();
      expect(await utf8.decoder.bind(response).join(), 'private-enrollment-capability');
      expect(response.certificate, isNotNull);
      expect(checkedPin, isTrue);
      expect(harness.requests, 1);
      expect(harness.plaintextVisible, isFalse);
      expect(harness.wireValid, isTrue);
    } finally { transport.close(); client.close(force: true); await harness.close(); }
  });
  test('Wrong fingerprint or hostname fails before enrollment bytes are sent', () async {
    final harness = await _Harness.start(serverIdentity, clientIdentity);
    try {
      for (final pinned in [true, false]) {
        final context = SecurityContext(withTrustedRoots: false);
        if (!pinned) context.setTrustedCertificatesBytes(utf8.encode(serverIdentity.certificate));
        final client = HttpClient(context: context)..connectionTimeout = const Duration(seconds: 3);
        final origin = Uri.parse(pinned ? 'https://agent.rdpmonitor.invalid' : 'https://wrong.rdpmonitor.invalid');
        final transport = RelayTransport(route: harness.route, agentOrigin: origin, context: context,
          onBadCertificate: pinned ? (_) => false : null)..attach(client);
        try {
          await expectLater(client.postUrl(origin.replace(path: '/enroll')), throwsA(anything));
          expect(harness.requests, 0);
        } finally { transport.close(); client.close(force: true); }
      }
    } finally { await harness.close(); }
  });
  test('HttpClient connection timeout covers bridge setup and cancels late upgrades', () async {
    final harness = await _Harness.start(serverIdentity, clientIdentity, delayUpgrade: true);
    final context = SecurityContext(withTrustedRoots: false);
    final client = HttpClient(context: context)..connectionTimeout = const Duration(milliseconds: 200);
    final origin = Uri.parse('https://agent.rdpmonitor.invalid');
    final transport = RelayTransport(route: harness.route, agentOrigin: origin, context: context)..attach(client);
    try {
      final watch = Stopwatch()..start();
      await expectLater(client.getUrl(origin), throwsA(anything));
      expect(watch.elapsed, lessThan(const Duration(seconds: 5)));
      expect(harness.requests, 0);
    } finally { transport.close(); client.close(force: true); await harness.close(); }
  });
  test('Synchronous close cancels pending setup without waiting for broker response', () async {
    final harness = await _Harness.start(serverIdentity, clientIdentity, delayUpgrade: true);
    final context = SecurityContext(withTrustedRoots: false);
    final client = HttpClient(context: context)..connectionTimeout = const Duration(seconds: 5);
    final origin = Uri.parse('https://agent.rdpmonitor.invalid');
    final transport = RelayTransport(route: harness.route, agentOrigin: origin, context: context)..attach(client);
    try {
      final failed = expectLater(client.getUrl(origin), throwsA(anything));
      await harness.upgradeSeen.future;
      transport.close();
      client.close(force: true);
      await failed.timeout(const Duration(seconds: 2));
      expect(harness.requests, 0);
    } finally { transport.close(); client.close(force: true); await harness.close(); }
  });
}
