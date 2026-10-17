import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rdpmonitor/api.dart';
import 'package:rdpmonitor/direct_installation.dart';
import 'package:rdpmonitor/guest_installation.dart';
import 'package:rdpmonitor/state.dart';

const _agent = '11111111-1111-4111-8111-111111111111';
const _device = '22222222-2222-4222-8222-222222222222';
String _encode(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
String _uri(String json, {List<int> trailing = const []}) => 'rdpmonitor://direct?v=1#${_encode([...ZLibEncoder(raw: true).convert(utf8.encode(json)), ...trailing])}';

// The widget binding replaces every HttpClient with a certificate-less 400
// response. Only these loopback integration scopes use real TLS sockets; no
// production certificate callback or verification policy is overridden.
class _NativeHttp extends HttpOverrides {}

class _Certificate implements X509Certificate {
  @override
  final String pem;
  _Certificate(this.pem);
  @override
  Uint8List get der => CryptoUtils.getBytesFromPEMString(pem);
  @override
  Uint8List get sha1 => Uint8List.fromList(crypto.sha1.convert(der).bytes);
  @override
  String get issuer => 'Test CA';
  @override
  String get subject => 'Test certificate';
  @override
  DateTime get startValidity => X509Utils.x509CertificateFromPem(pem).tbsCertificate!.validity.notBefore;
  @override
  DateTime get endValidity => X509Utils.x509CertificateFromPem(pem).tbsCertificate!.validity.notAfter;
}

class _Bundle {
  final PendingDirectSetup pending;
  final String ca;
  final String server;
  final String client;
  // Match the existing relay CA fixture: basic_utils' optional keyUsage
  // encoder emits nonzero unused padding bits, which native TLS rejects.
  // BasicConstraints still authorizes this CA; leaf client/server EKUs remain.
  _Bundle(this.pending, Map<String, String> authority, {String? clientCsr, List<ExtendedKeyUsage>? purposes})
    : ca = X509Utils.generateSelfSignedCertificate(CryptoUtils.rsaPrivateKeyFromPem(authority['key']!), authority['csr']!, 2,
        cA: true, notBefore: DateTime.now().subtract(const Duration(hours: 1))),
      server = X509Utils.generateSelfSignedCertificate(CryptoUtils.rsaPrivateKeyFromPem(authority['key']!),
        X509Utils.generateRsaCsrPem({'CN': 'localhost'}, CryptoUtils.rsaPrivateKeyFromPem(pending.serverKey!),
          RSAPublicKey(CryptoUtils.rsaPrivateKeyFromPem(pending.serverKey!).modulus!, BigInt.from(65537))),
        2, sans: ['localhost'], extKeyUsage: [ExtendedKeyUsage.SERVER_AUTH], cA: false,
        issuer: {'CN': 'Direct test CA'}, notBefore: DateTime.now().subtract(const Duration(hours: 1))),
      client = X509Utils.generateSelfSignedCertificate(CryptoUtils.rsaPrivateKeyFromPem(authority['key']!), clientCsr ?? pending.csr,
        2, extKeyUsage: purposes ?? [ExtendedKeyUsage.CLIENT_AUTH], cA: false,
        issuer: {'CN': 'Direct test CA'}, notBefore: DateTime.now().subtract(const Duration(hours: 1)));
  Map<String, dynamic> get response => {'v': 1, 'agent_id': _agent, 'endpoint': pending.endpoint,
    'fingerprint': crypto.sha256.convert(CryptoUtils.getBytesFromPEMString(server)).toString(),
    'certificate': client, 'ca_certificate': ca, 'device': {'id': _device, 'name': 'desktop viewer', 'role': 'viewer'},
    'expires': X509Utils.x509CertificateFromPem(client).tbsCertificate!.validity.notAfter.toUtc().toIso8601String()};
}

class _Vm {
  final HttpServer server;
  final _Bundle bundle;
  bool denyProtected = false;
  bool failAck = false;
  bool duplicateResponse = false;
  _Vm(this.server, this.bundle);
  static Future<_Vm> start(PendingDirectSetup pending, Map<String, String> ca) async {
    final seed = _Bundle(pending, ca);
    final context = SecurityContext(withTrustedRoots: false)
      ..useCertificateChainBytes(utf8.encode(seed.server))
      ..usePrivateKeyBytes(utf8.encode(pending.serverKey!))
      ..setTrustedCertificatesBytes(utf8.encode(seed.ca))
      ..setClientAuthoritiesBytes(utf8.encode(seed.ca));
    final server = await HttpServer.bindSecure(InternetAddress.loopbackIPv4, 0, context, requestClientCertificate: true);
    final adjusted = PendingDirectSetup.fromJson({...pending.toJson(), 'endpoint': 'https://localhost:${server.port}'});
    final vm = _Vm(server, _Bundle(adjusted, ca));
    // Certificates must be byte-identical to the live TLS certificate; avoid
    // creating a second cert with a different generated validity instant.
    vm._serverCertificate = seed.server;
    server.listen((request) { unawaited(vm._handle(request)); });
    return vm;
  }
  late final String _serverCertificate;
  Future<void> _handle(HttpRequest request) async {
    try {
      final text = await utf8.decoder.bind(request).join();
      final body = text.isEmpty ? <String, dynamic>{} : jsonDecode(text) as Map<String, dynamic>;
      request.response.headers.contentType = ContentType.json;
      final validClient = request.certificate != null &&
        crypto.sha256.convert(request.certificate!.der).toString() == crypto.sha256.convert(CryptoUtils.getBytesFromPEMString(bundle.client)).toString();
      if (request.uri.path == '/api/v1/direct/bootstrap') {
        if (body['nonce'] != bundle.pending.nonce) {
          request.response.statusCode = 403; request.response.write('{}');
        } else {
          final value = {...bundle.response, 'fingerprint': crypto.sha256.convert(CryptoUtils.getBytesFromPEMString(_serverCertificate)).toString()};
          final json = jsonEncode(value);
          request.response.write(duplicateResponse ? '{"v":1,${json.substring(1)}' : json);
        }
      } else if (request.uri.path == '/api/v1/health') {
        request.response.write(jsonEncode({'agent_id': _agent}));
      } else if (request.uri.path == '/api/v1/catalog' || request.uri.path == '/api/v1/direct/complete') {
        if (!validClient || denyProtected) {
          request.response.statusCode = 403; request.response.write(jsonEncode({'error': {'message': 'Viewer proof required'}}));
        } else if (request.uri.path.endsWith('/complete') && failAck) {
          request.response.statusCode = 503; request.response.write(jsonEncode({'error': {'message': 'Retry completion'}}));
        } else {
          request.response.write(jsonEncode(request.uri.path.endsWith('/complete') ? {'completed': body['nonce'] == bundle.pending.nonce} : {'actions': []}));
        }
      } else { request.response.statusCode = 404; request.response.write('{}'); }
      await request.response.close();
    } catch (_) { /* Test teardown may interrupt a TLS connection. */ }
  }
  Future<void> close() async { await server.close(force: true); }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late PendingDirectSetup intent;
  late Map<String, String> ca;
  late Map<String, String> other;
  setUpAll(() async {
    ca = createIdentity('Direct test CA');
    other = createIdentity('Unapproved desktop');
    intent = await PendingDirectSetup.create(name: 'Test VM', group: 'Lab', endpoint: 'localhost:8443');
  });
  setUp(() { FlutterSecureStorage.setMockInitialValues({}); });

  test('pending keys survive reopening and the CMD carries only the distinct VM key', () async {
    await intent.save();
    final reopened = (await PendingDirectSetup.load())!;
    expect(reopened.clientKey, intent.clientKey);
    expect(reopened.csr, intent.csr);
    expect(reopened.serverKey, intent.serverKey);
    expect(reopened.setupUri, intent.setupUri);
    final spec = DirectSetupCode.parse(reopened.setupUri);
    expect(spec.serverKey, isNot(reopened.clientKey));
    expect(spec.toJson().values, isNot(contains(reopened.clientKey)));
    final release = GuestInstallerRelease(url: 'https://example.com/guest.exe', sha256: 'ab' * 32,
      unsignedPreview: true, setupProtocol: 2);
    final command = await buildGuestInstallCommand(setupUri: reopened.setupUri, release: release, acceptUnsignedPreview: true);
    final outer = RegExp(r'^set "RDP_MONITOR_SETUP=([A-Za-z0-9_-]+)"').firstMatch(command)!.group(1)!;
    final transported = DirectSetupCode.parse(utf8.decode(base64Url.decode(base64Url.normalize(outer))));
    expect(transported.serverKey, reopened.serverKey);
    expect(transported.toJson().values, isNot(contains(reopened.clientKey)));
    await expectLater(buildGuestInstallCommand(setupUri: reopened.setupUri,
      release: GuestInstallerRelease(url: release.url, sha256: release.sha256, unsignedPreview: true),
      acceptUnsignedPreview: true), throwsFormatException);
  });

  test('URI rejects ambiguous JSON, trailing streams, inflation, expiry and shared keys', () {
    final spec = DirectSetupCode.parse(intent.setupUri).toJson();
    final json = jsonEncode(spec);
    final compressed = ZLibEncoder(raw: true).convert(utf8.encode(json));
    for (final uri in [
      _uri('{"v":1,${json.substring(1)}'),
      _uri(json, trailing: [0]), _uri(json, trailing: compressed),
      _uri(' ' * 8193), '${intent.setupUri}=',
      intent.setupUri.replaceFirst('?v=1', '?v=1&extra=1'),
      _uri(jsonEncode({...spec, 'expires': DateTime.now().millisecondsSinceEpoch ~/ 1000 - 1})),
      _uri(jsonEncode({...spec, 'expires': DateTime.now().millisecondsSinceEpoch ~/ 1000 + 7200})),
      _uri(jsonEncode({...spec, 'server_key': intent.clientKey})),
      _uri(jsonEncode({...spec, 'csr': X509Utils.generateRsaCsrPem({'CN': 'Privileged request'},
        CryptoUtils.rsaPrivateKeyFromPem(other['key']!),
        RSAPublicKey(CryptoUtils.rsaPrivateKeyFromPem(other['key']!).modulus!, BigInt.from(65537)), san: ['server.example'])})),
      _uri(jsonEncode({...spec, 'source': '0.0.0.0/0'})),
    ]) { expect(() => DirectSetupCode.parse(uri), throwsA(isA<Exception>())); }
    expect(() => PendingDirectSetup.fromJson({...intent.toJson(), 'serverKey': intent.clientKey}), throwsA(isA<Exception>()));
    expect(() => PendingDirectSetup.fromJson({...intent.toJson(), 'clientKey': other['key']}), throwsA(isA<Exception>()));
    expect(() => PendingDirectSetup.fromJson({...intent.toJson(), 'csr': other['csr']}), throwsA(isA<Exception>()));
  });

  test('bootstrap binds server key, hostname, viewer key, response shape and certificate expiry', () {
    final bundle = _Bundle(intent, ca);
    final cert = _Certificate(bundle.server);
    final issued = intent.acceptBootstrap(bundle.response, cert);
    expect(issued.profile!.privateKey, intent.clientKey);
    expect(issued.stage, DirectSetupStage.issued);
    expect(intent.acceptsServerCertificate(cert, 'another.example', 8443), isFalse);
    expect(intent.acceptsServerCertificate(cert, 'localhost', 9443), isFalse);
    expect(intent.acceptsServerCertificate(cert, 'localhost', 8443, now: cert.endValidity), isFalse);
    final changed = PendingDirectSetup.fromJson({...intent.toJson(), 'serverKey': other['key']});
    expect(changed.acceptsServerCertificate(cert, 'localhost', 8443), isFalse);
    for (final response in [
      {...bundle.response, 'endpoint': 'https://another.example:8443'},
      {...bundle.response, 'fingerprint': '00' * 32},
      {...bundle.response, 'agent_id': 'not-a-uuid'},
      {...bundle.response, 'extra': true},
      {...bundle.response, 'device': {'id': _device, 'name': 'desktop viewer', 'role': 'admin'}},
      {...bundle.response, 'expires': DateTime.now().subtract(const Duration(days: 1)).toUtc().toIso8601String()},
      {...bundle.response, 'certificate': _Bundle(intent, ca, clientCsr: other['csr']).client},
      {...bundle.response, 'certificate': _Bundle(intent, ca, purposes: [ExtendedKeyUsage.CLIENT_AUTH, ExtendedKeyUsage.SERVER_AUTH]).client},
    ]) { expect(() => intent.acceptBootstrap(response, cert), throwsA(isA<Exception>())); }
    expect(() => intent.acceptBootstrap(bundle.response, cert, now: intent.expires), throwsFormatException);
  });

  test('direct VM endpoints reject unspecified and multicast listener addresses', () {
    for (final address in ['0.0.0.0', '[::]', '239.1.2.3', '[ff02::1]']) {
      expect(() => normalizeDirectEndpoint(address), throwsFormatException);
      expect(() => normalizeDirectEndpoint('https://$address:8443'), throwsFormatException);
    }
    expect(normalizeDirectEndpoint('127.0.0.1'), 'https://127.0.0.1:8443');
    expect(normalizeDirectEndpoint('[::1]'), 'https://[::1]:8443');
  });

  test('failed protected probe and ack retain checkpoints without issuance or duplicate profile saves', () => HttpOverrides.runWithHttpOverrides(() async {
    final vm = await _Vm.start(intent, ca);
    addTearDown(vm.close);
    await vm.bundle.pending.save();
    final wrongNonce = PendingDirectSetup.fromJson({...vm.bundle.pending.toJson(), 'nonce': 'A' * 43});
    await expectLater(wrongNonce.pollBootstrap(), throwsA(isA<ApiException>()));
    expect((await PendingDirectSetup.load())!.stage, DirectSetupStage.waiting);
    vm.duplicateResponse = true;
    await expectLater(vm.bundle.pending.pollBootstrap(), throwsFormatException);
    vm.duplicateResponse = false;
    final issued = await vm.bundle.pending.pollBootstrap();
    await issued.save();
    // A stolen public bootstrap bundle is insufficient: TLS cannot prove the
    // issued certificate with another desktop's private key.
    final stolen = MachineProfile(id: _agent, name: 'Stolen bundle', group: '',
      endpoint: issued.endpoint, certificate: issued.profile!.certificate,
      privateKey: other['key']!, ca: issued.profile!.ca,
      fingerprint: issued.profile!.fingerprint, deviceId: _device, role: 'viewer');
    await expectLater(() async {
      AgentApi? attacker;
      try { attacker = AgentApi(stolen); await attacker.call('GET', '/catalog'); }
      finally { attacker?.close(); }
    }(), throwsA(isA<Exception>()));
    final fleet = Fleet()..ready = true;
    addTearDown(fleet.dispose);
    vm.denyProtected = true;
    await expectLater(issued.finish(onEnrolled: fleet.add), throwsA(isA<ApiException>()
      .having((error) => error.status, 'protected denial status', 403)
      .having((error) => error.message, 'protected denial', 'Viewer proof required')));
    expect(fleet.machines, isEmpty);
    expect(await ProfileVault().load(), isEmpty);
    final retry = (await PendingDirectSetup.load())!;
    expect(retry.stage, DirectSetupStage.issued);
    expect(retry.profile!.privateKey, intent.clientKey);
    vm.denyProtected = false; vm.failAck = true;
    await expectLater(retry.finish(onEnrolled: fleet.add), throwsA(isA<ApiException>()
      .having((error) => error.status, 'acknowledgement status', 503)
      .having((error) => error.message, 'acknowledgement failure', 'Retry completion')));
    final saved = (await PendingDirectSetup.load())!;
    expect(saved.stage, DirectSetupStage.saved);
    expect(saved.serverKey, isNull);
    expect(fleet.machines.keys, contains(_agent));
    expect(fleet.machines[_agent]!.profile.sameCredentials(issued.profile!), isTrue);
    expect(await ProfileVault().load(), hasLength(1));
    // Already-issued/saved state stays readable beyond the install window.
    final expiredSaved = PendingDirectSetup.fromJson({...saved.toJson(), 'expires': 1});
    await expiredSaved.save();
    vm.failAck = false;
    await (await PendingDirectSetup.load())!.finish(onEnrolled: fleet.add);
    expect(fleet.machines, hasLength(1));
    await fleet.save();
    final persisted = await ProfileVault().load();
    expect(persisted, hasLength(1));
    expect(persisted.single.sameCredentials(issued.profile!), isTrue);
    expect(await PendingDirectSetup.load(), isNull);
  }, _NativeHttp()));

  test('committed admission error is recovered into the real live fleet and survives a later save', () => HttpOverrides.runWithHttpOverrides(() async {
    final vm = await _Vm.start(intent, ca);
    addTearDown(vm.close);
    final fleet = Fleet()..ready = true;
    addTearDown(fleet.dispose);
    await vm.bundle.pending.save();
    final issued = await vm.bundle.pending.pollBootstrap();
    Future<void> commitThenInterrupt(MachineProfile profile) async {
      final committed = MachineProfile.fromJson({...profile.toJson(),
        'name': 'Recovered display name', 'group': 'Retained group',
        'costMinor': 12345, 'currency': 'EUR', 'billingPeriod': 'yearly',
        'expiresOn': '2030-06-15'});
      await ProfileVault().save([committed]);
      throw ApiException('Profile committed before live admission was interrupted.');
    }
    await expectLater(issued.finish(onEnrolled: commitThenInterrupt), throwsA(isA<ApiException>()
      .having((error) => error.message, 'committed admission error',
        'Profile committed before live admission was interrupted.')));
    expect(fleet.machines, isEmpty);
    final committed = (await ProfileVault().load()).single;
    expect(committed.sameCredentials(issued.profile!), isTrue);
    expect(committed.name, 'Recovered display name');
    expect((await PendingDirectSetup.load())!.stage, DirectSetupStage.issued);

    await (await PendingDirectSetup.load())!.finish(onEnrolled: fleet.add);
    expect(fleet.machines, hasLength(1));
    final recovered = fleet.machines[_agent]!.profile;
    expect(recovered.sameCredentials(issued.profile!), isTrue);
    expect(recovered.name, committed.name);
    expect(recovered.group, committed.group);
    expect(recovered.costMinor, committed.costMinor);
    expect(recovered.currency, committed.currency);
    expect(recovered.billingPeriod, committed.billingPeriod);
    expect(recovered.expiresOn, committed.expiresOn);
    expect(await PendingDirectSetup.load(), isNull);

    await fleet.save();
    final persisted = await ProfileVault().load();
    expect(persisted, hasLength(1));
    expect(persisted.single.toJson(), committed.toJson());
  }, _NativeHttp()));
}
