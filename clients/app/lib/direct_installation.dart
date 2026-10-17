import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart' show compute;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/asn1.dart';

import 'api.dart';

const _pendingKey = 'rdpmonitor.pending-direct-setup.v1';
const _storage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
  iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
);
final _uuid = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');

String _encode(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
Never _invalid([String message = 'The private direct setup is invalid.']) => throw FormatException(message);
bool _keys(Map<String, dynamic> value, Set<String> keys) => value.length == keys.length && keys.every(value.containsKey);

/// A direct origin always carries its effective port; no implicit 443 authority.
String normalizeDirectEndpoint(String input) {
  final value = input.trim();
  final address = value.startsWith('https://') ? value : 'https://$value';
  final match = RegExp(r'^https://(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::([0-9]+))?$').firstMatch(address);
  if (match == null) _invalid('Enter a VM IP or DNS hostname, optionally with an HTTPS port (default 8443), without a path or credentials.');
  var host = match[1]!.toLowerCase();
  if (host.startsWith('[')) host = host.substring(1, host.length - 1);
  final ip = InternetAddress.tryParse(host);
  if (ip != null) {
    if (ip.isMulticast || ip.rawAddress.every((byte) => byte == 0)) {
      _invalid('Use a reachable VM IP, not an unspecified or multicast listener address.');
    }
    host = ip.address;
  } else if (host.length > 253 || host.endsWith('.') ||
      host.split('.').any((label) => !RegExp(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$').hasMatch(label)) ||
      RegExp(r'^[0-9.]+$').hasMatch(host)) {
    _invalid('Use a valid IP literal or ASCII DNS hostname.');
  }
  final port = int.tryParse(match[2] ?? '8443');
  if (port == null || port < 1024 || port > 65535) _invalid('Use a TCP port from 1024 to 65535.');
  return 'https://${host.contains(':') ? '[$host]' : host}:$port';
}

String normalizeDirectSource(String input, String endpoint) {
  if (input.isEmpty || input == 'auto') return 'auto';
  final ip = InternetAddress.tryParse(input);
  if (ip == null || ip.address != input || ip.isMulticast || ip.isLinkLocal ||
      ip.rawAddress.every((byte) => byte == 0) ||
      (ip.isLoopback && InternetAddress.tryParse(Uri.parse(endpoint).host)?.isLoopback != true)) {
    _invalid('Enter one canonical desktop IP literal, without a subnet or port. Loopback is allowed only for a loopback VM.');
  }
  return ip.address;
}

Uint8List _pem(String value, String label) {
  final match = RegExp('^-----BEGIN $label-----\\r?\\n([A-Za-z0-9+/=\\r\\n]+)\\r?\\n-----END $label-----\\s*\$').firstMatch(value);
  if (match == null) _invalid('Invalid direct setup certificate material.');
  try {
    final bytes = base64.decode(match[1]!.replaceAll(RegExp(r'\s'), ''));
    final parser = ASN1Parser(bytes);
    parser.nextObject();
    if (parser.hasNext()) _invalid();
    return bytes;
  } catch (_) { _invalid('Invalid direct setup certificate material.'); }
}

RSAPrivateKey _privateKey(String pem) {
  final pkcs1 = pem.startsWith('-----BEGIN RSA PRIVATE KEY-----');
  _pem(pem, pkcs1 ? 'RSA PRIVATE KEY' : 'PRIVATE KEY');
  final key = pkcs1 ? CryptoUtils.rsaPrivateKeyFromPemPkcs1(pem) : CryptoUtils.rsaPrivateKeyFromPem(pem);
  if (key.modulus?.bitLength != 2048 || key.publicExponent != BigInt.from(65537)) _invalid('Direct setup requires a distinct RSA-2048 key with exponent 65537.');
  return key;
}
RSAPublicKey _public(RSAPrivateKey key) => RSAPublicKey(key.modulus!, key.publicExponent!);
Uint8List _hexBytes(String value) => Uint8List.fromList(List.generate(value.length ~/ 2, (i) => int.parse(value.substring(i * 2, i * 2 + 2), radix: 16)));
RSAPublicKey _certificateKey(String certificate) {
  _pem(certificate, 'CERTIFICATE');
  final data = X509Utils.x509CertificateFromPem(certificate);
  return CryptoUtils.rsaPublicKeyFromDERBytes(_hexBytes(data.tbsCertificate!.subjectPublicKeyInfo.bytes!));
}
bool _sameBytes(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var i = 0; i < left.length; i++) { if (left[i] != right[i]) return false; }
  return true;
}
bool _certificateHasHost(String certificate, String host) {
  final certificateSequence = ASN1Parser(_pem(certificate, 'CERTIFICATE')).nextObject() as ASN1Sequence;
  final tbs = certificateSequence.elements!.first as ASN1Sequence;
  final ip = InternetAddress.tryParse(host);
  for (final field in tbs.elements!) {
    if (field.tag != 0xa3) continue;
    final extensions = ASN1Parser(field.valueBytes).nextObject() as ASN1Sequence;
    for (final extension in extensions.elements!.cast<ASN1Sequence>()) {
      final oid = extension.elements!.first as ASN1ObjectIdentifier;
      if (oid.objectIdentifierAsString != '2.5.29.17') continue;
      final names = ASN1Parser((extension.elements!.last as ASN1OctetString).valueBytes).nextObject() as ASN1Sequence;
      for (final name in names.elements!) {
        final bytes = name.valueBytes!;
        if (ip == null && name.tag == 0x82 && ascii.decode(bytes) == host) return true;
        if (ip != null && name.tag == 0x87 && _sameBytes(bytes, ip.rawAddress)) return true;
      }
    }
  }
  return false;
}
RSAPublicKey _csrKey(String csr) {
  final der = _pem(csr, 'CERTIFICATE REQUEST');
  final seq = ASN1Parser(der).nextObject() as ASN1Sequence;
  final info = seq.elements![0] as ASN1Sequence;
  // This installer never requests extensions or authority through a CSR. Reject
  // attributes rather than depending on a decoder that drops unknown extensions.
  if (info.elements!.length != 4 || info.elements![3].valueBytes!.isNotEmpty ||
      !X509Utils.checkCsrSignature(csr)) {
    _invalid('The desktop CSR must be signed and must not request certificate privileges.');
  }
  final data = X509Utils.csrFromPem(csr);
  final key = CryptoUtils.rsaPublicKeyFromDERBytes(_hexBytes(data.certificationRequestInfo!.publicKeyInfo!.bytes!));
  if (key.modulus?.bitLength != 2048 || key.publicExponent != BigInt.from(65537)) _invalid('The desktop CSR must use RSA-2048.');
  return key;
}

/// Strict bounded transport, shared by the persisted intent and CMD builder.
class DirectSetupCode {
  final Map<String, dynamic> _value;
  final String code;
  DirectSetupCode._(this._value, this.code);
  String get endpoint => _value['endpoint'];
  String get serverKey => _value['server_key'];
  String get csr => _value['csr'];
  String get nonce => _value['nonce'];
  String get source => _value['source'];
  DateTime get expires => DateTime.fromMillisecondsSinceEpoch((_value['expires'] as int) * 1000, isUtc: true);
  Map<String, dynamic> toJson() => Map<String, dynamic>.from(_value);

  factory DirectSetupCode.parse(String uri, {DateTime? now}) {
    const prefix = 'rdpmonitor://direct?v=1#';
    if (utf8.encode(uri).length > 4096 || !uri.startsWith(prefix)) _invalid();
    final fragment = uri.substring(prefix.length);
    if (fragment.isEmpty || !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(fragment)) _invalid();
    final compressed = base64Url.decode(base64Url.normalize(fragment));
    if (_encode(compressed) != fragment) _invalid('Direct setup base64 is not canonical.');
    final value = _strictObject(utf8.decode(_inflate(compressed)));
    _validate(value, now: now);
    return DirectSetupCode._(value, uri);
  }
  static DirectSetupCode _create(Map<String, dynamic> value) {
    _validate(value);
    final bytes = utf8.encode(jsonEncode(value));
    if (bytes.length > 8192) _invalid('Direct setup exceeds its size limit.');
    final uri = 'rdpmonitor://direct?v=1#${_encode(ZLibEncoder(raw: true).convert(bytes))}';
    if (utf8.encode(uri).length > 4096) _invalid('Direct setup exceeds its command transport limit.');
    return DirectSetupCode._(value, uri);
  }
  static void _validate(Map<String, dynamic> value, {DateTime? now}) {
    if (!_keys(value, {'v', 'endpoint', 'server_key', 'csr', 'nonce', 'expires', 'source'}) ||
        value['v'] is! int || value['v'] != 1 || value['endpoint'] is! String ||
        value['server_key'] is! String || value['csr'] is! String || value['nonce'] is! String ||
        value['expires'] is! int || value['source'] is! String) {
      _invalid();
    }
    if (normalizeDirectEndpoint(value['endpoint']) != value['endpoint'] ||
        normalizeDirectSource(value['source'], value['endpoint']) != value['source']) {
      _invalid();
    }
    final nonce = value['nonce'] as String;
    if (!RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(nonce) || _encode(base64Url.decode('$nonce=')) != nonce) _invalid();
    final seconds = (now ?? DateTime.now()).millisecondsSinceEpoch ~/ 1000;
    if (value['expires'] <= seconds || value['expires'] > seconds + 3600) _invalid('Direct setup expired or has an invalid lifetime. Check both clocks. If already installed, approve recovery locally on the VM; do not reinstall over its identity.');
    final server = _privateKey(value['server_key']);
    final client = _csrKey(value['csr']);
    if (client == _public(server)) _invalid('Desktop and VM transport keys must be different.');
  }
}

enum DirectSetupStage { waiting, issued, saved }
String _newTransportKey(String _) => CryptoUtils.encodeRSAPrivateKeyToPem(CryptoUtils.generateRSAKeyPair(keySize: 2048).privateKey as RSAPrivateKey);

/// All private state stays in the OS vault. Issuance is local on the VM; the
/// desktop only reads a public bootstrap bundle, then proves its retained key.
class PendingDirectSetup {
  final String name;
  final String group;
  final String endpoint;
  final String source;
  final String clientKey;
  final String csr;
  final String? serverKey;
  final String nonce;
  final DateTime expires;
  final DirectSetupStage stage;
  final MachineProfile? profile;
  PendingDirectSetup._({required this.name, required this.group, required this.endpoint,
    required this.source, required this.clientKey, required this.csr, required this.serverKey,
    required this.nonce, required this.expires, required this.stage, this.profile});

  static Future<PendingDirectSetup> create({required String name, String group = '',
    required String endpoint, String source = 'auto'}) async {
    name = name.trim(); group = group.trim();
    _label(name, isRequired: true); _label(group);
    endpoint = normalizeDirectEndpoint(endpoint);
    source = normalizeDirectSource(source.trim(), endpoint);
    final identity = await compute(createIdentity, '${Platform.operatingSystem} viewer');
    final transport = await compute(_newTransportKey, '');
    final random = Random.secure();
    final pending = PendingDirectSetup._(name: name, group: group, endpoint: endpoint, source: source,
      clientKey: identity['key']!, csr: identity['csr']!, serverKey: transport,
      nonce: _encode(List.generate(32, (_) => random.nextInt(256))),
      expires: DateTime.fromMillisecondsSinceEpoch((DateTime.now().millisecondsSinceEpoch ~/ 1000 + 1800) * 1000, isUtc: true),
      stage: DirectSetupStage.waiting);
    pending.setupUri; // Validate before any private capability is exposed.
    return pending;
  }
  static void _label(String value, {bool isRequired = false}) {
    if ((isRequired && value.isEmpty) || value.length > 128 || RegExp(r'[\x00-\x1f\x7f]').hasMatch(value)) _invalid('Use a machine name/group of up to 128 characters without control characters.');
  }
  bool get canInstall => stage == DirectSetupStage.waiting && DateTime.now().isBefore(expires);
  String get setupUri {
    if (stage != DirectSetupStage.waiting || serverKey == null) _invalid('This identity was already issued. Retry the saved identity instead of reinstalling.');
    return DirectSetupCode._create({'v': 1, 'endpoint': endpoint, 'server_key': serverKey,
      'csr': csr, 'nonce': nonce, 'expires': expires.millisecondsSinceEpoch ~/ 1000, 'source': source}).code;
  }
  Map<String, dynamic> toJson() => {'v': 1, 'name': name, 'group': group, 'endpoint': endpoint,
    'source': source, 'clientKey': clientKey, 'csr': csr, 'serverKey': serverKey,
    'nonce': nonce, 'expires': expires.millisecondsSinceEpoch ~/ 1000, 'stage': stage.name,
    'profile': profile?.toJson()};
  factory PendingDirectSetup.fromJson(Map<String, dynamic> value) {
    if (!_keys(value, {'v', 'name', 'group', 'endpoint', 'source', 'clientKey', 'csr', 'serverKey', 'nonce', 'expires', 'stage', 'profile'}) ||
        value['v'] is! int || value['v'] != 1 || ['name', 'group', 'endpoint', 'source', 'clientKey', 'csr', 'nonce', 'stage'].any((key) => value[key] is! String) ||
        value['expires'] is! int || (value['serverKey'] != null && value['serverKey'] is! String) ||
        !DirectSetupStage.values.any((stage) => stage.name == value['stage'])) {
      _invalid('The protected direct setup is invalid.');
    }
    final stage = DirectSetupStage.values.singleWhere((stage) => stage.name == value['stage']);
    if ((stage == DirectSetupStage.waiting) != (value['profile'] == null) ||
        (stage == DirectSetupStage.saved) != (value['serverKey'] == null)) {
      _invalid('The protected direct checkpoint is incomplete.');
    }
    final pending = PendingDirectSetup._(name: value['name'], group: value['group'], endpoint: value['endpoint'],
      source: value['source'], clientKey: value['clientKey'], csr: value['csr'], serverKey: value['serverKey'],
      nonce: value['nonce'], expires: DateTime.fromMillisecondsSinceEpoch((value['expires'] as int) * 1000, isUtc: true),
      stage: stage, profile: value['profile'] == null ? null : MachineProfile.fromJson(object(value['profile'])));
    _label(pending.name, isRequired: true); _label(pending.group);
    if (normalizeDirectEndpoint(pending.endpoint) != pending.endpoint || normalizeDirectSource(pending.source, pending.endpoint) != pending.source ||
        !RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(pending.nonce) || _encode(base64Url.decode('${pending.nonce}=')) != pending.nonce ||
        _public(_privateKey(pending.clientKey)) != _csrKey(pending.csr)) {
      _invalid('The retained desktop key does not match this setup.');
    }
    if (pending.serverKey != null && _public(_privateKey(pending.serverKey!)) == _csrKey(pending.csr)) _invalid();
    if (pending.profile != null) pending._validateProfile(pending.profile!);
    return pending;
  }
  static Future<PendingDirectSetup?> load() async {
    final raw = await _storage.read(key: _pendingKey);
    if (raw == null) return null;
    try { return PendingDirectSetup.fromJson(_strictObject(raw)); }
    catch (_) { throw ApiException('Protected pending direct setup cannot be read. Restore OS credential storage before creating another identity.'); }
  }
  Future<void> save() async {
    final raw = jsonEncode(toJson());
    await _storage.write(key: _pendingKey, value: raw);
    if (await _storage.read(key: _pendingKey) != raw) throw ApiException('The direct identity could not be verified in OS credential storage. Keep this dialog open and retry saving.');
  }
  static Future<void> clear() async {
    await _storage.delete(key: _pendingKey);
    if (await _storage.read(key: _pendingKey) != null) throw ApiException('The pending direct setup could not be removed from OS credential storage.');
  }

  bool acceptsServerCertificate(X509Certificate certificate, String host, int port, {DateTime? now}) {
    final origin = Uri.parse(endpoint);
    final instant = now ?? DateTime.now();
    if (serverKey == null || host != origin.host || port != origin.port ||
        instant.isBefore(certificate.startValidity) || !instant.isBefore(certificate.endValidity)) {
      return false;
    }
    try {
      return _certificateHasHost(certificate.pem, origin.host) &&
        _certificateKey(certificate.pem) == _public(_privateKey(serverKey!));
    } catch (_) { return false; }
  }

  /// Single bounded read; callers may retry only while the local window is open.
  Future<PendingDirectSetup> pollBootstrap() async {
    if (!canInstall) _invalid('The setup window expired. For an installed VM, locally approve manual recovery on the VM; this desktop will never replace its identity.');
    final origin = Uri.parse(endpoint);
    final client = HttpClient(context: SecurityContext(withTrustedRoots: false))
      ..connectionTimeout = const Duration(seconds: 5);
    client.badCertificateCallback = (cert, host, port) => acceptsServerCertificate(cert, host, port);
    try {
      final request = await client.postUrl(origin.replace(path: '/api/v1/direct/bootstrap')).timeout(const Duration(seconds: 8));
      request.followRedirects = false;
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode({'nonce': nonce}));
      final response = await request.close().timeout(const Duration(seconds: 8));
      final cert = response.certificate;
      if (cert == null || !acceptsServerCertificate(cert, origin.host, origin.port)) throw ApiException('The VM transport key, hostname or certificate lifetime does not match the prepared installation.');
      final bytes = await response.fold<List<int>>([], (buffer, chunk) {
        if (buffer.length + chunk.length > 32768) throw ApiException('Direct bootstrap response exceeds its safety limit.');
        return buffer..addAll(chunk);
      }).timeout(const Duration(seconds: 8));
      if (response.statusCode != 200) throw ApiException('The VM did not publish this approved direct setup (${response.statusCode}). Check the VM installer and its clock. An installed VM requires locally approved recovery.', status: response.statusCode);
      return acceptBootstrap(_strictObject(utf8.decode(bytes)), cert);
    } finally { client.close(force: true); }
  }

  PendingDirectSetup acceptBootstrap(Map<String, dynamic> value, X509Certificate serverCertificate, {DateTime? now}) {
    final instant = now ?? DateTime.now();
    if (stage != DirectSetupStage.waiting || !instant.isBefore(expires)) _invalid('Direct setup expired or is already checkpointed.');
    if (!_keys(value, {'v', 'agent_id', 'endpoint', 'fingerprint', 'certificate', 'ca_certificate', 'device', 'expires'}) ||
        value['v'] is! int || value['v'] != 1 || value['agent_id'] is! String || !_uuid.hasMatch(value['agent_id']) ||
        value['endpoint'] != endpoint || value['fingerprint'] is! String ||
        value['certificate'] is! String || value['ca_certificate'] is! String || value['expires'] is! String ||
        value['device'] is! Map<String, dynamic>) {
      _invalid('The VM returned an invalid direct bootstrap bundle.');
    }
    final device = value['device'] as Map<String, dynamic>;
    if (!_keys(device, {'id', 'name', 'role'}) || device['id'] is! String || !_uuid.hasMatch(device['id']) ||
        device['name'] is! String || (device['name'] as String).isEmpty || (device['name'] as String).length > 128 ||
        device['role'] != 'viewer') {
      _invalid('Direct setup must issue exactly the approved viewer device.');
    }
    final origin = Uri.parse(endpoint);
    if (!acceptsServerCertificate(serverCertificate, origin.host, origin.port, now: instant) ||
        value['fingerprint'] != sha256.convert(serverCertificate.der).toString()) {
      _invalid('The VM transport certificate changed. No identity was saved.');
    }
    final profile = MachineProfile(id: value['agent_id'], name: name, group: group, endpoint: endpoint,
      certificate: value['certificate'], privateKey: clientKey, ca: value['ca_certificate'],
      fingerprint: value['fingerprint'], deviceId: device['id'], role: 'viewer');
    _validateProfile(profile, now: instant);
    final validity = X509Utils.x509CertificateFromPem(profile.certificate).tbsCertificate!.validity;
    final expiry = DateTime.tryParse(value['expires']);
    if (expiry == null || !expiry.isUtc || expiry != validity.notAfter || !instant.isBefore(expiry)) _invalid('The returned viewer certificate expiry is invalid.');
    if (!X509Utils.checkX509Signature(serverCertificate.pem, parent: profile.ca)) _invalid('The VM transport certificate is not signed by its returned CA.');
    return _with(DirectSetupStage.issued, profile);
  }

  void _validateProfile(MachineProfile profile, {DateTime? now}) {
    if (!_uuid.hasMatch(profile.id) || !_uuid.hasMatch(profile.deviceId) || profile.role != 'viewer' || profile.relay != null ||
        profile.endpoint != endpoint || profile.privateKey != clientKey || profile.name != name || profile.group != group ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(profile.fingerprint) || _certificateKey(profile.certificate) != _csrKey(csr)) {
      _invalid('The issued device identity does not match the retained desktop key and intent.');
    }
    _pem(profile.ca, 'CERTIFICATE');
    final cert = X509Utils.x509CertificateFromPem(profile.certificate).tbsCertificate!;
    final ca = X509Utils.x509CertificateFromPem(profile.ca).tbsCertificate!;
    final purposes = cert.extensions?.extKeyUsage;
    if (cert.extensions?.cA == true || purposes == null || !purposes.contains(ExtendedKeyUsage.CLIENT_AUTH) ||
        purposes.contains(ExtendedKeyUsage.SERVER_AUTH) || ca.extensions?.cA != true ||
        !X509Utils.checkX509Signature(profile.certificate, parent: profile.ca)) {
      _invalid('The VM returned an invalid client certificate or CA.');
    }
    if (now != null && (now.isBefore(cert.validity.notBefore) || !now.isBefore(cert.validity.notAfter) ||
        now.isBefore(ca.validity.notBefore) || !now.isBefore(ca.validity.notAfter))) {
      _invalid('The VM returned an expired or not-yet-valid certificate.');
    }
  }
  PendingDirectSetup _with(DirectSetupStage stage, MachineProfile profile) => PendingDirectSetup._(
    name: name, group: group, endpoint: endpoint, source: source, clientKey: clientKey, csr: csr,
    serverKey: stage == DirectSetupStage.saved ? null : serverKey, nonce: nonce, expires: expires, stage: stage, profile: profile);

  /// Probe before the first save, reconcile the matching profile into the live
  /// fleet through idempotent admission, then acknowledge. A committed vault
  /// write may have reported an error before live admission; retries must adopt
  /// that saved identity and metadata rather than skipping the callback.
  Future<void> finish({required Future<void> Function(MachineProfile) onEnrolled}) async {
    final issued = profile;
    if (issued == null || stage == DirectSetupStage.waiting) _invalid('Wait for the locally approved VM identity first.');
    await save();
    final profiles = await ProfileVault().load();
    final matches = profiles.where((saved) => saved.id == issued.id).toList();
    if (matches.length > 1 || (matches.isNotEmpty && !matches.single.sameCredentials(issued))) {
      throw ApiException('This agent already has a different saved identity. Its profile was not replaced. Resolve it in Machines before retrying.');
    }
    if (stage == DirectSetupStage.saved && matches.isEmpty) {
      throw ApiException('The completed profile is missing from the vault. Restore the saved profile before acknowledging; no identity will be reissued.');
    }
    final api = AgentApi(issued);
    try {
      if (matches.isEmpty) {
        final health = await api.call('GET', '/health');
        if (health['agent_id'] != issued.id) throw ApiException('Authenticated VM identity mismatch.');
        await api.call('GET', '/catalog');
      }
      await onEnrolled(matches.isEmpty ? issued : matches.single);
      // Admission must reconcile live state even if a previous vault commit
      // succeeded. Verify one exact credential before retiring publication.
      final committed = (await ProfileVault().load()).where((saved) => saved.id == issued.id).toList();
      if (committed.length != 1 || !committed.single.sameCredentials(issued)) {
        throw ApiException('The issued identity has not been committed to the profile vault. Retry admission of this same identity.');
      }
      await _with(DirectSetupStage.saved, issued).save();
      final result = await api.call('POST', '/direct/complete', body: {'nonce': nonce});
      if (!_keys(result, {'completed'}) || result['completed'] != true) throw ApiException('The VM did not acknowledge completion. The saved profile remains usable; retry acknowledgement without reinstalling.');
      await clear();
    } finally { api.close(); }
  }
}

/// JSON decoding with duplicate-key rejection (including nested device data).
Map<String, dynamic> _strictObject(String text) {
  final parser = _Json(text);
  final result = parser.value(0);
  parser.space();
  if (parser.at != text.length || result is! Map<String, dynamic>) _invalid('Invalid direct JSON object.');
  return result;
}
class _Json {
  final String text;
  int at = 0;
  _Json(this.text);
  void space() { while (at < text.length && ' \r\n\t'.contains(text[at])) { at++; } }
  dynamic value(int depth) {
    if (depth > 8) _invalid();
    space();
    if (at >= text.length) _invalid();
    if (text[at] == '"') {
      final token = RegExp(r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"').matchAsPrefix(text, at);
      if (token == null) _invalid();
      at = token.end;
      return jsonDecode(token[0]!);
    }
    if (text[at] == '{') {
      at++; space();
      final map = <String, dynamic>{};
      if (at < text.length && text[at] == '}') { at++; return map; }
      while (true) {
        space();
        if (at >= text.length || text[at] != '"') _invalid();
        final key = value(depth + 1) as String;
        space();
        if (map.containsKey(key) || at >= text.length || text[at++] != ':') _invalid('Duplicate or invalid direct JSON field.');
        map[key] = value(depth + 1);
        space();
        if (at >= text.length) _invalid();
        final end = text[at++];
        if (end == '}') return map;
        if (end != ',') _invalid();
      }
    }
    // Protocols here never carry arrays; rejecting them also bounds nesting.
    final token = RegExp(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null').matchAsPrefix(text, at);
    if (token == null) _invalid();
    at = token.end;
    return jsonDecode(token[0]!);
  }
}

/// A bounded RFC1951 decoder. Native inflate APIs do not expose consumed input,
/// so they cannot reject appended streams reliably. No output is allocated past
/// 8192 bytes; distance/history and all reserved symbols are checked here.
List<int> _inflate(List<int> input) {
  final bits = _Bits(input);
  final out = <int>[];
  void add(int byte) { if (out.length >= 8192) _invalid('Direct setup decompression exceeds 8192 bytes.'); out.add(byte); }
  var last = false;
  while (!last) {
    last = bits.read(1) == 1;
    final type = bits.read(2);
    if (type == 0) {
      bits.align();
      final length = bits.read(16);
      if ((length ^ bits.read(16)) != 65535) _invalid();
      for (var i = 0; i < length; i++) { add(bits.read(8)); }
      continue;
    }
    if (type == 3) _invalid();
    late List<int> lengths;
    late List<int> distances;
    if (type == 1) {
      lengths = List.generate(288, (i) => i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8);
      distances = List.filled(32, 5);
    } else {
      final hlit = bits.read(5) + 257;
      final hdist = bits.read(5) + 1;
      final hclen = bits.read(4) + 4;
      if (hlit > 286) _invalid();
      // RFC1951 code-length alphabet permutation.
      const codeOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
      final codeLengths = List.filled(19, 0);
      for (var i = 0; i < hclen; i++) { codeLengths[codeOrder[i]] = bits.read(3); }
      final codes = _Huffman(codeLengths, requireComplete: true);
      final all = <int>[];
      while (all.length < hlit + hdist) {
        final symbol = codes.decode(bits);
        if (symbol < 16) { all.add(symbol); continue; }
        if (symbol == 16 && all.isEmpty) _invalid();
        final count = symbol == 16 ? bits.read(2) + 3 : symbol == 17 ? bits.read(3) + 3 : bits.read(7) + 11;
        final length = symbol == 16 ? all.last : 0;
        if (all.length + count > hlit + hdist) _invalid();
        all.addAll(List.filled(count, length));
      }
      lengths = all.sublist(0, hlit); distances = all.sublist(hlit);
    }
    if (lengths[256] == 0) _invalid();
    final literals = _Huffman(lengths);
    final offsets = _Huffman(distances, allowEmpty: true);
    const lengthBase = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
    const lengthExtra = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
    const distanceBase = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
    const distanceExtra = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
    while (true) {
      final symbol = literals.decode(bits);
      if (symbol < 256) { add(symbol); continue; }
      if (symbol == 256) break;
      if (symbol > 285) _invalid();
      final index = symbol - 257;
      final length = lengthBase[index] + bits.read(lengthExtra[index]);
      final distanceSymbol = offsets.decode(bits);
      if (distanceSymbol > 29) _invalid();
      final distance = distanceBase[distanceSymbol] + bits.read(distanceExtra[distanceSymbol]);
      if (distance > out.length || out.length + length > 8192) _invalid();
      for (var i = 0; i < length; i++) { add(out[out.length - distance]); }
    }
  }
  if ((bits.at + 7) ~/ 8 != input.length) _invalid('Trailing direct setup compressed data is forbidden.');
  return out;
}
class _Bits {
  final List<int> bytes;
  int at = 0;
  _Bits(this.bytes);
  int read(int count) {
    if (at + count > bytes.length * 8) _invalid('Truncated direct setup data.');
    var value = 0;
    for (var i = 0; i < count; i++, at++) { value |= ((bytes[at ~/ 8] >> (at % 8)) & 1) << i; }
    return value;
  }
  void align() { at = (at + 7) ~/ 8 * 8; }
}
class _Huffman {
  final _symbols = <int, int>{};
  _Huffman(List<int> lengths, {bool requireComplete = false, bool allowEmpty = false}) {
    final counts = List.filled(16, 0);
    for (final length in lengths) { if (length < 0 || length > 15) _invalid(); counts[length]++; }
    counts[0] = 0;
    var remaining = 1;
    for (var i = 1; i <= 15; i++) { remaining = remaining * 2 - counts[i]; if (remaining < 0) _invalid(); }
    final populated = counts.fold<int>(0, (sum, count) => sum + count);
    if (remaining != 0 && !(allowEmpty && populated == 0) &&
        (requireComplete || populated != 1 || counts[1] != 1)) {
      _invalid('Incomplete direct setup Huffman tree.');
    }
    final next = List.filled(16, 0);
    var code = 0;
    for (var i = 1; i <= 15; i++) { code = (code + counts[i - 1]) << 1; next[i] = code; }
    for (var symbol = 0; symbol < lengths.length; symbol++) {
      final length = lengths[symbol];
      if (length == 0) continue;
      var normal = next[length]++;
      var reversed = 0;
      for (var i = 0; i < length; i++) { reversed = (reversed << 1) | (normal & 1); normal >>= 1; }
      _symbols[(length << 16) | reversed] = symbol;
    }
  }
  int decode(_Bits bits) {
    var code = 0;
    for (var length = 1; length <= 15; length++) {
      code |= bits.read(1) << (length - 1);
      final symbol = _symbols[(length << 16) | code];
      if (symbol != null) return symbol;
    }
    _invalid('Invalid direct setup Huffman stream.');
  }
}
