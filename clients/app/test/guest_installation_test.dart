import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rdpmonitor/guest_installation.dart';

const _url = 'https://github.com/Mans230/RDPMonitor-Desktop/releases/download/v1.0.0-preview.4/RDPMonitorGuest-1.0.0-windows-x64-UNSIGNED-PREVIEW-setup.exe';
final _hash = List.filled(64, 'a').join();
final _pin = List.filled(40, 'b').join();
final _setup = Uri(scheme: 'rdpmonitor', host: 'setup',
  queryParameters: {'relay': 'https://relay.example.com', 'v': '1'},
  fragment: '${base64Url.encode(List.filled(32, 17)).replaceAll('=', '')}.${base64Url.encode(List.filled(32, 29)).replaceAll('=', '')}').toString();

class _Bundle extends CachingAssetBundle {
  final String text;
  _Bundle(this.text);
  @override
  Future<ByteData> load(String key) async => ByteData.sublistView(Uint8List.fromList(utf8.encode(text)));
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  GuestInstallerRelease preview({String url = _url}) => GuestInstallerRelease(
    url: url, sha256: _hash, unsignedPreview: true);

  test('release rejects CMD expansion, HTTPS ambiguity and absent production identity', () {
    for (final url in [
      'http://example.com/guest.exe', 'https://u@example.com/guest.exe',
      'https://example.com/a?token=x', 'https://example.com/a#fragment',
      'https://example.com/a%20b.exe', 'https://example.com/a&whoami',
      'https://example.com/a!PATH!', 'https://example.com/a"b',
      'https://example.com/a\r\nb',
    ]) {
      expect(() => preview(url: url), throwsFormatException);
    }
    expect(() => GuestInstallerRelease(url: _url, sha256: _hash,
      unsignedPreview: false), throwsFormatException);
    expect(() => GuestInstallerRelease(url: _url, sha256: 'bad',
      unsignedPreview: true), throwsFormatException);
  });

  test('private transport round-trips without entering PowerShell argv or public code', () async {
    final command = await buildGuestInstallCommand(setupUri: _setup,
      release: preview(), acceptUnsignedPreview: true);
    expect(command.length, lessThanOrEqualTo(8191));
    expect(command, isNot(contains('\n')));
    expect(command, isNot(contains(_setup)));
    final privateValue = RegExp(r'^set "RDP_MONITOR_SETUP=([A-Za-z0-9_-]+)"').firstMatch(command)!.group(1)!;
    expect(utf8.decode(base64Url.decode(base64Url.normalize(privateValue))), _setup);
    final arguments = command.substring(command.indexOf('"%SystemRoot%'));
    expect(arguments, isNot(contains(privateValue)));
    expect(arguments, isNot(contains(_setup)));
    final encoded = RegExp(r'-EncodedCommand ([A-Za-z0-9+/=]+)').firstMatch(command)!.group(1)!;
    final bytes = base64.decode(encoded);
    expect(bytes.length.isEven, isTrue);
    final publicCode = String.fromCharCodes(List.generate(bytes.length ~/ 2,
      (i) => bytes[i * 2] | (bytes[i * 2 + 1] << 8)));
    final compressed = RegExp(r'set "RDP_MONITOR_BOOTSTRAP=([A-Za-z0-9+/=]+)"').firstMatch(command)!.group(1)!;
    final bootstrap = utf8.decode(ZLibDecoder(raw: true).convert(base64.decode(compressed)));
    expect(publicCode, isNot(contains(privateValue)));
    expect(bootstrap, isNot(contains(privateValue)));
    expect(bootstrap, isNot(contains(_setup)));
  });

  test('preview consent is explicit; production never inherits preview consent', () async {
    await expectLater(buildGuestInstallCommand(setupUri: _setup,
      release: preview()), throwsFormatException);
    final command = await buildGuestInstallCommand(setupUri: _setup,
      release: GuestInstallerRelease(url: _url, sha256: _hash,
        unsignedPreview: false, publisherThumbprint: _pin),
      acceptUnsignedPreview: true);
    expect(command, contains('set "RDP_MONITOR_INSTALLER_MODE=production"'));
    expect(command, contains('set "RDP_MONITOR_PREVIEW_ACCEPT="'));
    expect(command, isNot(contains('I_ACCEPT_UNSIGNED_MONITORING_ONLY')));
  });

  test('invalid capabilities, unavailable bootstrap and CMD overflow fail closed', () async {
    for (final value in ['not a setup capability', ' $_setup', '$_setup ']) {
      await expectLater(buildGuestInstallCommand(setupUri: value,
        release: preview(), acceptUnsignedPreview: true), throwsA(isA<Exception>()));
    }
    await expectLater(buildGuestInstallCommand(setupUri: _setup,
      release: preview(), acceptUnsignedPreview: true, bundle: _Bundle('')), throwsFormatException);
    await expectLater(buildGuestInstallCommand(setupUri: _setup,
      release: preview(url: 'https://example.com/${List.filled(8192, 'a').join()}'),
      acceptUnsignedPreview: true), throwsFormatException);
  });

  test('actual existing CMD clears private environment on success and failure', () async {
    for (final nativeExit in [0, 42]) {
      final command = await buildGuestInstallCommand(setupUri: _setup,
        release: preview(), acceptUnsignedPreview: true,
        bundle: _Bundle('exit $nativeExit'));
      final process = await Process.start(
        '${Platform.environment['SystemRoot']}\\System32\\cmd.exe', ['/d', '/q']);
      final output = process.stdout.drain<void>();
      final errors = process.stderr.drain<void>();
      try {
        // Feed an existing shell's stdin. Putting this private line in /c argv
        // would violate the command's process-list privacy contract.
        process.stdin.writeln(command);
        process.stdin.writeln('set "OBSERVED=%ERRORLEVEL%"');
        process.stdin.writeln('if defined RDP_MONITOR_SETUP exit 90');
        process.stdin.writeln('if defined RDP_MONITOR_PREVIEW_ACCEPT exit 91');
        process.stdin.writeln('exit %OBSERVED%');
        await process.stdin.close();
        expect(await process.exitCode.timeout(const Duration(seconds: 20)),
          nativeExit == 0 ? 0 : 1);
        await Future.wait([output, errors]);
      } finally {
        process.kill();
      }
    }
  }, skip: !Platform.isWindows);
}
