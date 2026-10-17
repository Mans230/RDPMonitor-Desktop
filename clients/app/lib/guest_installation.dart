import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

import 'relay.dart';

class GuestInstallerRelease {
  final String url;
  final String sha256;
  final bool unsignedPreview;
  final String? publisherThumbprint;

  GuestInstallerRelease({required this.url, required this.sha256,
    required this.unsignedPreview, this.publisherThumbprint}) {
    final uri = Uri.tryParse(url);
    // SET is parsed by CMD before PowerShell starts. Never permit expansion,
    // quoting, redirection, whitespace or command separators in public values.
    if (uri == null || uri.scheme != 'https' || uri.host.isEmpty ||
        uri.userInfo.isNotEmpty || uri.hasQuery || uri.hasFragment ||
        !RegExp(r'^https://[A-Za-z0-9._~:/-]+$').hasMatch(url) ||
        !RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(sha256) ||
        (publisherThumbprint != null && !RegExp(r'^[0-9a-fA-F]{40}$').hasMatch(publisherThumbprint!)) ||
        (!unsignedPreview && publisherThumbprint == null)) {
      throw const FormatException('The trusted guest release descriptor is invalid.');
    }
  }
}

/// Paste into an existing Administrator CMD, never pass as cmd.exe /c argv.
/// This private capability can remain in clipboard/CMD history; base64 is not
/// encryption. Only public bundled code is present in PowerShell's argv.
Future<String> buildGuestInstallCommand({required String setupUri,
  required GuestInstallerRelease release, bool acceptUnsignedPreview = false,
  AssetBundle? bundle}) async {
  if (setupUri != setupUri.trim()) {
    throw const FormatException('The private setup capability is invalid.');
  }
  RelaySetupCode.parse(setupUri);
  if (release.unsignedPreview && !acceptUnsignedPreview) {
    throw const FormatException('Explicit unsigned monitoring-only acceptance is required.');
  }
  final script = await (bundle ?? rootBundle).loadString('assets/guest-bootstrap.ps1');
  if (script.trim().isEmpty) {
    throw const FormatException('The bundled guest bootstrap is missing.');
  }
  // Compress only trusted bundled public code, never private input. Transport
  // its ASCII base64 in a separate environment value to avoid double-base64
  // expansion inside UTF-16LE EncodedCommand and CMD's 8191-character limit.
  final packed = base64.encode(ZLibEncoder(raw: true).convert(utf8.encode(script)));
  const publicScript = r"&([scriptblock]::Create([IO.StreamReader]::new("
    r"[IO.Compression.DeflateStream]::new([IO.MemoryStream]::new("
    r"[Convert]::FromBase64String($env:RDP_MONITOR_BOOTSTRAP)),[IO.Compression.CompressionMode]::Decompress)).ReadToEnd()))";
  final utf16 = <int>[];
  for (final unit in publicScript.codeUnits) {
    utf16.add(unit & 255); utf16.add(unit >> 8);
  }
  final values = <String, String>{
    'RDP_MONITOR_SETUP': base64Url.encode(utf8.encode(setupUri)).replaceAll('=', ''),
    'RDP_MONITOR_BOOTSTRAP': packed,
    'RDP_MONITOR_INSTALLER_URL': release.url,
    'RDP_MONITOR_INSTALLER_SHA256': release.sha256,
    'RDP_MONITOR_INSTALLER_MODE': release.unsignedPreview ? 'preview' : 'production',
    'RDP_MONITOR_PUBLISHER': release.publisherThumbprint ?? '',
    'RDP_MONITOR_PREVIEW_ACCEPT': release.unsignedPreview ? 'I_ACCEPT_UNSIGNED_MONITORING_ONLY' : '',
  };
  final cleanup = values.keys.map((key) => 'set "$key="').join(' & ');
  // SET resets CMD's errorlevel. Branch before clearing, then return 1 for any
  // failure; the bootstrap prints the exact native installer exit when known.
  final command = '${values.entries.map((e) => 'set "${e.key}=${e.value}"').join(' & ')} & '
    '"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -NonInteractive -EncodedCommand ${base64.encode(utf16)}'
    ' && ($cleanup) || ($cleanup & "%SystemRoot%\\System32\\cmd.exe" /d /c exit 1)';
  if (command.length > 8191) {
    throw const FormatException('The private CMD command exceeds the Windows 8191-character limit. Use a shorter relay origin or release URL.');
  }
  return command;
}
