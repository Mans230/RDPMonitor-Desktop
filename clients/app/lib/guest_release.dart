import 'guest_installation.dart';

/// Release URL and digest are pinned in the operator app, never fetched from an
/// unsigned mutable manifest. Self-hosted/signed builds must override all trust
/// inputs together; invalid overrides cannot fall back to this preview.
GuestInstallerRelease guestInstallerRelease() {
  const url = String.fromEnvironment('RDP_GUEST_URL');
  const sha256 = String.fromEnvironment('RDP_GUEST_SHA256');
  const mode = String.fromEnvironment('RDP_GUEST_MODE');
  const publisher = String.fromEnvironment('RDP_GUEST_PUBLISHER');
  final overridden = url.isNotEmpty || sha256.isNotEmpty ||
    mode.isNotEmpty || publisher.isNotEmpty;
  if (!overridden) {
    return GuestInstallerRelease(
      url: 'https://github.com/Mans230/RDPMonitor-Desktop/releases/download/v1.0.0-preview.4/RDPMonitorGuest-1.0.0-windows-x64-UNSIGNED-PREVIEW-setup.exe',
      sha256: '3e122b4d69e13f255751bed13f7a8362041bdb02da7e84d3157085693a65d699',
      unsignedPreview: true,
    );
  }
  if (url.isEmpty || sha256.isEmpty ||
      (mode != 'unsigned-preview' && mode != 'production')) {
    throw const FormatException('Guest release overrides require URL, SHA256 and an explicit trust mode.');
  }
  return GuestInstallerRelease(url: url, sha256: sha256,
    unsignedPreview: mode == 'unsigned-preview',
    publisherThumbprint: publisher.isEmpty ? null : publisher);
}
