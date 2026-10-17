import 'guest_installation.dart';

/// Release URL and digest are pinned in the operator app, never fetched from an
/// unsigned mutable manifest. Self-hosted/signed builds must override all trust
/// inputs together; invalid overrides cannot fall back to this preview.
GuestInstallerRelease guestInstallerRelease() {
  const url = String.fromEnvironment('RDP_GUEST_URL');
  const sha256 = String.fromEnvironment('RDP_GUEST_SHA256');
  const mode = String.fromEnvironment('RDP_GUEST_MODE');
  const publisher = String.fromEnvironment('RDP_GUEST_PUBLISHER');
  const setupProtocol = String.fromEnvironment('RDP_GUEST_SETUP_PROTOCOL');
  final overridden = url.isNotEmpty || sha256.isNotEmpty ||
    mode.isNotEmpty || publisher.isNotEmpty || setupProtocol.isNotEmpty;
  if (!overridden) {
    return GuestInstallerRelease(
      url: 'https://github.com/Mans230/RDPMonitor-Desktop/releases/download/v1.0.2-preview.1/RDPMonitorGuest-1.0.2-windows-x64-UNSIGNED-PREVIEW-setup.exe',
      sha256: 'ad867abeeb50b61598c5f45a64c25f7a7458ff249bf97e65e86ff217ff7005c8',
      unsignedPreview: true, setupProtocol: 2,
    );
  }
  if (url.isEmpty || sha256.isEmpty ||
      (mode != 'unsigned-preview' && mode != 'production') ||
      (setupProtocol.isNotEmpty && setupProtocol != '1' && setupProtocol != '2')) {
    throw const FormatException('Guest overrides require URL, SHA256, an explicit trust mode and a supported setup protocol (1 or 2).');
  }
  return GuestInstallerRelease(url: url, sha256: sha256,
    unsignedPreview: mode == 'unsigned-preview',
    publisherThumbprint: publisher.isEmpty ? null : publisher,
    setupProtocol: setupProtocol.isEmpty ? 1 : int.parse(setupProtocol));
}
