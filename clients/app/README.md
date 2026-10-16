# RDPMonitor native client

Flutter Windows, Android and iOS source for RDPMonitor 1.0.0. This is a native widget application, not a WebView. It connects to the Windows agent HTTPS `/api/v1` interface. No shared API password, browser panel, or Telegram account is needed.

## Development and enrollment

Install Flutter stable/Dart 3.13 and the target SDK/toolchain. From this directory, run `flutter pub get --enforce-lockfile`, then `flutter run -d windows`; build the desktop with `flutter build windows --release`. Windows requires Visual Studio 2022 Desktop development with C++, the Windows SDK and ATL. Prefer a short checkout path. Android requires an Android SDK/JDK (`flutter build apk --debug` is a development build); iOS requires a Mac, Xcode, a signing team and an appropriate device provisioning profile.

Start an actual Windows agent from the repository root, using an elevated terminal, Python 3.14 and installed root `requirements.txt` dependencies:

```powershell
python -m agent serve --read-only --data-dir "$env:LOCALAPPDATA\RDPMonitorEvaluation" --port 9443
python -m agent pair --data-dir "$env:LOCALAPPDATA\RDPMonitorEvaluation" --role owner
```

The example uses safe read-only local evaluation: real telemetry without administration mutations or backup schedules. Run `pair` in a second elevated terminal. Omit `--read-only` only on a machine you intend to administer, preferably a disposable VM first. The integrated `serve` command is for development. Normal deployment uses the signed installer and separate privileged worker/constrained gateway services, not an open terminal. The worker owns monitoring and schedules even when this app is closed. The signed-in user session helper supplies interactive operations; source users can run `python -m agent session-helper` in their own session, with no SYSTEM desktop fallback. Configure certificate hosts and network access policy before connecting remotely. Do not expose an unrestricted service port to the public Internet. See [deployment](../../docs/DESKTOP-DEPLOYMENT.md).

Choose **Enroll machine**. Enter the HTTPS origin, machine name, optional group, local device name, the SHA256 **server certificate** fingerprint printed locally by the agent and its short-lived pairing code. Compare the fingerprint using a trusted channel before approving it. A rootless bootstrap TLS context admits only that exact pinned certificate before sending the code/CSR. RSA2048 identity generation runs in a background isolate. Enrollment codes and CSR payloads are never persisted by the app.

After enrollment the app trusts only the issued agent CA, uses its own enrolled client certificate/key and retains normal hostname and expiration checks. A changed network address is editable without changing the identity, provided that hostname/address is covered by the agent certificate. Server identity replacement requires verified pairing; certificate validation cannot be disabled. **Settings → Renew this device certificate** generates a new key and requests renewal; old access is revoked when the replacement is issued. Keep the client running until secure persistence completes. A lost renewal response or process termination during renewal can require trusted local pairing again.

Profiles, grouping, certificates and private keys are held only in `flutter_secure_storage`: Windows AES-GCM encrypted storage with its encryption key in Windows Credential Manager, Android Keystore-backed encrypted preferences, or iOS Keychain using device-only accessibility. Profile writes use two protected slots, verify the new record, then switch the protected active pointer before deleting the old slot. Android application backup is disabled. This app does not export private credentials to plaintext files. iOS loads its client identity as an in-memory PKCS12 bundle and CA as DER as required by Dart's platform TLS implementation.

## Workflows

- Machines: individual targets, editable secure connection profiles, groups and read-only fleet status.
- Overview/Monitoring: actual timestamped CPU, RAM, disks, NICs, sessions/processes, history charts and accessible sample tables. Missing measurements are never default zeroes. Live/stale/offline indicate contact and sample age independently of retained readings.
- Security, Accounts, Processes/services, Backup/recovery, Files, Diagnostics, Imaging, Automation, Settings and Maintenance: executable operations discovered from the authenticated agent catalog. Typed fields, choices, booleans and masked secret entry are generated from agent descriptors. Unknown catalog sections remain reachable in Maintenance. High-risk actions require the exact machine name, a visible risk review and an agent-issued nonce bound to the exact parameters.
- Files: native file picker, SHA256 declaration, 256 KiB upload chunks, explicit pause/resume using the acknowledged agent offset, and durable completion jobs. Only the worker-configured approved upload directory is available. Downloads stream to a chosen desktop path or app documents on phones, with SHA256 verification when the result provides a digest. iOS Files sharing exposes downloaded documents, not Keychain credentials.
- Activity: durable jobs, progress/results, explicit cancellation, authenticated result artifacts, persisted events, acknowledgements and actor-attributed audit. Job polling survives navigation/reconnection. Cancellation never promises rollback. Mutations are never retried automatically; an uncertain submission displays its request identifier and asks the operator to inspect Activity.
- Settings: recursive typed object/list/numeric/boolean/text controls for monitor and backup domains; revision preconditions and exact `configuration.update` confirmations. Unchanged `***` secret markers are preserved by the agent; Replace/clear explicitly changes a secret. Invalid local numeric edits cannot be submitted. A conflict preserves unsaved edits for deliberate resolution.
- Devices: server-side enrollment/role/expiry details and confirmed certificate revocation, including a specific warning when revoking this device.

## Notifications and mobile delivery

Settings contains an explicit local-notification opt-in. Windows uses a native application identity; Android requests notification permission; iOS requests user notification authorization. Newly received warning/error/critical events generate local alerts while this client is active. The agent's durable event inbox remains authoritative while the app is suspended or closed. API/notification errors are visible rather than replaced by fake data.

The worker includes APNs/FCM sender integration, but native push-token acquisition and registration are **not implemented in this Flutter client**. No production provider credentials/provisioning are supplied. Entering provider credentials alone cannot enable background delivery for this app. Provider secrets must stay on a trusted server, never in Flutter assets/source. Mobile is not release-ready: token acquisition/registration, signed/provisioned real-device lifecycle, iOS push delivery, Android background behavior and native notification delivery remain acceptance gates. Generation of platform source or successful compilation is not evidence of these checks.

For an Android release, supply signing environment variables `RDPMONITOR_ANDROID_KEYSTORE`, `RDPMONITOR_ANDROID_STORE_PASSWORD`, `RDPMONITOR_ANDROID_KEY_ALIAS` and `RDPMONITOR_ANDROID_KEY_PASSWORD` to the trusted build environment. Release builds never silently use debug signing. iOS signing is configured in Xcode for your own team; its Keychain entitlement must be included in the provisioning profile.

## Validation ownership

Dependency resolution has been performed. Unit/widget behavior regressions are included in `test/widget_test.dart`. Build/analyze/test/device and installed Windows UI validation are integration-owner checks, not claimed here. Expected integration checks include real TLS enrollment and mismatch rejection, revocation/renewal, restart/reconnect job tracking, stale telemetry, masked-secret revision preservation, chunk resume, artifact hash failure, operation catalog coverage, narrow-screen layout, keyboard/screen-reader navigation and notifications on each target platform.

## Prerelease limits and attribution

The published unsigned Windows x64 ZIP is an evaluation prerelease, not a signed production installer. Production publisher signing and installed SCM/boot/logoff isolation checks remain open, along with destructive policy/account/power safety, signed migration/update/rollback, off-host recovery and actual image boot. Direct visual acceptance on a clean Windows machine is still required: local RDP captures were intermittently blank despite responsive accessibility controls. Consult the [deployment release gates](../../docs/DESKTOP-DEPLOYMENT.md#verification-and-release-gates) before production use; mobile source is not a mobile release.

Derived from [Mans230/RDPMonitor](https://github.com/Mans230/RDPMonitor), under the [MIT license](../../LICENSE). Preserve upstream copyright and dependency/external-tool license notices.
