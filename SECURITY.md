# Security

## Scope and trust boundaries

RDPMonitor Desktop uses a native Flutter client, an HTTPS gateway, a privileged resident Windows worker and a separate signed-in user session helper. There is no browser administration panel or Telegram transport to configure. The client runs as a normal user; closing it does not stop the worker's monitoring, protection, accepted jobs or backup schedules.

The constrained gateway communicates with the worker through an ACL-protected local named pipe. The worker validates capabilities, roles and exact-parameter confirmations before privileged operations. Interactive actions require the appropriate signed-in session helper; there is no SYSTEM/session-zero desktop fallback. The deployment guide describes the intended service-account and filesystem isolation; installed SCM/boot acceptance remains a release gate.

## Enrollment and network exposure

- Approve each device locally with a short-lived, one-use pairing code and an owner/operator/viewer role. Keep pairing codes private and compare the exact server certificate SHA256 fingerprint over a trusted channel.
- Normal connections use the enrolled CA and individual client certificate, with hostname and expiration checks. Do not disable certificate validation to fix an endpoint mismatch. Revoke lost devices; a network disconnect is not revocation or job cancellation.
- Installation defaults to loopback. Remote deployment must select the real private/VPN interface, certificate names and approved source addresses. Do not expose an unrestricted public administration port or use broad port forwarding.
- Network timeouts do not prove a mutation failed. Inspect durable Activity/jobs before resubmitting; cancellation does not promise rollback.

See [deployment, migration and recovery](docs/DESKTOP-DEPLOYMENT.md) for the signed installer, certificate-host configuration and recovery procedures.

## Credentials and recovery material

Runtime identities, protected secrets, configuration, jobs and telemetry belong in the protected data directory (normally `%ProgramData%\RDPMonitor`), not source control or release archives. Worker secrets/configuration/job snapshots are encrypted; filesystem ACLs and the worker/gateway boundary also matter. Do not publish runtime databases, private keys, enrollment codes, provider credentials, configuration containing secrets, or unsanitized diagnostic/audit exports. Ignore rules are not a substitute for reviewing a publication.

The client stores profiles and device credentials in `flutter_secure_storage` using Windows Credential Manager-backed encryption, Android Keystore-backed storage or iOS Keychain. Provider credentials belong only on a trusted server, never in Flutter assets. Local notifications require an active client. Although the worker has APNs/FCM sender integration, **mobile push-token acquisition/registration is not implemented in the current Flutter client**; configuring provider credentials alone does not enable mobile background delivery.

Keep independent, encrypted off-host recovery material. Windows DPAPI is not portable recovery: legacy migration must run as the original Windows account when its user-scoped secrets need decryption. Do not copy encrypted state to another host/account and assume it will work. Rollback restores identities and revocations as well as other snapshot state; review subsequent administrative changes and device access afterward.

## Unsigned prerelease and outstanding gates

The Windows x64 unsigned ZIP is an evaluation prerelease, not an authenticated production installer. Do not bypass production signature checks to install it. Publisher signing and a signed coherent release manifest are required for production distribution.

Automated tests and local CLI/UI smoke checks do not establish production safety. Outstanding acceptance includes destructive policy/account/power operations with console recovery; installed SCM service-account isolation, reboot-without-login and logoff behavior; signed fresh install, original-account migration, update failure and exact-state rollback; independent off-host backup recovery and actual image boot; direct visual/accessibility acceptance on a clean Windows machine; and signed/provisioned real-device mobile lifecycle, token registration and provider delivery. See the deployment guide's release-gate table. Platform source or compilation alone is not mobile release readiness.

## Reporting a vulnerability

Before sharing vulnerability details, check the [new repository's Security tab](https://github.com/Mans230/RDPMonitor-Desktop/security) for its currently available reporting policy and contact options. Private vulnerability reporting is not assumed to be enabled, and no security email is advertised here. If no private channel is listed, use a public issue only to request a private contact method, without exploit details, credentials or affected-host information. Do not publish an unpatched vulnerability or secrets in an issue.

## License and upstream

This project derives from [Mans230/RDPMonitor](https://github.com/Mans230/RDPMonitor) and remains under the [MIT license](LICENSE). Retain copyright, license and applicable dependency/external-tool notices when redistributing.
