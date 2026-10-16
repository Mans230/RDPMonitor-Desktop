# Security

## Scope and trust boundaries

RDPMonitor Desktop uses a native Flutter client, an HTTPS gateway, a privileged resident Windows worker and a separate signed-in user session helper. There is no browser administration panel or Telegram transport to configure. The client runs as a normal user; closing it does not stop the worker's monitoring, protection, accepted jobs or backup schedules.

The constrained gateway communicates with the worker through an ACL-protected local named pipe. The worker validates capabilities, roles and exact-parameter confirmations before privileged operations. Interactive actions require the appropriate signed-in session helper; there is no SYSTEM/session-zero desktop fallback. The deployment guide describes the intended service-account and filesystem isolation; installed SCM/boot acceptance remains a release gate.

## Enrollment and network exposure

- Approve each device locally with a short-lived, one-use pairing code and an owner/operator/viewer role. Keep pairing codes private and compare the exact server certificate SHA256 fingerprint over a trusted channel.
- Normal connections use the enrolled CA and individual client certificate, with hostname and expiration checks. Do not disable certificate validation to fix an endpoint mismatch. Revoke lost devices; a network disconnect is not revocation or job cancellation.
- Relay installation keeps the Windows gateway on loopback; desktop and agent connect outward to the operator's HTTPS/WSS relay. Advanced direct access must instead select a private/VPN interface, certificate names and approved sources. Neither mode permits unrestricted public administration ingress.
- Network timeouts do not prove a mutation failed. Inspect durable Activity/jobs before resubmitting; cancellation does not promise rollback.
- The self-hosted relay forwards opaque inner agent TLS/mTLS, not Windows RPC authority. Installation invitations only admit relay registrations. Connection envelopes use AES-256-GCM with a locally copied 256-bit fragment secret, SHA256 lookup identifier, origin-bound associated data and a short lifetime. The broker cannot replace the authenticated fingerprint or read the enrollment code from its stored ciphertext.
- Routing credentials are hashed at the broker, DPAPI-protected on Windows and held in the desktop's OS credential vault. A route grant alone never authorizes an agent operation. Device revocation remains effective on existing inner TLS connections; permanent route revocation disconnects transport without uninstalling Windows code or changing policy.
- Remote relay origins require ordinary HTTPS certificate validation. The only HTTP exception is explicit numeric-loopback development mode with a debug client; release clients and installers reject it. The relay can observe metadata, misroute or deny traffic, but a wrong agent must fail inner certificate verification before receiving the enrollment secret.
- Live broker sockets, including closing sockets, retain bounded quota until native transport teardown. Stalled output is forcibly aborted rather than relying on a close frame or asyncio's buffered graceful close. Use the supplied single-process launcher and pinned protocol/dependencies, not an arbitrary ASGI worker configuration.

See [deployment, migration and recovery](docs/DESKTOP-DEPLOYMENT.md) for the signed installer, certificate-host configuration and recovery procedures.

## Credentials and recovery material

Runtime identities, protected secrets, configuration, jobs and telemetry belong in protected data (normally `%ProgramData%\RDPMonitor`), not source or release archives. Worker secrets/configuration/job snapshots are encrypted. Elevated state is Administrators-owned; only SYSTEM/Administrators can write it. The constrained gateway receives noninheriting root descriptor/attribute/traverse access and read access to its own TLS/routing inputs, never inherited access to worker database files or the CA key. Do not publish runtime databases, private keys, enrollment/install codes, relay keys, provider credentials or unsanitized diagnostics. Ignore rules do not replace publication review.

The client stores profiles and device credentials in `flutter_secure_storage` using Windows Credential Manager-backed encryption, Android Keystore-backed storage or iOS Keychain. Provider credentials belong only on a trusted server, never in Flutter assets. Local notifications require an active client. Although the worker has APNs/FCM sender integration, **mobile push-token acquisition/registration is not implemented in the current Flutter client**; configuring provider credentials alone does not enable mobile background delivery.

Keep independent, encrypted off-host recovery material. Windows DPAPI is not portable recovery: legacy migration must run as the original Windows account when its user-scoped secrets need decryption. Do not copy encrypted state to another host/account and assume it will work. Rollback restores identities and revocations as well as other snapshot state; review subsequent administrative changes and device access afterward.

## Network reachability monitoring

The worker probes the configured reachability target (`ping_target`, default `1.1.1.1`) over TCP about once a minute while `net_watch` is enabled. After the failure debounce it records a durable `network.down` event, and a matching `network.up` event with the outage duration when connectivity returns. Those events feed the client inbox and any configured push provider; they are the record to inspect when a machine was isolated. The probe is outbound only: it opens no listening port, uploads nothing off-host and runs no command. Set `net_watch` to false in monitor settings to disable it, or use the reachability switch in the Overview network panel, which rewrites only `net_watch` against the current revision. A powered-off machine cannot report its own outage, so reliable machine-down alerting still needs an external observer.

## Recent hardening

- Monitor configuration is fail-closed: a field whose name reads as credential material is excluded from the readable and writable configuration surface, even when it is newly introduced, so a future secret cannot silently become exportable or settable.
- The job transport, durable events and audit records now share a single secret-name definition instead of three lists that could drift.
- The update-availability comparison uses SHA-256 rather than MD5.
- Backup pre/post hooks run with the worker identity. They can be disabled with the `hooks_enabled` backup setting, a command containing a NUL byte is refused rather than executed, and each run is logged by SHA-256 fingerprint instead of the command text, which may embed credentials.

## Unsigned prerelease and outstanding gates

The unsigned Windows ZIP and explicitly labeled native preview installer are evaluation prereleases, not authenticated production releases. Native preview setup requires affirmative local consent, forces monitoring-only service deployment and viewer pairing, and cannot turn itself into a full-administration installation. Production package, publisher and signature checks remain separate and fail closed. A real publisher signing key and signed coherent manifest are required for production distribution; no self-signed substitute is generated.

Automated tests and local CLI/UI smoke checks do not establish production safety. Outstanding acceptance includes destructive policy/account/power operations with console recovery; installed SCM service-account isolation, reboot-without-login and logoff behavior; signed fresh install, original-account migration, update failure and exact-state rollback; independent off-host backup recovery and actual image boot; direct visual/accessibility acceptance on a clean Windows machine; and signed/provisioned real-device mobile lifecycle, token registration and provider delivery. See the deployment guide's release-gate table. Platform source or compilation alone is not mobile release readiness.

Public relay hosting, DNS/ACME issuance, container deployment and clean-VM setup/reboot/repair/uninstall are not established by local relay sockets or an installer build. Keep console recovery available. A copied URI must be pasted into the native app/setup, never navigated in a browser or put in arguments/logs; clipboard history can retain it. Native setup exchanges secrets only through administrator/SYSTEM-protected session files and preserves the installed runtime for repair if post-install pairing fails.

## Reporting a vulnerability

Before sharing vulnerability details, check the [new repository's Security tab](https://github.com/Mans230/RDPMonitor-Desktop/security) for its currently available reporting policy and contact options. Private vulnerability reporting is not assumed to be enabled, and no security email is advertised here. If no private channel is listed, use a public issue only to request a private contact method, without exploit details, credentials or affected-host information. Do not publish an unpatched vulnerability or secrets in an issue.

## License and upstream

This project derives from [Mans230/RDPMonitor](https://github.com/Mans230/RDPMonitor) and remains under the [MIT license](LICENSE). Retain copyright, license and applicable dependency/external-tool notices when redistributing.
