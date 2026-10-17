# RDP Monitor v4.3-fixed

Security and reliability corrections applied to a separate copy of v4.3:

- Replaced TCP-port instance locking with a per-installation Windows named mutex.
- Updated installer status and uninstall detection to use the same mutex.
- Reworked the RDP allow-list as explicit TCP and UDP rules.
- Windows `TermService`/RDP service rules are now treated as relevant RDP rules.
- Firewall rules are tracked by unique rule ID rather than non-unique display name.
- Firewall changes are made one at a time and rollback state is saved after each change.
- Failed scans, verification, policy changes, and rule changes trigger rollback.
- Firewall Guard does not enable the firewall unless an RDP access rule was verified.
- Lockdown no longer automatically trusts currently connected clients.
- Corrected Event 4625 NLA fields (`LogonProcessName` and `AuthenticationPackageName`).
- Failed unblock operations retain their local block record.
- Uninstall cleanup now reports a real exit status and `[cleanup] done` marker.
- Text, photo, and document retry queues persist across restarts.
- Password-bearing Telegram messages are deleted on receipt when bot permissions allow.
- Disk2vhd requires a valid signer whose certificate CN is exactly Microsoft Corporation.
- Disk imaging is disabled by default, requires confirmation, refuses the Windows system
  volume as its output target, and persists/reconciles operation state after restarts.
- File upload and Windows user management are disabled by default on fresh installs.
- Added safety regression tests under `tests/`.

Run non-destructive tests with:

```console
python -m unittest discover -s tests -v
```

The monitor still starts at user logon rather than early Windows boot. Changing it to run
as SYSTEM would break interactive screenshot/message features and user-scoped DPAPI, so
that architectural limitation is documented rather than hidden.

## Hardened WebConsole edition

- Integrated the patched core instead of the original v4.3 core.
- Localhost-only installation by default; no automatic public firewall opening.
- Direct remote mode requires TLS certificate/key and an explicit source-IP allow-list.
- Replaced URL bearer tokens with DPAPI-protected login token, HttpOnly SameSite session
  cookie, 30-minute expiry, CSRF token, login throttling, and token rotation.
- Shell/program execution and arbitrary file downloads are disabled by default.
- Added request/body/thread/time limits, security headers, Host checks, file-root and size
  limits, streamed downloads, application-level IP enforcement, and a single-instance lock.
- Escaped dynamic dashboard content and removed external Google Fonts.
- Added validated IP operations, verified unblock behavior, and cross-process blocklist lock.
- Added WebConsole security regression tests.

## Desktop agent: network monitoring and hardening

- Added agent-owned network reachability monitoring. The worker probes `ping_target`
  (default `1.1.1.1`) over TCP about every 60 seconds while `net_watch` is enabled,
  debounces the result, and records durable `network.down`/`network.up` events (with the
  outage duration) that feed the client inbox and any configured push provider. The state
  is exposed through the `monitoring.network_health` operation and the `network` block in
  `snapshot` and `health`.
- The client now shows reachability: a status pill in the machine bar and a reachability
  block in the Overview network panel.
- The Overview network panel gained a one-click reachability switch. It reads and rewrites
  only `net_watch` against the current configuration revision, so it can never clobber
  unrelated monitor settings; the full editor in Settings still exposes the same key with
  its surrounding context.
- Monitor configuration is fail-closed. Any editable field whose name reads as credential
  material is excluded from the readable and writable configuration surface, so a newly
  introduced secret cannot silently become exportable or settable.
- The job transport, durable events and audit records share one secret-name definition.
- The update-availability comparison uses SHA-256 instead of MD5.
- Backup pre/post hooks gained a `hooks_enabled` master switch (default off; opt in),
  refuse a command containing a NUL byte, and are logged by SHA-256 fingerprint instead
  of the command text, which may embed credentials.
- Reorganized client navigation: Diagnostics moved under Observe and Imaging moved under
  Manage, with the grouping rationale documented in code.
- Added network-watch and hardening regression tests to `tests/`.

## Desktop Preview 3 — one-code fleet workspace

- Add machine now asks for name/group and supplies one VM setup code plus the public installer link. Local VM approval triggers automatic encrypted enrollment; no second code is copied back.
- Independent installation/pairing capabilities preserve the broker trust boundary. Pending setup and issued identities are checkpointed in OS-protected storage; ambiguous issuance is never silently replayed.
- Advanced recovery retains an issued identity before the final mTLS probe, including across dialog close/reopen. Pinned response bodies have a 128 KiB limit and 30-second deadline.
- Machines gained grouped disk-space tables and optional contract expiry, renewal, currency/cost and billing-period metadata. Exact integer hundredths avoid monetary rounding; certificate rotation preserves contract fields.
- Added dedicated Backups, Recovery, Processes and Services destinations, related command groups, responsive natural-height one/two/three-column cards and wide-sidebar hide/show with narrow drawer navigation.
- Fleet mutations reject unreadable/unloaded vault state; post-commit cleanup cannot falsely roll back saved metadata. Nested JSON inspectors no longer share expansion booleans with selectable-text scroll offsets.
- Retained merged PR #1 network monitoring/hardening and PR #2 bounded relay lookup/WebSocket Origin checks. Missing reachability measurements are labeled honestly.
- Verification: 187 backend tests and 25 client tests passed, analyzer clean, actual native automatic enrollment and failed-probe/no-replay recovery exercised. Installed SCM/reboot/signing/public relay acceptance remains external.

## Desktop Preview 4 — one-command Windows guest installation

- Add machine prepares one private Administrator CMD command from the requested name/group. The background guest installs silently and the desktop enrolls automatically; no VM desktop app, wizard, manual setup-code entry or return code.
- Added a distinct guest-only runtime/native installer with explicit package components. Guest artifacts omit the Flutter client and desktop shortcut; install, repair, signed update and rollback reject component drift.
- The trusted desktop-bundled public bootstrap downloads only a native executable over HTTPS, verifies its pinned SHA256 and production publisher when applicable, and uses a protected cache. No downloaded script executes, and production trust failures never become unsigned previews.
- Private setup capabilities move through environment into a protected native exchange, never PowerShell/installer arguments or download URLs. Fresh CMD provisioning rejects retained identity/services and always forces monitoring-only/viewer, even for signed builds. Clipboard/CMD history remains private; encoding is not encryption.
- Actual native preparation/consent/copy, narrow/wide layouts, protected pending close/reopen, strict HTTPS/WSS automatic enrollment and live disk telemetry were exercised. Native silent preflight, OS-only-PATH frozen import and download/hash/publisher rejection were exercised separately; installed SCM/reboot/production signing remain external VM acceptance gates.
- Retained merged security follow-up PR #3: fail-closed vault decoding, bounded client response buffering, encoded event paths, pinned removal authority, verified Microsoft imaging staging, PowerShell/VSS argument validation and explicit backup ACL diagnostics.
- Compatibility note: backup hooks now default **off**. Operators who intentionally use pre/post commands must explicitly set `backup.hooks_enabled` to `true`; the unsigned/CMD monitoring-only policy still disables administration and schedules.
- Corrected a Windows named-pipe connection race exposed by integration verification: after contention, the last instance can disappear before its successor exists. The existing five-second handshake now survives that known-busy gap without retrying a submitted RPC; a real Windows-handle regression proves exactly one execution.
- Integrated verification: 196 backend tests and 30 client tests passed; analyzer clean. Full installed service/reboot, production signing and public relay acceptance remain separate external gates.

## Native console redesign — included in Preview 5

- Applied the supplied black-and-white console reference to the existing Flutter app: compact bordered panels, monochrome charts, semantic status accents and dense grouped operation rows.
- Combined Backups/Recovery and Processes/Services navigation with separate tabs; added a searchable real-catalog operation picker and a dedicated CMD setup guide without removing existing capabilities.
- Added full-sidebar/icon-rail/drawer navigation, retained manual hide/show, and preserved disk/expiry/renewal/cost metadata in responsive fleet tables and labelled narrow records.
- Unified dialog actions across setup, profiles, operations, configuration and desktop settings. Phone dialogs use full-height scrollable sheets and full-width actions.
- Added client-only telemetry pause/resume; agent jobs and monitoring remain independent.
- Fixed dialog-theme interpolation when resizing between desktop and phone constraints. A consumer regression reproduces the previous assertion with an open settings dialog and checks resize bounds and dismissal.
- Kept the published Preview 4 one-CMD guest installation and security hardening; no prototype sample operations or telemetry are used.
- Verification: 31 Flutter tests passed, analyzer clean and Windows release binary built. Actual native rendering covered 18 routes/tabs at 1440, 900, 700, 600 and 390 logical pixels (90 scenes) without Flutter error events after the resize fix. Native drawer/sidebar, setup/editor cancellation, pause/resume and a successful read-only `rdp.sessions` job were exercised against a temporary local agent.

## Desktop Preview 5 — relay-free, desktop-bound VM setup

- Add machine now takes name/group and a reachable VM address, prepares one private Administrator CMD command and automatically saves a locally preapproved viewer identity. Relay configuration and return codes are not part of normal setup.
- Desktop client and VM transport keys are distinct. The desktop client private key stays on the PC; the VM creates its own CA and approves the exact CSR locally without opening a remote pairing window. Knowing the IP, nonce or public certificate cannot claim the VM.
- Added bounded direct setup parsing, transport public-key/SAN/lifetime pinning, ordinary mTLS protected probing, expiring public bootstrap and authenticated idempotent completion.
- Added fresh-only native provisioning, unique RDP-peer/explicit source selection and executable/port/source-limited Windows firewall rules. Disabled/permissive filtering or ambiguous source selection fails closed; provider/router configuration remains external. Trusted packaged helper invocation uses process-only execution policy without changing machine/user policy.
- Protected issued/saved checkpoints recover from failed probes, committed-but-reported-failed vault writes and late acknowledgements without duplicate issuance or dropping the live machine. Saved metadata survives reconciliation; initial VM transport keys are removed from saved checkpoints.
- Corrected certificate bundle expiry to the actual DER certificate notAfter precision; cross-language verification exposed the previous millisecond discrepancy.
- Corrected a live telemetry socket race: the HTTPS keep-alive now exceeds the desktop pool's 20-second idle lifetime instead of closing at the same five-second boundary as polling. Native monitoring stayed Live/error-free for 12 consecutive five-second observations after reproducing the stale-connection failure.
- Verification: 218 backend tests and 37 Flutter tests passed; analyzer clean. Actual native preparation/consent/private CMD copy, protected close/reopen and automatic viewer admission were exercised. Frozen worker plus separate named-pipe HTTPS gateway proved real disk telemetry, privileged-access denial, bootstrap retirement and one saved identity; responsive direct dialogs rendered without Flutter errors. Installed SCM/reboot/provider routing and production signing remain unvalidated external gates; this is an unsigned monitoring-only preview.

## Desktop Preview 6 — readable selection labels

- Corrected the shared chip theme: unselected labels now use the surface foreground, and selected choice chips use their explicit contrasting secondary label style. This fixes invisible fleet filters and history/activity selectors without per-screen fallback styles.
- Native light/dark Machines and Activity surfaces were exercised after reproducing the blank labels in the packaged Preview 5 desktop. Direct-installation security and the immutable Preview 5 guest URL/SHA256 remain unchanged.
- Desktop build number is 6. Preview 5 assets remain published unchanged; this is a separate corrected desktop release, not a silent asset replacement.

