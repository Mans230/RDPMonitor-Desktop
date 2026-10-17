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
