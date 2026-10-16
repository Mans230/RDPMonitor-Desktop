# Desktop deployment, migration and recovery

## Deployment status

The Windows native client, frozen agent and native installer can be built locally. Production installation requires a valid publisher code-signing certificate/private key, an HTTPS timestamp service and an authenticated release. A distinct, explicitly consented unsigned preview installer forces monitoring-only services and viewer enrollment. It never falls back from failed production verification; neither preview packaging nor local smoke establishes production readiness.

Run the client as the signed-in user. The agent's privileged worker and constrained gateway are separate Windows services. Closing or exiting the client does not stop monitoring, protection, accepted jobs or backup scheduling. Stopping/removing the services is a different administrative action.

## Build prerequisites

- Windows x64; Python 3.14 with the pinned `requirements.txt` environment.
- Flutter with Dart **3.13.0 or newer within 3.x** and the committed `clients/app/pubspec.lock`. The bounded native WebSocket API requires this SDK minimum.
- Visual Studio 2022 C++ build tools, Windows SDK and ATL; a short checkout path avoids native build path limits.
- Windows SDK `signtool.exe` and a valid RSA code-signing certificate in the current user's certificate store, including the code-signing EKU and private key.
- The matching licensed x64 `Microsoft.VC143.CRT` release redistributable directory and official Microsoft redistribution notice. The build copies these DLLs beside the client; do not use `debug_nonredist`.
- External backup/imaging tools are separate dependencies. Configure approved HTTPS download URLs and independently verified SHA256 digests in the agent tooling operations. Missing tools must produce actionable errors, not silent fallback. Retain each redistributed tool's license and distribution conditions; Disk2vhd licensing is separate.

From an appropriately provisioned build terminal:

```powershell
.\scripts\build-release.ps1 -Version 1.0.0 `
  -CertificateThumbprint $PublisherThumbprint `
  -TimestampUrl $TimestampServiceHttpsUrl `
  -VCRuntimeDirectory $LicensedX64CrtDirectory `
  -VCRedistributionNoticeFile $MicrosoftRedistributionNotice `
  -Python .\.venv\Scripts\python.exe
```

The build bundles the agent runtime and native client, signs PE files and PowerShell scripts, verifies signatures, records dependency/license notices, and writes a signed file-inventory manifest plus ZIP/SHA256. Authenticate the publisher fingerprint independently before installing. A ZIP checksum obtained alongside an untrusted ZIP is not publisher authentication.

For a Build Tools installation, the CRT directory is typically `VC\Redist\MSVC\<version>\x64\Microsoft.VC143.CRT` beneath its installation root; the redistribution notice is under `Licenses\1033\Redist.txt`. Authenticate and retain the toolchain's redistribution terms. End users do not need Visual Studio, Python or Flutter to run the packaged client/runtime.

Build the native wizard around that complete authenticated package:

```powershell
.\scripts\build-installer.ps1 -AcquireCompiler
.\scripts\build-installer.ps1 -Package 'C:\Releases\RDPMonitor-1.0.0-windows-x64' `
  -CertificateThumbprint $PublisherThumbprint -TimestampUrl $TimestampServiceHttpsUrl
```

Compiler acquisition is separate from application installation. It checks the immutable official Inno Setup 7.1.0 asset SHA256 and its Windows Authenticode chain/current official publisher before executing the tool installer. Production setup and its embedded uninstaller are signed; no self-signed publisher or automatic unsigned fallback is created. Retain Inno's embedded notices and review its current commercial-use guidance for your organization.

For an explicitly unsigned evaluation build, use the separate parameter set:

```powershell
.\scripts\build-release.ps1 -UnsignedPreview -Version 1.0.0 -BuildNumber 2 `
  -VCRuntimeDirectory $LicensedX64CrtDirectory `
  -VCRedistributionNoticeFile $MicrosoftRedistributionNotice `
  -Python .\.venv\Scripts\python.exe
.\scripts\build-installer.ps1 `
  -Package '.\dist\RDPMonitor-1.0.0-windows-x64-UNSIGNED-PREVIEW' -UnsignedPreview
```

This builds the complete runtime, dependency/font/Microsoft notices, an explicitly unsigned inventory, ZIP/checksum and then a monitoring-only setup executable. Unsigned checksums establish file integrity, not publisher authenticity. The preview setup cannot enable administration, protection or schedules; use a disposable Windows VM first. The developer/source agent CLI is separate from this installed preview policy: source evaluation must explicitly use `--read-only`.

## Install anywhere and connect with a code

### One-time relay deployment

The operator supplies an internet-reachable server, Docker/Compose, a DNS hostname, ports **80/443 on the relay server**, an ACME contact email and a private administration key. No inbound management port is opened on the Windows VMs. A container build or HTTPS domain is not supplied by GitHub Releases.

From a source checkout on the relay host:

1. Copy `deploy/relay/.env.example` to private `deploy/relay/.env`. Set the real hostname and ACME email.
2. Generate a canonical random 256-bit administration key, for example `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`, and put it in that private file. Restrict file permissions and never commit it, paste `docker compose config` output publicly, or put the key in URLs.
3. Point the hostname's DNS at that host, then start the supplied stack:

```sh
docker compose --env-file deploy/relay/.env -f deploy/relay/compose.yaml up --build -d
```

Caddy obtains/renews the public HTTPS certificate. Only Caddy publishes ports; the Python broker and persistent SQLite volume remain on the private container network. The broker trusts only Caddy's fixed private address for forwarded scheme information. Request/access logging is disabled to avoid leaking capability metadata. Check `https://YOUR-RELAY-DOMAIN/health` for `{"status":"ok","protocol":1}`. An open TCP healthcheck alone is not public HTTPS acceptance.

Run one broker process per database. Exclusive database locking rejects an independent second worker; live socket rendezvous is not a multi-worker service. Back up its persistent volume and administration key, maintain host/container security updates, monitor availability, and keep its origin stable. SQLite holds hashed random credentials and encrypted envelopes, not decrypted agent traffic or Windows authority keys.

For non-container deployments, install `relay/requirements.txt`, set private `RDP_RELAY_ADMIN_KEY` and `RDP_RELAY_PUBLIC_ORIGIN`, and run `python -m relay` behind a correctly configured HTTPS reverse proxy. Use the supplied launcher/native WebSocket protocol: a generic `uvicorn relay.server:...` configuration does not provide the required hard socket teardown. Expose the plaintext listener only to the trusted proxy; never trust wildcard forwarded-header sources.

### Operator desktop and VM setup

1. Run the native desktop as the operator. Open **Relay settings**, enter the HTTPS origin and administration key, and choose **Save & load routes**. Both settings are held in OS-protected storage.
2. Choose **Add machine**, enter its name and optional group, then **Create setup code**. A single pending installation is retained in OS-protected storage; close/reopen Add machine to resume it.
3. Choose **Copy installer link** and download the matching Preview 3 setup on the Windows VM. Run it, approve administrator elevation and the unsigned-preview notice, then paste the private setup code. Preview 2 installers do not understand the new setup-code format. Release installers require valid HTTPS; no remote HTTP or certificate bypass is available.
4. Monitoring-only is selected by default. The unsigned preview forces it and a viewer approval; signed production setup can enable administration only after explicit local consent.
5. The desktop polls for the encrypted VM approval, verifies its pinned identity, enrolls and probes ordinary mTLS automatically. **Do not copy another code back.** The setup completion page retains a manual recovery option for advanced use.

The VM gateway binds `127.0.0.1:8443`; the constrained gateway connects outward using HTTPS/WSS. Neither a public VM address, management port forwarding nor a VPN is required. Existing Windows/RDP firewall protection is not relaxed. Each Windows VM needs its own installation and persistent identity; copying DPAPI state to another VM is not enrollment. Linux agents and hypervisor provisioning/power-on are not implemented.

Keep setup and manual connection codes private; they are copy/paste URIs, not browser links or globally resolvable six-digit PINs. A setup URI carries two independent canonical 256-bit capabilities in its fragment: the one-use relay installation token and a desktop-generated pairing key. The VM sends only the installation token during registration, then publishes the existing AES-GCM envelope using the independent key. Desktop lookup sends only SHA256(key); the broker cannot decrypt/replace the identity or authorize Windows operations. The separate installer download link contains no capability and can be opened normally in a browser.

Reopen the same installer and choose **Pair installed agent** to generate a new connection code; no consumed installation invitation is reused. **Repair the same release** preserves the machine identity, enrolled devices, routing, data and deployment mode. Version/trust changes use the signed update lifecycle, not an unsigned repair path. A failed post-install helper displays recovery instructions and setup exit code `42`, rather than claiming a completed connection; the protected runtime remains available for repair.

Normal installation invitations last 15 minutes. Waiting is serialized at three-second intervals and stops after the installation window plus at most five minutes for a VM that already registered. Closing the waiting dialog keeps its intent/key in protected storage; discard explicitly removes only that local pending state, not a remote invitation, route or certificate. Enrollment is not silently replayed after an ambiguous one-use POST. Once a device identity is received, both normal setup and advanced recovery checkpoint it before the final mTLS probe; retry verifies/saves that identity instead of issuing another certificate. Enrollment response bodies are bounded to 128 KiB and a 30-second read deadline.

Use a fresh disposable VM for this unsigned evaluation payload. **Repair means the same published release**, not an unsigned cross-preview/version upgrade or trust migration. Existing installed agents can still generate a fresh manual code through Pair installed agent.


The private exchange directory is `%ProgramData%\RDPMonitor\setup\<random-session>`. It is protected before any invitation/result is written, and cleaned when setup exits. No invitation, connection code or routing token is placed in process arguments. Worker state remains SYSTEM/Administrators-only; the gateway receives noninheriting root descriptor/traverse rights plus read access to its own TLS/routing inputs, not the worker database or CA key.

Use **Devices & access** to revoke a lost Windows device certificate. **Relay settings → Revoke route** instead permanently disconnects that installation's transport credentials/grants; it does not uninstall the agent or revoke its Windows device certificates. Identity tombstones prevent takeover/re-registration of that same agent ID. Do not revoke a route as a temporary pause. There is no automatic identity reset or cross-relay migration.

The default single-broker bounds are 256 retained agent identities (including revocation tombstones), 128 live installation invitations, 32 grants and 32 unexpired envelopes per route, 16 streams per route and 256 total streams. Pending grants expire after ten minutes; the first admitted connection activates a grant until revocation. Pairing envelopes expire independently. Closing sockets remain in quota accounting until actual transport teardown; stalled output is forcibly aborted after two seconds. Expired records are cleaned without replaying application requests.

### Machine inventory and command layout

The Machines table groups profiles and supports name/group search, connection-state filters, expiry-due and renewal-due filters. Disk values come from authenticated agent snapshots; retained measurements are labeled stale, and missing values are not replaced by zero. Hover the disk cell for all reported volumes and the measurement time. Scroll each table horizontally when the sidebar or window leaves insufficient room.

**Edit profile and contract** controls the display name/group, optional contract expiry/renewal dates, cost estimate, three-letter currency and monthly/yearly/one-time period. Decimal input is stored as integer hundredths, not floating point. The date-only action edits billing reminders, not device credentials. Metadata remains local in OS-protected storage and survives certificate renewal. Direct HTTPS address editing is under Connection; relay identities remain read-only. Unloaded/unreadable secure profiles cannot be overwritten by fleet mutations.

Backups and Recovery are separate navigation destinations, as are Processes and Services. Commands are grouped by related task, searchable and still governed by agent capabilities/confirmation. Card columns use actual available logical content width (including text scaling), not just monitor width. The wide sidebar can be hidden/reopened; below the desktop breakpoint the same destinations live in a scrollable drawer.


### Local relay development

For isolated development only, `python -m relay --allow-loopback-http --public-origin http://127.0.0.1:8765` admits a numeric-loopback HTTP origin/listener. The source gateway requires explicit `--allow-loopback-relay`, and only debug Flutter builds accept this transport. Inner agent HTTPS/mTLS remains real. Release clients/installers reject this exception, and no mode disables remote certificate validation.


## Advanced direct or loopback installation

Keep provider/physical console access available for the first deployment. Test on a disposable VM before a production RDP-only machine. Extract the authenticated release and run its signed installer from an elevated PowerShell terminal:

```powershell
.\scripts\install_suite.ps1 -Package (Get-Location).Path `
  -PublisherThumbprint $TrustedPublisherThumbprint
```

Default scope is loopback (`127.0.0.1:8443`); it opens no remote management ingress. Immutable code/runtime live under `%ProgramFiles%\RDPMonitor\releases\<version>`. Mutable identity, encrypted secrets, configuration, jobs and telemetry live under `%ProgramData%\RDPMonitor`. The installer protects code from ordinary-user modification and constrains gateway access rather than granting it worker secrets.

For explicitly enabled private/VPN access, select the actual private interface, listener address and approved source ranges:

```powershell
.\scripts\install_suite.ps1 -Package (Get-Location).Path `
  -PublisherThumbprint $TrustedPublisherThumbprint `
  -Scope Private -ListenAddress '100.80.0.10' `
  -RemoteAddress @('100.80.0.11/32') -InterfaceAlias @('Tailscale')
```

Replace these example addresses with your own deployment. Public/Any source scopes are rejected. The administration firewall rule is constrained by program, interface, local address, approved sources and Private/Domain profile. Do not expose it through unrestricted port forwarding.

The Start Menu shortcut targets the active client release. A machine-wide sign-in entry starts the hidden session helper as each signed-in user, independently of the client. It does not run as SYSTEM or silently substitute another user's desktop. Sessions must be interactive and unlocked for actions that need a desktop. Source users can run `python -m agent session-helper` in their own session. A newly installed helper's automatic startup occurs at the next sign-in.

## Enrollment and certificate names

In an elevated terminal on the agent machine:

```powershell
$deployment = Get-Content "$env:ProgramData\RDPMonitor\deployment.json" -Raw | ConvertFrom-Json
$agent = Join-Path $deployment.release 'agent\RDPMonitorAgent.exe'
& $agent pair --role owner
```

Open **RDPMonitor** from the Start Menu as a normal user. For this direct method choose **Advanced: direct HTTPS** from the connection menu and enter the endpoint, one-use pairing code and exact SHA256 server fingerprint printed locally. Compare the fingerprint over a trusted channel. Client private keys stay in OS-protected storage. Enrollment role is approved locally, never chosen by a remote enrollment request.

For DNS/private endpoint changes, approve the complete desired SAN set locally before pairing:

```powershell
& $agent certificate-hosts --host 'server.example.internal' --host '100.80.0.10'
Stop-Service RDPMonitorGateway
Stop-Service RDPMonitorWorker
Start-Service RDPMonitorWorker
Start-Service RDPMonitorGateway
```

This changes the server certificate/fingerprint. Restart both services in the order shown so the listener loads it; source `serve` users must restart their integrated process instead. Then issue a fresh pairing approval and verify the new fingerprint before enrollment. Never disable TLS verification to work around a mismatch. The worker includes its configured listener and stable `<agent-id>.rdpmonitor.invalid` tunnel name while retaining the locally approved direct SAN set; the synthetic tunnel name does not require DNS resolution.

Use **Devices & access** to inspect/revoke enrolled devices. Revocation is checked for current requests and job admission; losing network connectivity is not revocation or cancellation.

## Client startup and notification area

The Windows client's **Desktop** menu is available before enrollment. It controls start at Windows sign-in, optional close-to-notification-area, explicit hide and exit. Closing exits by default; hiding is opt-in. The notification-area menu restores the window or exits only the client. Startup is per-user and unelevated; it does not enable/disable protection or backup schedules.

Local notifications require an active client. Persisted events remain available after reconnect. Mobile push requires protected provider credentials and a correctly provisioned app/token; it is best effort, not a guaranteed machine-down alarm. Use an independent external observer when outage alerts are required.

## Migrating an existing installation

Do not copy legacy DPAPI values to a new Windows account or machine and expect decryption. Run migration elevated as the same original Windows account that protected the old secrets. Preserve an off-host copy of the legacy tree and recovery material first.

```powershell
.\scripts\install_suite.ps1 -Package (Get-Location).Path `
  -PublisherThumbprint $TrustedPublisherThumbprint `
  -MigrateFrom 'C:\ExistingRDPMonitor' -OriginalAccount 'DOMAIN\original-user'
```

Migration tooling stops the old execution owners, validates/copies retained state under a recovery manifest and decrypts/reprotects secrets in the new storage context. It must not call legacy uninstall/cleanup routines that remove active RDP protection rules. Review migration errors and the manifest before deleting anything from the original installation. Keep backup archives/repositories and portable recovery keys off-host; DPAPI is not portable recovery material.

## Update and rollback

Use the updater from the installed protected release, not executable code in the incoming untrusted package. Supply a locally downloaded, authenticated release directory:

```powershell
& $agent update --package 'C:\Releases\RDPMonitor-next' --verify-only
& $agent update --package 'C:\Releases\RDPMonitor-next'
```

The updater checks publisher signature, every inventory hash, monotonic version and API/schema compatibility before activation. It stops gateway then worker, snapshots complete state under `%ProgramData%\RDPMonitorRecovery\<update-id>`, activates the protected release, updates entrypoints/firewall program identity, and requires local worker/gateway health before committing. It restores matching code **and** state on recoverable failure; uncertain state leaves services stopped rather than starting old code against a potentially incompatible database.

Manual rollback is limited to the exact current committed update and its verified snapshot:

```powershell
& $agent rollback --update-id $ExactUpdateId --confirm-rollback 'RESTORE CODE AND STATE'
```

Rollback restores configuration, history, identities and revocations to snapshot time, not just binaries. Review devices/revocations and every administrative change since that snapshot. Old/new release activation refreshes both the Start Menu shortcut and session-helper startup path. Already running user processes do not become a new version automatically; exit/reopen the client and sign out/in to refresh session helpers.

## Repair and removal

```powershell
& $agent repair
& $agent remove
```

Repair revalidates installed release integrity, reapplies protected-directory ACLs, repairs service registration/user entrypoints and waits for health. Removal stops/deletes services and removes the shortcut/helper startup entry; firewall protection policy, backup repositories, data and protected recovery material are preserved by default. Close the client before removal; locked release files can require a reboot to finish removal. Disable per-user client startup in the Desktop settings before removing the installation.

Data deletion is separate and explicit:

```powershell
& $agent remove --delete-data --confirm-data-deletion 'DELETE RDPMonitor DATA'
```

Deleting agent data is not a request to delete backup repositories or relax active Windows firewall policy. Retain console access and inspect the resulting policy yourself.

## Verification and release gates

Current automated checks and local smoke scenarios do not replace deployment acceptance. Run these checks on disposable machines/devices with console access and nonproduction backup targets:

| Gate | Required observation |
|---|---|
| Service lifetime | Reboot without login; fresh monitoring, configured protection and a due backup continue; client close/logoff does not stop worker jobs |
| Least privilege | Ordinary user cannot alter executable/runtime, scripts or privileged state; constrained gateway cannot read worker secrets |
| Enrollment | Wrong fingerprint/name, reused/expired code, viewer denial, revoked/expired certificate and renewal behavior |
| Policy safety | Allow-list, panic, port change, last-admin/session safeguards and recovery using provider console |
| Backup/recovery | Real ZIP/restic/VSS; missing/unreadable sources, partial cloud delivery, disk-full; independent content verification and off-host restore using recovery material |
| Sessions | Unlocked/locked/disconnected/multiple-user behavior; correct execution identity; no SYSTEM desktop fallback |
| Updates | Signed fresh install, migration under original account, update failure, exact-state rollback, repair and removal preserving data/policy |
| Desktop | Actual installed UI, keyboard/accessibility, offline/reconnect, confirmations, artifact transfer, startup and notification-area behavior |
| Relay | Public Caddy HTTPS/WSS, no VM ingress, offline/reconnect and bounded slow-reader cleanup, expiry/reuse, misrouting, real transfer and live device/route revocation |
| Native setup | Fresh VM invitation/code completion, rejected/expired invitation, failure exit `42`, same-release repair/pairing, uninstall preserving policy/data and signed production publisher acceptance |
| Imaging | Real complete image file set, interruption/recovery, and actual VM boot where supported; file creation alone is insufficient |
| Mobile | macOS/Xcode/iOS provisioning, production Android signing, real-device lifecycle/network changes, token registration and provider delivery |

Do not mark the release production-ready until these observations are attached. Publisher signing credentials, private cloud/provider credentials, a disposable VM/provider console, and real mobile provisioning/devices are external prerequisites, not simulated by tests.
