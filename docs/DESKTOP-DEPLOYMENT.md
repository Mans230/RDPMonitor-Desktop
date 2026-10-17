# Desktop deployment, migration and recovery

## Deployment status

The Windows native client, frozen agent and native installer can be built locally. Production installation requires a valid publisher code-signing certificate/private key, an HTTPS timestamp service and an authenticated release. A distinct, explicitly consented unsigned preview installer forces monitoring-only services and viewer enrollment. It never falls back from failed production verification; neither preview packaging nor local smoke establishes production readiness.

Run the client as the signed-in user. The agent's privileged worker and constrained gateway are separate Windows services. Closing or exiting the client does not stop monitoring, protection, accepted jobs or backup scheduling. Stopping/removing the services is a different administrative action.

## Build prerequisites

- Windows x64; Python 3.14 with the pinned `requirements.txt` environment.
- Flutter with Dart **3.13.0 or newer within 3.x** and the committed `clients/app/pubspec.lock`, for desktop builds only. Guest-only packaging does not invoke Flutter.
- Visual Studio 2022 C++ build tools, Windows SDK and ATL for the native desktop; a short checkout path avoids native build path limits.
- Windows SDK `signtool.exe` and a valid RSA code-signing certificate in the current user's certificate store, including the code-signing EKU and private key.
- The matching licensed x64 `Microsoft.VC143.CRT` release redistributable directory and official Microsoft redistribution notice. The build copies these DLLs beside the client; do not use `debug_nonredist`.
- External backup/imaging tools are separate dependencies. Configure approved HTTPS download URLs and independently verified SHA256 digests in the agent tooling operations. Missing tools must produce actionable errors, not silent fallback. Retain each redistributed tool's license and distribution conditions; Disk2vhd licensing is separate.

Build the guest first, then pin the final signed native guest executable into the desktop build. Set the publisher, timestamp and licensed runtime inputs below from your actual toolchain:

```powershell
$build = @{
  Version = '1.0.1'; BuildNumber = 6
  CertificateThumbprint = $PublisherThumbprint
  TimestampUrl = $TimestampServiceHttpsUrl
  VCRuntimeDirectory = $LicensedX64CrtDirectory
  VCRedistributionNoticeFile = $MicrosoftRedistributionNotice
  Python = '.\.venv\Scripts\python.exe'
}
.\scripts\build-release.ps1 @build -GuestOnly -Output '.\dist\guest'
.\scripts\build-installer.ps1 -GuestOnly `
  -Package '.\dist\guest\RDPMonitorGuest-1.0.1-windows-x64' `
  -CertificateThumbprint $PublisherThumbprint -TimestampUrl $TimestampServiceHttpsUrl `
  -Output '.\dist\guest\native'
$GuestInstaller = '.\dist\guest\native\RDPMonitorGuest-1.0.1-windows-x64-setup.exe'
$GuestSetupSha256 = (Get-FileHash $GuestInstaller -Algorithm SHA256).Hash
# Publish these exact bytes, then set GuestSetupHttpsUrl to their immutable HTTPS URL.
.\scripts\build-release.ps1 @build -Output '.\dist\desktop' `
  -GuestSetupUrl $GuestSetupHttpsUrl -GuestSetupSha256 $GuestSetupSha256 `
  -GuestSetupMode production -GuestPublisherThumbprint $PublisherThumbprint -GuestSetupProtocol 2
```

The guest bundles the frozen Python agent/runtime, lifecycle scripts and dependency/Microsoft notices, but no `client` directory or desktop shortcut. Its signed inventory declares `component: guest`; the desktop suite declares `component: suite`. Component changes are rejected during install, repair, signed update and rollback. Guest and suite are not co-installed on one Windows installation.

Production builds sign PE files and PowerShell scripts, verify signatures and write a signed file-inventory manifest plus ZIP/SHA256. The final native guest setup/uninstaller is signed separately before its executable digest is pinned. Production desktop builds require explicit production guest trust inputs; a missing/invalid override never falls back to an unsigned preview. Authenticate the publisher independently: a ZIP checksum alongside an untrusted ZIP is not publisher authentication.

For a Build Tools installation, the CRT directory is typically `VC\Redist\MSVC\<version>\x64\Microsoft.VC143.CRT` beneath its installation root; the redistribution notice is under `Licenses\1033\Redist.txt`. Authenticate and retain the toolchain's redistribution terms. End users do not need Visual Studio, Python or Flutter to run the packaged client/runtime.

Build the optional advanced suite wizard around the complete authenticated desktop package:

```powershell
.\scripts\build-installer.ps1 -AcquireCompiler
.\scripts\build-installer.ps1 -Package '.\dist\desktop\RDPMonitor-1.0.1-windows-x64' `
  -CertificateThumbprint $PublisherThumbprint -TimestampUrl $TimestampServiceHttpsUrl
```

Compiler acquisition is separate from application installation. It checks the immutable official Inno Setup 7.1.0 asset SHA256 and its Windows Authenticode chain/current official publisher before executing the tool installer. Production setup and its embedded uninstaller are signed; no self-signed publisher or automatic unsigned fallback is created. Retain Inno's embedded notices and review its current commercial-use guidance for your organization.

For an explicitly unsigned evaluation build, use the separate parameter set and the same guest-first order:

```powershell
$preview = @{
  UnsignedPreview = $true; Version = '1.0.1'; BuildNumber = 6
  VCRuntimeDirectory = $LicensedX64CrtDirectory
  VCRedistributionNoticeFile = $MicrosoftRedistributionNotice
  Python = '.\.venv\Scripts\python.exe'
}
.\scripts\build-release.ps1 @preview -GuestOnly -Output '.\dist\preview-guest'
.\scripts\build-installer.ps1 -GuestOnly -UnsignedPreview `
  -Package '.\dist\preview-guest\RDPMonitorGuest-1.0.1-windows-x64-UNSIGNED-PREVIEW' `
  -Output '.\dist\preview-guest\native'
$GuestInstaller = '.\dist\preview-guest\native\RDPMonitorGuest-1.0.1-windows-x64-UNSIGNED-PREVIEW-setup.exe'
$GuestSetupSha256 = (Get-FileHash $GuestInstaller -Algorithm SHA256).Hash
# Publish these exact bytes and set GuestSetupHttpsUrl before building their desktop.
.\scripts\build-release.ps1 @preview -Output '.\dist\preview-desktop' `
  -GuestSetupUrl $GuestSetupHttpsUrl -GuestSetupSha256 $GuestSetupSha256 `
  -GuestSetupMode unsigned-preview -GuestSetupProtocol 2
```

Preview 6 desktop defaults pin the unchanged official **Preview 5 guest** asset and secure direct setup protocol **2**. Rebuilt installers need not be byte-identical: publish your own exact guest bytes under an immutable HTTPS URL and override URL/digest/mode/protocol together. A protocol-1 guest cannot provision direct setup, so command copying fails closed rather than downloading the old relay-only guest. Download URLs must contain no credentials, query, fragment or CMD metacharacters. Commands above CMD's 8191-character limit fail explicitly.

Unsigned checksums establish integrity, not publisher authenticity. Preview setup requires explicit evaluation consent and cannot enable administration, protection or schedules; use a disposable Windows VM first. The source agent CLI is separate from installed preview policy: source evaluation must explicitly use `--read-only`.

## Install a VM with one CMD command

### Direct setup — normal Add machine

1. Run the native desktop on the watcher PC. Choose **Add machine**, enter name, optional group and the VM's reachable IP/hostname. HTTPS defaults to TCP **8443**; an explicit port from 1024–65535 is supported.
2. Normally leave source selection automatic: the VM must have exactly one established non-loopback TCP peer on its configured RDP listener. RDP gateways, browser/provider consoles, multiple peers or another watcher PC require **Advanced: desktop source IP**, with the watcher's single literal address. IPv6-only VMs need an IPv6 literal endpoint; DNS endpoints use an IPv4 listener.
3. Choose **Prepare command**, explicitly accept the unsigned monitoring-only notice when applicable, then **Copy CMD command**. The same intent, two separate private keys and 30-minute deadline are retained in protected desktop storage.
4. Paste the one line into an existing **Administrator Command Prompt** inside the fresh Windows VM. No wizard, pairing-code entry, app on the guest or return code. The bootstrap downloads/verifies the pinned guest-only executable and silently installs the worker/gateway services.
5. Leave Add machine open. The VM locally creates its own CA and preissues one viewer certificate to the desktop's CSR. The desktop verifies the prepared VM transport key and public bundle, proves ordinary CA/hostname-verified mTLS against a protected endpoint, saves the machine, then retires bootstrap publication using that exact certificate.

**Reachability is required, not manufactured.** The VM binds its chosen HTTPS port and adds a Windows rule limited to the guest executable, TCP port and one detected/explicit source. Firewall service/profiles must be enabled with effective default inbound Block and permit the owned local rule; setup does not rewrite unrelated policy. Other existing allow rules can broaden network access, so certificate authentication remains essential. Permit the same source/port in provider security groups/router forwarding as needed. This installer has no provider credentials and cannot open those controls. A changing desktop public IP requires separately authorized source maintenance; it never expands to Any automatically.

The command contains the initial VM transport private key, public desktop CSR and random bootstrap nonce, **not** the desktop client private key or VM CA key. Protect clipboard/history and never pass it as `cmd /c` arguments. Private values travel through environment and an administrator/SYSTEM-protected native exchange, never download URLs or helper arguments. Both signed and unsigned direct CMD installation force viewer/read-only. IP/nonce/public-certificate knowledge cannot authenticate another desktop, and no pairing window is opened.

Close/reopen Add machine to resume its protected waiting/issued/saved state. A failed protected probe reuses the issued certificate. A storage write that committed before reporting failure is reconciled into the live fleet on retry, preserving saved display/contract metadata and one identity. A saved profile with failed acknowledgement remains usable and can finish acknowledgement after the setup deadline. Discard removes only local pending state; it does not revoke a remote device or uninstall an agent.

The command is **fresh-install-only**. Retained/partial identity, services or deployment state are not replaced. If a VM was installed but its unclaimed bootstrap expired, use the matching native guest installer's **Pair installed agent**, then the desktop's **Pair installed agent (direct HTTPS)** and locally verified endpoint/fingerprint/code. This is explicit local recovery, not another fresh command. Same-release repair preserves identity and direct scope; repair is not a cross-preview upgrade. Keep provider console access for first installation.

### Optional relay — one-time deployment

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

### Optional relay — operator desktop and VM setup

1. Open **Relay settings**, enter the supplied relay's HTTPS origin and administration key, then **Save & load routes**. Both settings are held in OS-protected storage.
2. Choose **Install through relay (advanced)** from the connection menu, enter name/group and create its installation command. Its separate protected pending intent resumes by reopening that advanced flow.
3. Approve the unsigned evaluation notice when applicable, then **Copy CMD command**. Paste into Administrator CMD inside the fresh VM.
4. The bundled public bootstrap downloads the native **guest-only** installer over validated HTTPS into a unique administrator/SYSTEM-protected cache, checks the app-pinned SHA256 and production Authenticode publisher when applicable, then installs silently. No VM wizard, separate setup-code entry or desktop app on the guest is needed. No downloaded script is executed.
5. The desktop polls for encrypted VM approval, verifies its pinned identity, enrolls and probes ordinary mTLS automatically. **Do not copy another code back.** Normal CMD provisioning always forces monitoring-only/viewer, even in signed builds. Administrative access remains an advanced signed interactive flow requiring separate affirmative local consent.

The VM gateway binds `127.0.0.1:8443`; the constrained gateway connects outward using HTTPS/WSS. Neither a public VM address, management port forwarding nor a VPN is required. Existing Windows/RDP firewall protection is not relaxed. Each Windows VM needs its own installation and persistent identity; copying DPAPI state to another VM is not enrollment. Linux agents and hypervisor provisioning/power-on are not implemented.

**Treat the copied command like a password.** It carries a base64url-encoded setup URI in an environment value; encoding is not encryption. The URI contains independent one-use relay registration and desktop pairing capabilities. Only the installation token reaches the broker; the VM publishes an AES-GCM envelope under the independent key and desktop lookup sends only SHA256(key). Never navigate to it in a browser, share it, or put the entire private line in `cmd /c` process arguments. Clipboard and interactive CMD history can retain it.

Only trusted public bootstrap code appears in PowerShell arguments. Native setup consumes the private environment value into `%ProgramData%\RDPMonitor\setup\<random-session>` before staging files, clears the parent environment before later helpers, and cleans its protected exchange on exit. The CMD caller clears all generated environment values on either branch. CMD returns `0` on success and `1` on failure; when native setup reports a failure, its exact exit code is printed. There is no certificate bypass, downloaded mutable script or production-to-preview fallback.

The command is for **fresh provisioning**, not repair: retained identity/deployment/relay state or registered services cause rejection rather than silently replacing an existing machine. For advanced recovery, reopen the matching native guest installer and choose **Pair installed agent** or **Repair the same release**. Pairing generates a fresh private manual connection code without reusing a consumed invitation; same-release repair preserves identity, enrolled devices, routing, data and deployment mode. Version/trust/component changes are not an unsigned repair path. A failed post-install helper returns native setup code `42` instead of claiming a completed connection; use the retained protected runtime for recovery.

Relay installation invitations last 15 minutes. Waiting is serialized at three-second intervals and stops after the invitation window plus at most five minutes for an already registered VM. Closing the advanced relay dialog retains its protected intent; discard removes only that local state. Ambiguous one-use enrollment is not silently replayed. Issued manual/relay identities are checkpointed before final mTLS probing; bounded response bodies and deadlines prevent indefinite busy enrollment. Direct setup uses its separate 30-minute preissued-key protocol described above.

Use a fresh disposable VM for this unsigned evaluation payload. **Repair means the same published release**, not an unsigned cross-preview/version upgrade or trust migration. Existing installed agents can still generate a fresh manual code through Pair installed agent.


The private exchange directory is protected before any invitation/result is written, and cleaned when setup exits. No invitation, connection code or routing token is placed in PowerShell/native installer process arguments; the pasted CMD line itself remains private history. Worker state remains SYSTEM/Administrators-only; the gateway receives noninheriting root descriptor/traverse rights plus read access to its own TLS/routing inputs, not the worker database or CA key.

Use **Devices & access** to revoke a lost Windows device certificate. **Relay settings → Revoke route** instead permanently disconnects that installation's transport credentials/grants; it does not uninstall the agent or revoke its Windows device certificates. Identity tombstones prevent takeover/re-registration of that same agent ID. Do not revoke a route as a temporary pause. There is no automatic identity reset or cross-relay migration.

The default single-broker bounds are 256 retained agent identities (including revocation tombstones), 128 live installation invitations, 32 grants and 32 unexpired envelopes per route, 16 streams per route and 256 total streams. Pending grants expire after ten minutes; the first admitted connection activates a grant until revocation. Pairing envelopes expire independently. Closing sockets remain in quota accounting until actual transport teardown; stalled output is forcibly aborted after two seconds. Expired records are cleaned without replaying application requests.

### Machine inventory and command layout

The Machines table groups profiles and supports name/group/address/role search, connection-state filters, expiry-due and renewal-due filters. Fleet summary counts and contact times use the loaded agent state. Disk values come from authenticated snapshots; retained measurements are labeled stale, and missing values are not replaced by zero. Hover the disk cell for all reported volumes and measurement time. Rich tables scroll internally where needed and become labelled stacked records below an accessibility-adjusted 560 logical pixels of available content width.

**Edit profile and contract** controls the display name/group, optional contract expiry/renewal dates, cost estimate, three-letter currency and monthly/yearly/one-time period. Decimal input is stored as integer hundredths, not floating point. The date-only action edits billing reminders, not device credentials. Metadata remains local in OS-protected storage and survives certificate renewal. Direct HTTPS address editing is under Connection; relay identities remain read-only. Unloaded/unreadable secure profiles cannot be overwritten by fleet mutations.

**Backups & recovery** contains separate Backups and Recovery tabs; **Processes & services** likewise retains both sets of tools. Searchable command groups use compact bordered rows, capability tags and explicit confirmation/read-only indicators. The agent remains the authority for every operation. **Run operation** opens a searchable picker for the selected machine rather than running a default command.

At 1100 logical pixels and above, navigation uses the full labelled sidebar. From 560 to 1099 it uses an icon rail; below 560 it becomes a scrollable drawer. Hide/show remains available on desktop. Phone dialogs occupy the available height, scroll their content and stack full-width actions. Dialogs remain usable while resizing across these breakpoints.

**Pause telemetry** stops automatic client polling, not the Windows agent, its schedules, notifications or jobs. Already active requests can finish, explicit refresh still works, and Resume triggers a fresh read. Contact and sample timestamps continue aging; paused or retained values are not a current health guarantee.



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

Open **RDPMonitor** from the Start Menu as a normal user. Choose **Pair installed agent (direct HTTPS)** from the connection menu and enter the endpoint, one-use pairing code and exact SHA256 server fingerprint printed locally. Compare the fingerprint over a trusted channel. Client private keys stay in OS-protected storage. Enrollment role is approved locally, never chosen by a remote enrollment request. Installed direct CMD monitoring policy remains viewer/read-only; manual recovery does not promote it to administration.

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
| Native setup | One Administrator CMD line on a fresh VM; guest-only payload/no wizard; valid download/publisher/hash; automatic monitoring-only enrollment; expired/malformed/retained identity rejection; failure exit `42`; same-release repair/pairing; uninstall preserving policy/data; signed production publisher acceptance |
| Imaging | Real complete image file set, interruption/recovery, and actual VM boot where supported; file creation alone is insufficient |
| Mobile | macOS/Xcode/iOS provisioning, production Android signing, real-device lifecycle/network changes, token registration and provider delivery |

Do not mark the release production-ready until these observations are attached. Publisher signing credentials, private cloud/provider credentials, a disposable VM/provider console, and real mobile provisioning/devices are external prerequisites, not simulated by tests.
