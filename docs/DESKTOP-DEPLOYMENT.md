# Desktop deployment, migration and recovery

## Deployment status

The Windows native client and frozen agent can be built locally. Local development builds are not authenticated production releases. Production installation requires a valid publisher code-signing certificate with its private key, an HTTPS timestamp service, and a release produced by `scripts/build-release.ps1`. Never bypass signature checks to install an unsigned development build.

Run the client as the signed-in user. The agent's privileged worker and constrained gateway are separate Windows services. Closing or exiting the client does not stop monitoring, protection, accepted jobs or backup scheduling. Stopping/removing the services is a different administrative action.

## Build prerequisites

- Windows x64; Python 3.14 with the pinned `requirements.txt` environment.
- Flutter stable/Dart 3.13 and the committed `clients/app/pubspec.lock`.
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

## Fresh installation

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

Open **RDPMonitor** from the Start Menu as a normal user. Choose **Enroll machine** and enter the HTTPS endpoint, one-use pairing code and exact SHA256 server fingerprint printed locally. Compare the fingerprint over a trusted channel. Client private keys are generated on the client and stored in OS-protected storage. Enrollment role is approved locally, not chosen by the remote device.

For DNS/private endpoint changes, approve the complete desired SAN set locally before pairing:

```powershell
& $agent certificate-hosts --host 'server.example.internal' --host '100.80.0.10'
Stop-Service RDPMonitorGateway
Stop-Service RDPMonitorWorker
Start-Service RDPMonitorWorker
Start-Service RDPMonitorGateway
```

This changes the server certificate/fingerprint. Restart both services in the order shown so the listener loads it; source `serve` users must restart their integrated process instead. Then issue a fresh pairing approval and verify the new fingerprint before enrollment. Never disable TLS verification to work around an endpoint/name mismatch. The installed worker includes its configured listener address when preparing its certificate.

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
| Imaging | Real complete image file set, interruption/recovery, and actual VM boot where supported; file creation alone is insufficient |
| Mobile | macOS/Xcode/iOS provisioning, production Android signing, real-device lifecycle/network changes, token registration and provider delivery |

Do not mark the release production-ready until these observations are attached. Publisher signing credentials, private cloud/provider credentials, a disposable VM/provider console, and real mobile provisioning/devices are external prerequisites, not simulated by tests.
