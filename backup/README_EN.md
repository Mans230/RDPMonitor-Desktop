# RDPMonitor backup engines

This folder contains the shared ZIP, restic, rclone, restore and scheduling engines in `app/`. They are imported by `agent/backup.py`; this is not a standalone desktop application or independently installed daemon. Do not create a separate backup scheduled task. There is no browser panel or Telegram setup requirement.

## Run from source

From the repository root on Windows, create the Python 3.14 environment and install the root requirements:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

For read-only evaluation, start the integrated development agent in an elevated terminal:

```powershell
.venv\Scripts\python -m agent serve --read-only --data-dir "$env:LOCALAPPDATA\RDPMonitorEvaluation" --port 9443
```

In a second elevated terminal, approve enrollment:

```powershell
.venv\Scripts\python -m agent pair --data-dir "$env:LOCALAPPDATA\RDPMonitorEvaluation" --role owner
```

Build/run the [native Flutter client](../clients/app/README.md), then enroll `https://127.0.0.1:9443` using the locally verified fingerprint and one-use code. Read-only mode exposes actual status but does not run backup schedules or administration mutations. To exercise real backup work, omit `--read-only` only on an isolated machine with nonproduction sources and backup destinations.

Use the native **Backup/recovery** operations to inspect status, submit runs, review results, configure destinations and request restore/recovery actions. Typed backup settings live under **Settings** with revision checks and explicit secret replacement/clearing. Long-running work is tracked in **Activity**; disconnection does not cancel an accepted job, and cancellation is not rollback. Do not blindly retry an uncertain mutation.

## Resident deployment and data

Production deployment uses the signed suite installer and separate boot-time worker/gateway services described in [deployment, migration and recovery](../docs/DESKTOP-DEPLOYMENT.md). The privileged worker, not the client window or a backup GUI, owns schedules and VSS-capable execution. Closing the client must not be used to stop schedules. Interactive desktop actions belong to the signed-in user helper, not a SYSTEM desktop.

The adapter relocates backup configuration, logs, repositories/control files and tool state beneath the selected agent data directory's `backup` subtree (normally `%ProgramData%\RDPMonitor\backup`). Configuration and secrets are protected in the worker context; never commit runtime configuration, cloud credentials, archive/repository passwords or recovery exports. Legacy migration must decrypt user-scoped secrets under the original Windows account before reprotecting them. Do not merely copy an old encrypted configuration to a different host/account.

Restic, rclone and imaging tools are external dependencies with their own licenses. Configure approved HTTPS tool sources and independently verified SHA256 digests through agent tooling operations; missing tools are not silently replaced. Back up portable passwords/keys independently off-host: Windows DPAPI is not a portable recovery key. Verify recovered file contents on a separate machine rather than treating archive creation or cloud upload as restore evidence.

## Prerelease limits

The unsigned Windows ZIP is an evaluation prerelease, not a signed production installer. Do not bypass installer signature checks. Production acceptance still requires publisher signing; installed SCM/least-privilege isolation and reboot-without-login/logoff scheduling; destructive policy/account/power safety with console recovery; signed migration/update/rollback; real ZIP/restic/VSS failure and off-host restore scenarios; actual image boot; and clean-machine visual/accessibility checks. See the deployment guide's release-gate table.

Mobile platform sources are not release-ready. Native Flutter push-token acquisition/registration is not implemented, and provider credentials alone do not enable mobile background delivery. Production mobile signing, provisioning, lifecycle and push-provider delivery need implementation/real-device acceptance.

## License and upstream

Derived from [Mans230/RDPMonitor](https://github.com/Mans230/RDPMonitor), under the [MIT license](../LICENSE). Preserve upstream copyright and dependency/external-tool notices; the project license does not replace external-tool or cloud-provider terms.
