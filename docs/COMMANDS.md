# Native operation reference

These operations are executed by the Windows agent and exposed through native desktop forms. The authenticated `/api/v1/catalog` is the authoritative runtime contract. No slash-command parser or browser panel is required.

Permissions are enforced by the agent; a visible control is not authorization. Destructive operations require a fresh parameter-bound confirmation. Read-only agent mode refuses non-view operations. A listed operation can still be unavailable because a capability is disabled, a sensor/tool/session is absent, or Windows refuses access.

## accounts.create

Account capability is off by default. Disruptive changes refuse last enabled administrator and signed-in accounts. Passwords are never echoed.

- Screen group: accounts
- Capability: `accounts`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |
| `password` | secret | yes |  |
| `role` | choice | no | user, admin |

## accounts.delete

Account capability is off by default. Disruptive changes refuse last enabled administrator and signed-in accounts. Passwords are never echoed.

- Screen group: accounts
- Capability: `accounts`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## accounts.disable

Account capability is off by default. Disruptive changes refuse last enabled administrator and signed-in accounts. Passwords are never echoed.

- Screen group: accounts
- Capability: `accounts`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## accounts.enable

Account capability is off by default. Disruptive changes refuse last enabled administrator and signed-in accounts. Passwords are never echoed.

- Screen group: accounts
- Capability: `accounts`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## accounts.list

Read enabled state and administrator membership from Windows, without invented fallback state.

- Screen group: accounts
- Capability: `view`
- Explicit confirmation: not required

## accounts.password

Account capability is off by default. Disruptive changes refuse last enabled administrator and signed-in accounts. Passwords are never echoed.

- Screen group: accounts
- Capability: `accounts`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |
| `password` | secret | yes |  |

## accounts.rename

Account capability is off by default. Disruptive changes refuse last enabled administrator and signed-in accounts. Passwords are never echoed.

- Screen group: accounts
- Capability: `accounts`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |
| `new_name` | string | yes |  |

## activity.audit

Durable attributed outcomes recorded by the worker.

- Screen group: activity
- Capability: `manage`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `limit` | integer | no |  |

## activity.mute

Bounded mute leaves security/critical alerts deliverable.

- Screen group: activity
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `minutes` | integer | no |  |

## activity.test

Persist and deliver a real test event through the configured agent channel.

- Screen group: activity
- Capability: `operate`
- Explicit confirmation: not required

## automation.keepalive.list

Actual persisted automation configuration.

- Screen group: automation
- Capability: `view`
- Explicit confirmation: not required

## automation.keepalive.remove

Remove matching policy without launching or stopping the target.

- Screen group: automation
- Capability: `execute`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## automation.keepalive.set

Validated policy applied by the sole monitor; keepalive always requires execution capability even without a custom command.

- Screen group: automation
- Capability: `execute`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |
| `run` | string | yes |  |

## automation.svcwatch.list

Actual persisted automation configuration.

- Screen group: automation
- Capability: `view`
- Explicit confirmation: not required

## automation.svcwatch.remove

Remove matching policy without launching or stopping the target.

- Screen group: automation
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## automation.svcwatch.set

Validated policy applied by the sole monitor; keepalive always requires execution capability even without a custom command.

- Screen group: automation
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## automation.watch.list

Actual persisted automation configuration.

- Screen group: automation
- Capability: `view`
- Explicit confirmation: not required

## automation.watch.remove

Remove matching policy without launching or stopping the target.

- Screen group: automation
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## automation.watch.set

Validated policy applied by the sole monitor; keepalive always requires execution capability even without a custom command.

- Screen group: automation
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |
| `ram_mb` | integer | no |  |

## backup.archive.delete

Delete local archive

- Screen group: backups
- Capability: `backup`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `archive` | string | yes |  |

## backup.archive.download

Download backup archive

- Screen group: backups
- Capability: `files`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `archive` | string | yes |  |

## backup.archives

List ZIP archives and restic snapshots

- Screen group: backups
- Capability: `view`
- Explicit confirmation: not required

## backup.backup.set

Revision-checked settings update. Hooks are privileged shell commands executed under the worker identity; settings may change retention and future scheduled actions.

- Screen group: backups
- Capability: `execute`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `engine` | choice | no | zip, restic |
| `sources` | string | no |  |
| `exclude_extensions` | string | no |  |
| `exclude_patterns` | string | no |  |
| `exclude_max_size_mb` | integer | no |  |
| `keep_local_copies` | integer | no |  |
| `use_vss` | boolean | no |  |
| `verify` | boolean | no |  |
| `require_all_sources` | boolean | no |  |
| `pre_command` | string | no |  |
| `post_command` | string | no |  |
| `hook_timeout_minutes` | integer | no |  |
| `revision` | integer | yes |  |

## backup.cancel

Cancel active backup or recovery

- Screen group: backups
- Capability: `backup`
- Explicit confirmation: not required

## backup.cloud.archives

List cloud backup archives

- Screen group: backups
- Capability: `view`
- Explicit confirmation: not required

## backup.cloud.create

Configure provider credentials

- Screen group: backups
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |
| `provider` | string | yes |  |
| `options` | secret | yes |  |

## backup.cloud.oauth

Returns rclone's explicit authorization URL. Open it in an administrator browser; complete using cloud.create with the issued token; never launches a SYSTEM browser.

- Screen group: backups
- Capability: `configure`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `provider` | string | yes |  |
| `client_id` | string | no |  |
| `client_secret` | secret | no |  |

## backup.cloud.providers

List cloud provider onboarding options

- Screen group: backups
- Capability: `view`
- Explicit confirmation: not required

## backup.cloud.remotes

List configured cloud remotes

- Screen group: backups
- Capability: `view`
- Explicit confirmation: not required

## backup.cloud.remove

Remove cloud remote credentials

- Screen group: backups
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## backup.cloud.set

Revision-checked settings update. Hooks are privileged shell commands executed under the worker identity; settings may change retention and future scheduled actions.

- Screen group: backups
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `remotes` | string | no |  |
| `remote_folder` | string | no |  |
| `retention_days` | integer | no |  |
| `allow_share_links` | boolean | no |  |
| `revision` | integer | yes |  |

## backup.cloud.test

Writes random probe bytes under the selected backup folder, downloads and hashes them, then deletes only that probe.

- Screen group: backups
- Capability: `backup`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `remote` | string | yes |  |

## backup.config

Read backup settings (secrets redacted)

- Screen group: backups
- Capability: `view`
- Explicit confirmation: not required

## backup.drill

Restores newest ZIP/snapshot, verifies actual content, removes only its own temporary directory unless keep is selected.

- Screen group: backups
- Capability: `backup`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `keep` | boolean | no |  |

## backup.monitoring.set

Revision-checked settings update. Hooks are privileged shell commands executed under the worker identity; settings may change retention and future scheduled actions.

- Screen group: backups
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `alert_after_hours` | integer | no |  |
| `revision` | integer | yes |  |

## backup.progress

Read current backup progress

- Screen group: backups
- Capability: `view`
- Explicit confirmation: not required

## backup.recovery.export

Export portable encrypted recovery configuration

- Screen group: backups
- Capability: `manage`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `passphrase` | secret | yes |  |

## backup.recovery.import

Import portable encrypted recovery configuration

- Screen group: backups
- Capability: `manage`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `bundle` | secret | yes |  |
| `passphrase` | secret | yes |  |

## backup.repository.check

Verify repository data

- Screen group: backups
- Capability: `backup`
- Explicit confirmation: not required

## backup.repository.init

Creates an encrypted repository with the saved write-only password. Does not replace an existing repository.

- Screen group: backups
- Capability: `backup`
- Explicit confirmation: required

## backup.repository.prune

Apply restic retention

- Screen group: backups
- Capability: `backup`
- Explicit confirmation: required

## backup.restic.set

Revision-checked settings update. Hooks are privileged shell commands executed under the worker identity; settings may change retention and future scheduled actions.

- Screen group: backups
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `repository` | string | no |  |
| `keep_daily` | integer | no |  |
| `keep_weekly` | integer | no |  |
| `keep_monthly` | integer | no |  |
| `check_after_backup` | boolean | no |  |
| `revision` | integer | yes |  |

## backup.restore

Restore and verify isolated copy

- Screen group: backups
- Capability: `backup`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `engine` | choice | yes | zip, restic |
| `archive` | string | no |  |

## backup.restore_drill.set

Revision-checked settings update. Hooks are privileged shell commands executed under the worker identity; settings may change retention and future scheduled actions.

- Screen group: backups
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `enabled` | boolean | no |  |
| `interval_days` | integer | no |  |
| `dest` | string | no |  |
| `keep` | boolean | no |  |
| `revision` | integer | yes |  |

## backup.run

Captures an immutable settings revision; hooks execute as the worker identity; uses configured retention and destinations.

- Screen group: backups
- Capability: `backup`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `scheduled` | boolean | no |  |

## backup.schedule.set

Revision-checked settings update. Hooks are privileged shell commands executed under the worker identity; settings may change retention and future scheduled actions.

- Screen group: backups
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `enabled` | boolean | no |  |
| `mode` | choice | no | daily, interval, times |
| `time` | string | no |  |
| `times` | string | no |  |
| `interval_hours` | integer | no |  |
| `retry_count` | integer | no |  |
| `retry_delay_minutes` | integer | no |  |
| `timezone` | string | no |  |
| `catch_up` | boolean | no |  |
| `revision` | integer | yes |  |

## backup.secrets.update

Update write-only backup secrets

- Screen group: backups
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `archive_password` | secret | no |  |
| `repository_password` | secret | no |  |
| `healthcheck_url` | secret | no |  |
| `heartbeat_url` | secret | no |  |
| `clear` | string | no |  |

## backup.status

Backup worker status

- Screen group: backups
- Capability: `view`
- Explicit confirmation: not required

## backup.tools.install

HTTPS official release, mandatory SHA-256 and executable version verification; atomic install into protected agent data.

- Screen group: backups
- Capability: `manage`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `tool` | choice | yes | restic, rclone |
| `url` | string | yes |  |
| `sha256` | string | yes |  |
| `version` | string | yes |  |

## backup.tools.status

Inspect backup tool versions

- Screen group: backups
- Capability: `view`
- Explicit confirmation: not required

## diagnostics.boot

Boot and crash diagnosis; runs synchronously to a final result.

- Screen group: diagnostics
- Capability: `view`
- Explicit confirmation: not required

## diagnostics.connections

Connections and listeners; reads actual host state.

- Screen group: diagnostics
- Capability: `view`
- Explicit confirmation: not required

## diagnostics.dumps

Crash dumps can contain passwords and private data; listing requires management permission.

- Screen group: diagnostics
- Capability: `manage`
- Explicit confirmation: not required

## diagnostics.event_statistics

Group actual Windows errors by source.

- Screen group: diagnostics
- Capability: `view`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `days` | integer | no |  |

## diagnostics.events

Analyze System/Application errors with explanations and priorities.

- Screen group: diagnostics
- Capability: `view`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `hours` | integer | no |  |

## diagnostics.export_dump

Only a current Windows crash-dump inventory entry may be exported; sensitive artifact retention applies.

- Screen group: diagnostics
- Capability: `manage`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `path` | path | yes |  |

## diagnostics.export_logs

Export actual seven-day System/Application errors into a protected downloadable ZIP; no Telegram size limit.

- Screen group: diagnostics
- Capability: `files`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `scope` | choice | no | all, system, application |

## diagnostics.logs

Bounded event log query; reports access failure explicitly.

- Screen group: diagnostics
- Capability: `view`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `hours` | integer | no |  |
| `level` | choice | no | error, warning, all |

## diagnostics.network_test

DNS, ping and TCP connectivity diagnostics.

- Screen group: diagnostics
- Capability: `operate`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `host` | string | yes |  |

## diagnostics.speed_test

Consumes bandwidth; reports actual measured throughput.

- Screen group: diagnostics
- Capability: `operate`
- Explicit confirmation: not required

## diagnostics.startup

Startup inventory; runs synchronously to a final result.

- Screen group: diagnostics
- Capability: `view`
- Explicit confirmation: not required

## diagnostics.system

System information; runs synchronously to a final result.

- Screen group: diagnostics
- Capability: `view`
- Explicit confirmation: not required

## diagnostics.updates

Pending Windows updates; runs synchronously to a final result.

- Screen group: diagnostics
- Capability: `view`
- Explicit confirmation: not required

## files.browse

Canonical path and reparse-safe approved-root browsing; protected state is never exported.

- Screen group: files
- Capability: `files`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `path` | path | no |  |

## files.download

Export only an approved non-secret file, subject to configured quota and artifact retention.

- Screen group: files
- Capability: `files`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `path` | path | yes |  |

## files.largest

Bounded cancellable scan with progress, without traversing reparse points.

- Screen group: files
- Capability: `files`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `path` | path | no |  |
| `limit` | integer | no |  |
| `max_entries` | integer | no |  |

## imaging.chart

Image upload chart. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `view`
- Explicit confirmation: not required

## imaging.link

Uploaded image share link. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `backup`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `path` | path | yes |  |
| `remote` | string | yes |  |

## imaging.list

List local system images. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `view`
- Explicit confirmation: not required

## imaging.recovery

Image recovery instructions. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `view`
- Explicit confirmation: not required

## imaging.start

Create system image. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `manage`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `target` | path | yes |  |
| `volumes` | string | no |  |
| `vss` | boolean | no |  |
| `remote` | string | no |  |

## imaging.status

Image status/progress. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `view`
- Explicit confirmation: not required

## imaging.stop

Stop active imaging/upload. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `manage`
- Explicit confirmation: required

## imaging.tools

Install/verify Microsoft imaging tool. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `manage`
- Explicit confirmation: required

## imaging.upload

Upload and verify system image. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `backup`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `path` | path | yes |  |
| `remote` | string | yes |  |

## imaging.verify

Verify local VHDX structure. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `manage`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `path` | path | yes |  |

## imaging.volumes

Available imaging volumes. Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.

- Screen group: imaging
- Capability: `view`
- Explicit confirmation: not required

## advanced.shell

Disabled by default. Executes as privileged worker, bounded time/output, cancellation kills the process tree. Secrets are not audited as command text.

- Screen group: maintenance
- Capability: `execute`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `command` | secret | yes |  |
| `timeout` | integer | no |  |

## help.operations

Effects, permission requirements, confirmation flags and typed input reference for every callable operation.

- Screen group: maintenance
- Capability: `view`
- Explicit confirmation: not required

## maintenance.cleanup

Remove eligible old temporary files, report actual bytes removed and access failures; never follows reparse directories.

- Screen group: maintenance
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `age_hours` | integer | no |  |

## maintenance.cleanup_preview

Enumerate old temporary files only; no recycle-bin or arbitrary-root deletion.

- Screen group: maintenance
- Capability: `operate`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `age_hours` | integer | no |  |

## maintenance.export_log

Generate downloadable monitor log artifact.

- Screen group: maintenance
- Capability: `manage`
- Explicit confirmation: required

## maintenance.logs

Read bounded worker/monitor log tail; paths are not remotely selectable.

- Screen group: maintenance
- Capability: `manage`
- Explicit confirmation: not required

## maintenance.update

Verify a pinned-publisher signed release, then hand off to the installed transactional updater. Job remains partial until the external updater commits; never replace running Python source.

- Screen group: maintenance
- Capability: `manage`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `package` | path | yes |  |

## power.cancel

Ask Windows to cancel a scheduled restart/shutdown; actual exit code determines outcome.

- Screen group: maintenance
- Capability: `manage`
- Explicit confirmation: not required

## power.restart

Schedules real host power action with a cancellation window; closes unsaved work.

- Screen group: maintenance
- Capability: `manage`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `delay` | integer | no |  |
| `reason` | string | no |  |

## power.shutdown

Schedules real host power action with a cancellation window; closes unsaved work.

- Screen group: maintenance
- Capability: `manage`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `delay` | integer | no |  |
| `reason` | string | no |  |

## monitoring.chart

Generate a downloadable CPU/RAM chart from measured history.

- Screen group: monitoring
- Capability: `view`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `hours` | integer | no |  |

## monitoring.history

Persisted timestamped CPU/RAM/network measurements.

- Screen group: monitoring
- Capability: `view`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `limit` | integer | no |  |

## monitoring.network

Network totals and rates; reads actual host state.

- Screen group: monitoring
- Capability: `view`
- Explicit confirmation: not required

## monitoring.report

Generate the same report as scheduled daily/weekly reporting.

- Screen group: monitoring
- Capability: `view`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `period` | choice | no | daily, weekly |

## monitoring.temperature

Read available WMI/NVIDIA sensors; unavailable is not zero.

- Screen group: monitoring
- Capability: `view`
- Explicit confirmation: not required

## monitoring.top

Top processes; reads actual host state.

- Screen group: monitoring
- Capability: `view`
- Explicit confirmation: not required

## monitoring.traffic

Daily persistent transferred totals and current quota window.

- Screen group: monitoring
- Capability: `view`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `days` | integer | no |  |

## monitoring.when

Search measured history, not estimated samples.

- Screen group: monitoring
- Capability: `view`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `metric` | choice | no | cpu, ram |
| `threshold` | integer | no |  |
| `hours` | integer | no |  |

## overview.snapshot

Actual CPU, RAM, disks, rates, processes, sessions and uptime.

- Screen group: overview
- Capability: `view`
- Explicit confirmation: not required

## session.list

Discover actual WTS sessions and availability.

- Screen group: overview
- Capability: `view`
- Explicit confirmation: not required

## processes.inspect

Full executable paths and owners, reusing the monitor inspection engine.

- Screen group: processes
- Capability: `view`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## processes.list

PID, creation timestamp, owner, image, memory and CPU for identity-safe targeting.

- Screen group: processes
- Capability: `view`
- Explicit confirmation: not required

## processes.terminate

Revalidates PID/creation identity; protects system and agent processes. Unsaved work can be lost.

- Screen group: processes
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `pid` | integer | yes |  |
| `created` | number | yes |  |

## services.list

Read service name, status, startup mode and binary path.

- Screen group: processes
- Capability: `view`
- Explicit confirmation: not required

## services.restart

Run a typed service action, wait for its final state; protected system/agent services cannot be stopped.

- Screen group: processes
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## services.start

Run a typed service action, wait for its final state; protected system/agent services cannot be stopped.

- Screen group: processes
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## services.stop

Run a typed service action, wait for its final state; protected system/agent services cannot be stopped.

- Screen group: processes
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## session.launch

Requires available authenticated per-user helper; never silently runs interactively as SYSTEM. Logoff loses unsaved work.

- Screen group: processes
- Capability: `execute`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `session_id` | integer | yes |  |
| `executable` | path | yes |  |
| `arguments` | string | no |  |

## session.lock

Requires available authenticated per-user helper; never silently runs interactively as SYSTEM. Logoff loses unsaved work.

- Screen group: processes
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `session_id` | integer | yes |  |

## session.logoff

Requires available authenticated per-user helper; never silently runs interactively as SYSTEM. Logoff loses unsaved work.

- Screen group: processes
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `session_id` | integer | yes |  |

## session.message

Requires available authenticated per-user helper; never silently runs interactively as SYSTEM. Logoff loses unsaved work.

- Screen group: processes
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `session_id` | integer | yes |  |
| `message` | string | yes |  |
| `title` | string | no |  |

## session.recycle_bin

Requires available authenticated per-user helper; never silently runs interactively as SYSTEM. Logoff loses unsaved work.

- Screen group: processes
- Capability: `operate`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `session_id` | integer | yes |  |

## session.screenshot

Requires available authenticated per-user helper; never silently runs interactively as SYSTEM. Logoff loses unsaved work.

- Screen group: processes
- Capability: `files`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `session_id` | integer | yes |  |

## rdp.allow_add

Transactional RDP allow-list change. Clearing can expose RDP; keep an independent console connection.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `ip` | string | yes |  |

## rdp.allow_apply

Transactional RDP allow-list change. Clearing can expose RDP; keep an independent console connection.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

## rdp.allow_clear

Transactional RDP allow-list change. Clearing can expose RDP; keep an independent console connection.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

## rdp.allow_remove

Transactional RDP allow-list change. Clearing can expose RDP; keep an independent console connection.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `ip` | string | yes |  |

## rdp.lockdown

Restrict RDP to explicitly trusted sources, with persisted expiry; may disconnect sessions.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `enabled` | boolean | yes |  |
| `minutes` | integer | no |  |

## rdp.logins

Read successful Windows logon events.

- Screen group: security
- Capability: `view`
- Explicit confirmation: not required

| Input | Type | Required | Choices |
|---|---|---|---|
| `limit` | integer | no |  |

## rdp.panic

Close all RDP access, including current management path. Requires independent console recovery.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `enabled` | boolean | yes |  |

## rdp.port

Verify free port, stage firewall, change registry/restart service, verify listener; rollback on failure.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `port` | integer | yes |  |

## rdp.sessions

RDP sessions and addresses; reads actual host state.

- Screen group: security
- Capability: `view`
- Explicit confirmation: not required

## rdp.status

Effective allow-list, port, panic and lockdown state.

- Screen group: security
- Capability: `view`
- Explicit confirmation: not required

## security.block

Changes Windows Firewall. Trusted/current RDP addresses are protected; subnet operation previews the affected /24.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `ip` | string | yes |  |

## security.block_subnet

Changes Windows Firewall. Trusted/current RDP addresses are protected; subnet operation previews the affected /24.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `ip` | string | yes |  |

## security.blocks

Tracked block addresses and creation timestamps.

- Screen group: security
- Capability: `view`
- Explicit confirmation: not required

## security.firewall

Actual profile state and inbound allowed ports.

- Screen group: security
- Capability: `view`
- Explicit confirmation: not required

## security.hardening_audit

Audit NLA, account lockout and administrator naming without changing them.

- Screen group: security
- Capability: `view`
- Explicit confirmation: not required

## security.hardening_fix

Enable NLA and supported account lockout controls; verify actual outcome.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

## security.learned_remove

Forget a learned address without silently changing the manual allow-list.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `ip` | string | yes |  |

## security.trap_add

Manage validated trap names used by failed-logon protection.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## security.trap_remove

Manage validated trap names used by failed-logon protection.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `name` | string | yes |  |

## security.traps

Login attempts using a trap trigger protection.

- Screen group: security
- Capability: `view`
- Explicit confirmation: not required

## security.unblock

Changes Windows Firewall. Trusted/current RDP addresses are protected; subnet operation previews the affected /24.

- Screen group: security
- Capability: `security`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `ip` | string | yes |  |

## security.whitelist

Learned login success is not automatically equivalent to manual trust.

- Screen group: security
- Capability: `view`
- Explicit confirmation: not required

## settings.account_watch

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.alert_interval

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.auto_clean_day

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.auto_clean_enabled

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.auto_clean_hour

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.auto_learn_ips

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.auto_lock_minutes

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.auto_restart_consecutive

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.auto_restart_cpu

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.auto_restart_enabled

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.auto_restart_ram

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.baseline_alerts

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.cpu_alert_threshold

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.critical_alerts

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.critical_threshold

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.daily_report_enabled

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.daily_report_hour

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.danger_threshold

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.disk_threshold

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.exec_enabled

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.export

Safe configuration export excludes runtime state and every credential.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: not required

## settings.failed_login_alerts

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.failed_login_block

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.failed_login_block_threshold

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.failed_login_window

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.failed_logon_types

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | string | yes |  |

## settings.files

Change export roots and quotas. Agent credential/state and Windows security material remain denied.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `roots` | string | yes |  |
| `max_bytes` | integer | no |  |
| `revision` | integer | yes |  |

## settings.fw_guard

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.heartbeat_hours

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.image_delete_after

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.image_enabled

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.import

Validate the entire configuration atomically before applying; no legacy token imports.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `configuration` | string | yes |  |
| `revision` | integer | yes |  |

## settings.instance_name

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | string | yes |  |

## settings.learn_for_lockdown

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.lockdown

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.lockdown_limit

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.lockdown_minutes

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.net_watch

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.new_ip_alerts

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.ping_target

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | string | yes |  |

## settings.ram_alert_threshold

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.rclone_path

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | string | yes |  |

## settings.rclone_remote

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | string | yes |  |

## settings.rdp_watch

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.rdphours

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | string | yes |  |

## settings.recovery_export

AES-GCM encrypted monitor configuration, password-derived key; keep passphrase separately. Backup recovery has its own export operation.

- Screen group: settings
- Capability: `manage`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `passphrase` | secret | yes |  |

## settings.restart_cooldown

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.restart_delay_seconds

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.selfheal_disk

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.session_alerts

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.speedtest_interval_hours

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.spike_cooldown

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.spike_threshold

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.startup_report

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.status

Secrets and legacy transport credentials are excluded.

- Screen group: settings
- Capability: `view`
- Explicit confirmation: not required

## settings.subnetblock

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.temp_threshold

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.traffic_quota_gb

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.traffic_reset_day

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.update_check_hours

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.upload_dir

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | string | yes |  |

## settings.uploads_enabled

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.user_management

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.weekly_report_day

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |

## settings.weekly_report_enabled

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | boolean | yes |  |

## settings.weekly_report_hour

Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.

- Screen group: settings
- Capability: `configure`
- Explicit confirmation: required

| Input | Type | Required | Choices |
|---|---|---|---|
| `value` | integer | yes |  |
