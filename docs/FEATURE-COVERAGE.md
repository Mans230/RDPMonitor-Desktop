# Native desktop feature coverage

Baseline: `72fae430d3ee8d29b5d004ce476cacdff4bac821`. All 87 documented legacy commands are accounted for below. The agent currently exposes 199 executable operation descriptors, including typed settings and recovery operations.

This is a source-to-catalog migration ledger, not a claim that every destructive operation was executed. Actual verification and required production VM/device checks are documented in `DESKTOP-DEPLOYMENT.md`. Transport-only commands are intentionally replaced rather than kept as aliases.

| Legacy intent | Native operation or disposition |
|---|---|
| `/view` | `overview.snapshot` |
| `/top` | `monitoring.top` |
| `/chart` | `monitoring.chart` |
| `/report` | `monitoring.report` |
| `/temp` | `monitoring.temperature` |
| `/net` | `monitoring.network` |
| `/traffic` | `monitoring.traffic` |
| `/speedtest` | `diagnostics.speed_test` |
| `/rdp` | `rdp.sessions` |
| `/logins` | `rdp.logins` |
| `/listusers` | `accounts.list` |
| `/bigfiles` | `files.largest` |
| `/netstat` | `diagnostics.connections` |
| `/firewall` | `security.firewall` |
| `/sysinfo` | `diagnostics.system` |
| `/startup` | `diagnostics.startup` |
| `/updates` | `diagnostics.updates` |
| `/audit` | `activity.audit` |
| `/blocklist` | `security.blocks` |
| `/block` | `security.block` |
| `/blocksubnet` | `security.block_subnet` |
| `/whitelist` | `security.whitelist` |
| `/botlog` | `maintenance.logs` |
| `/clean` | `maintenance.cleanup_preview`, `maintenance.cleanup`, `session.recycle_bin` |
| `/exec` | `advanced.shell` |
| `/kill` | `processes.terminate` |
| `/run` | `session.launch` |
| `/download` | `files.download` |
| `/logoff` | `session.logoff` |
| `/adduser` | `accounts.create` |
| `/disableuser` | `accounts.disable` |
| `/enableuser` | `accounts.enable` |
| `/deluser` | `accounts.delete` |
| `/setrdpport` | `rdp.port` |
| `/rdpallow` | `rdp.allow_add`, `rdp.allow_remove`, `rdp.allow_apply`, `rdp.allow_clear` |
| `/lockdown` | `rdp.lockdown` |
| `/panic` | `rdp.panic` |
| `/harden` | `security.hardening_audit`, `security.hardening_fix` |
| `/restart` | `power.restart` |
| `/shutdown` | `power.shutdown` |
| `/mute` | `activity.mute` |
| `/image` | `imaging.start`, `imaging.list`, `imaging.upload`, `imaging.status`, `imaging.stop`, `imaging.recovery` |
| `/set` | `settings.status` |
| `/status` | `settings.status` |
| `/panel` | Replaced by native machine navigation; no browser interface is shipped. |
| `/panelstatus` | Replaced by authenticated agent health and client Live/Stale/Offline status. |
| `/paneltoken` | Removed. Locally approved certificate enrollment replaces revealing shared credentials. |
| `/panelremote` | Replaced by explicitly scoped signed deployment and native connection profile enrollment. |
| `/backup` | `backup.run` |
| `/backupstatus` | `backup.status` |
| `/backuplist` | `backup.archives` |
| `/backsrc` | `backup.backup.set`, `files.browse` |
| `/backupprogress` | `backup.progress` |
| `/restorelist` | `backup.archives` |
| `/restore` | `backup.restore` |
| `/drill` | `backup.drill` |
| `/start` | Replaced by native application launch and Machines/Overview navigation. |
| `/menu` | Replaced by native navigation. |
| `/noop` | Replaced by dismissing an unsubmitted confirmation; running work has explicit cancellation. |
| `/diagnose` | `diagnostics.events` |
| `/logstats` | `diagnostics.event_statistics` |
| `/exportlogs` | `diagnostics.export_logs` |
| `/dumps` | `diagnostics.dumps`, `diagnostics.export_dump` |
| `/screenshot` | `session.screenshot` |
| `/msg` | `session.message` |
| `/ps` | `processes.inspect` |
| `/when` | `monitoring.when` |
| `/nettest` | `diagnostics.network_test` |
| `/test` | `activity.test` |
| `/token` | Removed. No shared panel bearer token exists. |
| `/configbackup` | `settings.export`, `settings.recovery_export`, `backup.recovery.export` |
| `/cancel_restart` | `power.cancel` |
| `/update` | `maintenance.update` |
| `/unblock` | `security.unblock` |
| `/allow` | Replaced by locally approved owner/operator/viewer device certificates and native revocation. |
| `/trap` | `security.traps`, `security.trap_add`, `security.trap_remove` |
| `/svc` | `services.start`, `services.stop`, `services.restart` |
| `/watch` | `automation.watch.list`, `automation.watch.set`, `automation.watch.remove` |
| `/renameuser` | `accounts.rename` |
| `/getlog` | `maintenance.logs` |
| `/keepalive` | `automation.keepalive.list`, `automation.keepalive.set`, `automation.keepalive.remove` |
| `/svcwatch` | `automation.svcwatch.list`, `automation.svcwatch.set`, `automation.svcwatch.remove` |
| `/help` | `help.operations` |
| `/docs` | `help.operations` |
| `/backupschedule` | `backup.schedule.set` |
| `/cloud` | `backup.cloud.set`, `backup.cloud.test` |
| `/rclone` | `backup.tools.install`, `backup.cloud.create`, `backup.cloud.oauth`, `backup.cloud.remotes`, `backup.cloud.providers`, `backup.cloud.remove` |

## Capabilities beyond slash commands

- Process/service inventory, identity-safe process termination, WTS session helper and account password changes.
- Background monitoring/protection, reports, disk/temp/account/session events, watch/keepalive/service recovery, quotas, RDP hours and distributed-attack protection.
- Incoming files: bounded resumable upload staging and SHA-256/no-overwrite commit, controlled by live upload and approved-root policies.
- ZIP/restic configuration, missing-source enforcement, VSS, hooks, retention, cloud OAuth/credentials, actual restore verification and isolated drills.
- Durable jobs, cancellation, per-job encrypted configuration snapshots, encrypted off-host recovery export/import, device renewal/revocation and cursor-based event history.
- APNs/FCM sender integration, protected target registration and persistent inbox/outbox. Actual provider credentials and signed mobile device setup are external prerequisites.

## Safety and platform boundaries

Windows actions run on Windows agents. Interactive operations require the selected signed-in user helper. Guest agents cannot power on their own stopped VM or control a hypervisor without a separate provider integration. Shell/account/upload/imaging capabilities remain deliberately gated. Closing the client does not stop agent work.
