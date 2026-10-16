"""Transport-independent Windows management, using the retained monitor engines.

Catalog entries are the public operation contract. Only execute() performs requested
work; construction never changes host accounts, firewall, power, or services.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import mimetypes
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile

import psutil

from .contracts import OperationError
from .security import ROLE_CAPABILITIES


def field(name, label, kind="string", required=True, default=None, choices=None, help=None):
    result = {"name": name, "label": label, "type": kind, "required": required}
    if default is not None:
        result["default"] = default
    if choices is not None:
        result["choices"] = choices
    if help:
        result["help"] = help
    return result


def success(data=None, message="Completed"):
    return {"status": "succeeded", "message": message, "data": data}


class WindowsBackend:
    def __init__(self, root: Path, data_dir: Path, store):
        self.root, self.data_dir, self.store = Path(root), Path(data_dir), store
        self.data_dir.mkdir(parents=True, exist_ok=True)
        migrated = self.data_dir / "legacy" / "monitor"
        self.monitor_dir = migrated if migrated.is_dir() else self.data_dir / "monitor"
        self.monitor_dir.mkdir(parents=True, exist_ok=True)
        self.exports = self.data_dir / "exports"
        self.exports.mkdir(exist_ok=True)
        self._lock = threading.RLock()
        self._capture_lock = threading.RLock()
        self._started = False
        self.read_only = False
        self._submitter = None
        self._network_sample = None
        self._catalog = []
        self._handlers = {}
        # Delayed import: no worker/background loops are started by the module.
        import rdp_monitor as monitor
        self.monitor = monitor
        monitor.configure_runtime(self.monitor_dir, self._emit, self._artifact, self._session_automation)
        monitor.BACKUP_DIR = str(self.data_dir / "backup")
        monitor.load_config()
        # Legacy transports and their credentials are never runtime authorities.
        for name in ("telegram_token", "telegram_token_enc", "chat_id"):
            monitor.config[name] = ""
        for name in ("trusted_chat_ids", "trusted_user_ids"):
            monitor.config[name] = []
        from .backup import BackupManager
        self.backup = BackupManager(self.root, self.data_dir, self._emit)
        self._register_operations()
        saved = self.store.get_config("monitor", {})
        if saved["value"]:
            monitor.config.update(self._validate_config(saved["value"]))
        else:
            initial = {key: copy.deepcopy(monitor.config[key]) for key in self._editable_defaults()}
            self.store.set_config("monitor", initial, saved["revision"])
        self._sync_backup_config()
        monitor.load_history()

    def _emit(self, kind, message, severity="info", data=None):
        return self.store.append_event(kind, str(message), severity, data=data)

    def _artifact(self, path, name=None, media_type="application/octet-stream"):
        return self.store.add_artifact(Path(path), name=name, media_type=media_type)

    def set_submitter(self, callback):
        self._submitter = callback
        self.backup.set_submitter(callback)

    def start(self, read_only=False):
        with self._lock:
            if self._started:
                return
            if os.name != "nt":
                raise OperationError("platform_unavailable", "The management worker requires Windows", 503)
            self.read_only = bool(read_only)
            self.monitor.start_monitoring(read_only=self.read_only)
            self.backup.start(read_only=self.read_only)
            self._started = True

    def stop(self):
        with self._lock:
            if not self._started:
                return
            self.backup.stop()
            self.monitor.stop_monitoring()
            self._started = False

    def catalog(self):
        return copy.deepcopy(self._catalog + self.backup.catalog())

    def job_snapshot(self):
        """Private execution state; never expose this through gateway responses."""
        return {"monitor": self.get_config("monitor"), "backup": self.backup.job_snapshot(),
                "files": self.get_config("files")}

    def _sync_backup_config(self):
        private = self.backup.job_snapshot()["value"]
        stored = self.store.get_config("backup", {})
        if stored["value"] != private:
            self.store.set_config("backup", private, stored["revision"])

    def approve_file(self, path, write=False):
        """Shared transfer admission; returns a canonical non-reparse approved path."""
        if write and not self.monitor.config.get("uploads_enabled"):
            raise OperationError("capability_disabled", "File reception is disabled", 403)
        return self._approved(os.fspath(path), must_exist=not write)

    def _session_automation(self, action, args):
        if self.read_only:
            return 0 if action == "idle" else False
        try:
            sessions = [s for s in self._helper().sessions()
                        if s.get("helper_available") and not s.get("locked")
                        and s.get("idle_seconds") is not None]
            if action == "idle":
                return max((s["idle_seconds"] for s in sessions), default=0)
            if action == "lock" and self._submitter:
                threshold = self.monitor.config.get("auto_lock_minutes", 0) * 60
                for session in sessions:
                    if threshold and session["idle_seconds"] >= threshold:
                        sid = session.get("session_id", session.get("id"))
                        self._submitter("session.lock", {"session_id": sid},
                                        f"idle-lock:{sid}:{int(time.time() // max(threshold, 60))}")
                # Submission is not completion. Runtime delivers the actual job
                # outcome; never announce a lock while execution is still queued.
                return False
        except Exception as exc:
            self._emit("automation.session", "Session idle protection failed: " + str(exc), "warning")
        return 0 if action == "idle" else False

    def _add(self, operation, title, section, capability, destructive, fields, handler, description):
        self._catalog.append({"id": operation, "title": title, "section": section,
                              "description": description, "capability": capability,
                              "destructive": destructive, "fields": fields})
        self._handlers[operation] = handler

    def _register_operations(self):
        add, m = self._add, self.monitor
        add("overview.snapshot", "Live machine overview", "overview", "view", False, [],
            lambda a, c: self.latest_snapshot(), "Actual CPU, RAM, disks, rates, processes, sessions and uptime.")
        reports = [
            ("monitoring.top", "Top processes", "monitoring", m.format_top_report),
            ("monitoring.network", "Network totals and rates", "monitoring", m.format_net_report),
            ("rdp.sessions", "RDP sessions and addresses", "security", m.format_rdp_report),
            ("diagnostics.connections", "Connections and listeners", "diagnostics", m.format_netstat),
        ]
        for op, title, section, fn in reports:
            add(op, title, section, "view", False, [], lambda a, c, fn=fn: self._text(fn), title + "; reads actual host state.")
        add("monitoring.temperature", "Temperature sensors", "monitoring", "view", False, [],
            self._temperatures, "Read available WMI/NVIDIA sensors; unavailable is not zero.")
        add("monitoring.history", "Metric history", "monitoring", "view", False,
            [field("limit", "Samples", "integer", False, 1000)], lambda a, c: self.history(a["limit"]), "Persisted timestamped CPU/RAM/network measurements.")
        add("monitoring.chart", "Historical chart", "monitoring", "view", False,
            [field("hours", "Hours", "integer", False, 24)], self._chart, "Generate a downloadable CPU/RAM chart from measured history.")
        add("monitoring.report", "Usage report", "monitoring", "view", False,
            [field("period", "Period", "choice", False, "daily", ["daily", "weekly"])],
            lambda a, c: self._capture(m.send_weekly_report if a["period"] == "weekly" else m.send_daily_report, c), "Generate the same report as scheduled daily/weekly reporting.")
        add("monitoring.traffic", "Traffic and billing quota", "monitoring", "view", False,
            [field("days", "Days", "integer", False, 7)], lambda a, c: self._text(lambda: m.traffic_report(self._int(a["days"], 1, 365))), "Daily persistent transferred totals and current quota window.")
        add("monitoring.when", "Find threshold occurrences", "monitoring", "view", False,
            [field("metric", "Metric", "choice", False, "cpu", ["cpu", "ram"]), field("threshold", "Percent", "integer", False, 80), field("hours", "Hours", "integer", False, 24)],
            lambda a, c: self._text(lambda: m.when_report(a["metric"], self._int(a["threshold"], 1, 100), self._int(a["hours"], 1, 192))), "Search measured history, not estimated samples.")
        diagnostics = [
            ("diagnostics.startup", "Startup inventory", m.startup_job),
            ("diagnostics.updates", "Pending Windows updates", m.updates_job),
            ("diagnostics.system", "System information", m._sysinfo_job),
            ("diagnostics.boot", "Boot and crash diagnosis", m.boot_report),
        ]
        for op, title, fn in diagnostics:
            add(op, title, "diagnostics", "view", False, [], lambda a, c, fn=fn: self._capture(fn, c), title + "; runs synchronously to a final result.")
        add("diagnostics.events", "Analyze Windows event failures", "diagnostics", "view", False,
            [field("hours", "Hours", "integer", False, 24)], lambda a, c: self._text(lambda: m.diagnose_report(self._int(a["hours"], 1, 720))), "Analyze System/Application errors with explanations and priorities.")
        add("diagnostics.event_statistics", "Event source statistics", "diagnostics", "view", False,
            [field("days", "Days", "integer", False, 7)], lambda a, c: self._text(lambda: m.logstats_report(self._int(a["days"], 1, 30))), "Group actual Windows errors by source.")
        add("diagnostics.logs", "Read Windows event logs", "diagnostics", "view", False,
            [field("hours", "Hours", "integer", False, 24), field("level", "Level", "choice", False, "error", list(m.LOG_LEVELS))], self._event_logs, "Bounded event log query; reports access failure explicitly.")
        add("diagnostics.network_test", "Host connectivity test", "diagnostics", "operate", False,
            [field("host", "IP address or hostname")], lambda a, c: self._capture(lambda: m.nettest_job(self._host(a["host"])), c), "DNS, ping and TCP connectivity diagnostics.")
        add("diagnostics.speed_test", "Internet bandwidth test", "diagnostics", "operate", False, [],
            lambda a, c: success(dict(zip(("ping_ms", "download_mbps", "upload_mbps"), m.run_speedtest()))), "Consumes bandwidth; reports actual measured throughput.")
        add("security.firewall", "Firewall posture", "security", "view", False, [], self._firewall, "Actual profile state and inbound allowed ports.")
        add("security.blocks", "Tracked firewall blocks", "security", "view", False, [], lambda a, c: copy.deepcopy(m._blocked), "Tracked block addresses and creation timestamps.")
        for action in ("block", "unblock", "block_subnet"):
            add("security." + action, action.replace("_", " ").title(), "security", "security", True,
                [field("ip", "IP address")], lambda a, c, action=action: self._block(action, a, c), "Changes Windows Firewall. Trusted/current RDP addresses are protected; subnet operation previews the affected /24.")
        add("security.whitelist", "Trusted and learned addresses", "security", "view", False, [],
            lambda a, c: {"manual": copy.deepcopy(m.config["rdp_allowed_ips"]), "learned": copy.deepcopy(m.config["learned_ips"])}, "Learned login success is not automatically equivalent to manual trust.")
        add("security.learned_remove", "Remove learned address", "security", "security", True,
            [field("ip", "IP address")], self._forget_ip, "Forget a learned address without silently changing the manual allow-list.")
        add("rdp.status", "RDP protection status", "security", "view", False, [], lambda a, c: m.api_rdp_status(), "Effective allow-list, port, panic and lockdown state.")
        for action in ("add", "remove", "apply", "clear"):
            add("rdp.allow_" + action, "RDP allow-list: " + action, "security", "security", True,
                [field("ip", "IP address")] if action in ("add", "remove") else [],
                lambda a, c, action=action: self._pair(getattr(m, "api_rdp_allow_" + action)(a["ip"]) if "ip" in a else getattr(m, "api_rdp_allow_" + action)()),
                "Transactional RDP allow-list change. Clearing can expose RDP; keep an independent console connection.")
        add("rdp.port", "Change RDP port", "security", "security", True,
            [field("port", "New TCP/UDP port", "integer")], self._rdp_port, "Verify free port, stage firewall, change registry/restart service, verify listener; rollback on failure.")
        add("rdp.lockdown", "Emergency trusted-source lockdown", "security", "security", True,
            [field("enabled", "Enable", "boolean"), field("minutes", "Duration (minutes)", "integer", False, 60)], self._lockdown, "Restrict RDP to explicitly trusted sources, with persisted expiry; may disconnect sessions.")
        add("rdp.panic", "Emergency RDP closure", "security", "security", True,
            [field("enabled", "Close RDP", "boolean")], self._panic, "Close all RDP access, including current management path. Requires independent console recovery.")
        add("security.hardening_audit", "Audit RDP hardening", "security", "view", False, [], lambda a, c: self._hardening(False), "Audit NLA, account lockout and administrator naming without changing them.")
        add("security.hardening_fix", "Apply supported RDP hardening", "security", "security", True, [], lambda a, c: self._hardening(True), "Enable NLA and supported account lockout controls; verify actual outcome.")
        add("security.traps", "Trap usernames", "security", "view", False, [], lambda a, c: copy.deepcopy(m.config["trap_users"]), "Login attempts using a trap trigger protection.")
        for action in ("add", "remove"):
            add("security.trap_" + action, "Trap username: " + action, "security", "security", True,
                [field("name", "Username")], lambda a, c, action=action: self._trap(action, a), "Manage validated trap names used by failed-logon protection.")
        add("rdp.logins", "Successful RDP logins", "security", "view", False,
            [field("limit", "Entries", "integer", False, 10)], lambda a, c: self._capture(lambda: m._logins_job(self._int(a["limit"], 1, 100)), c), "Read successful Windows logon events.")
        add("processes.list", "Process inventory", "processes", "view", False, [], lambda a, c: self._processes(), "PID, creation timestamp, owner, image, memory and CPU for identity-safe targeting.")
        add("processes.inspect", "Process details", "processes", "view", False,
            [field("name", "Exact process name")], lambda a, c: self._text(lambda: m.ps_detail(a["name"])), "Full executable paths and owners, reusing the monitor inspection engine.")
        add("processes.terminate", "Terminate one process", "processes", "operate", True,
            [field("pid", "Process ID", "integer"), field("created", "Creation timestamp", "number")], self._terminate, "Revalidates PID/creation identity; protects system and agent processes. Unsaved work can be lost.")
        add("services.list", "Windows services", "processes", "view", False, [], self._services, "Read service name, status, startup mode and binary path.")
        for action in ("start", "stop", "restart"):
            add("services." + action, action.title() + " Windows service", "processes", "operate", True,
                [field("name", "Service name")], lambda a, c, action=action: self._service(action, a), "Run a typed service action, wait for its final state; protected system/agent services cannot be stopped.")
        add("accounts.list", "Local accounts", "accounts", "view", False, [], lambda a, c: m._local_users_detail(strict=True), "Read enabled state and administrator membership from Windows, without invented fallback state.")
        for action in ("create", "enable", "disable", "delete", "password", "rename"):
            fields = [field("name", "Account name")]
            if action in ("create", "password"):
                fields.append(field("password", "New password", "secret"))
            if action == "create":
                fields.append(field("role", "Membership", "choice", False, "user", ["user", "admin"]))
            if action == "rename":
                fields.append(field("new_name", "New account name"))
            add("accounts." + action, action.title() + " account", "accounts", "accounts", True, fields,
                lambda a, c, action=action: self._account(action, a), "Account capability is off by default. Disruptive changes refuse last enabled administrator and signed-in accounts. Passwords are never echoed.")
        session_fields = [field("session_id", "Interactive session ID", "integer")]
        add("session.list", "Interactive Windows sessions", "overview", "view", False, [], lambda a, c: self._helper().sessions(), "Discover actual WTS sessions and availability.")
        for action, title, capability, extra in (
            ("screenshot", "Capture selected session", "files", []),
            ("message", "Message selected session", "operate", [field("message", "Message"), field("title", "Title", "string", False, "RDPMonitor")]),
            ("launch", "Launch in selected session", "execute", [field("executable", "Executable", "path"), field("arguments", "Arguments (JSON string array)", "string", False, "[]")]),
            ("lock", "Lock selected session", "operate", []),
            ("recycle_bin", "Empty selected user's Recycle Bin", "operate", []),
            ("logoff", "Log off selected session", "operate", [])):
            add("session." + action, title, "processes", capability, True, session_fields + extra,
                lambda a, c, action=action: self._session(action, a, c), "Requires available authenticated per-user helper; never silently runs interactively as SYSTEM. Logoff loses unsaved work.")
        add("advanced.shell", "Bounded Windows shell", "maintenance", "execute", True,
            [field("command", "Command", "secret"), field("timeout", "Timeout seconds", "integer", False, 30)], self._shell, "Disabled by default. Executes as privileged worker, bounded time/output, cancellation kills the process tree. Secrets are not audited as command text.")
        for action in ("restart", "shutdown"):
            add("power." + action, action.title() + " this computer", "maintenance", "manage", True,
                [field("delay", "Delay seconds", "integer", False, 60), field("reason", "Reason", "string", False, "RDPMonitor operator request")], lambda a, c, action=action: self._power(action, a), "Schedules real host power action with a cancellation window; closes unsaved work.")
        add("power.cancel", "Cancel pending power action", "maintenance", "manage", False, [], lambda a, c: self._command(["shutdown", "/a"], timeout=15), "Ask Windows to cancel a scheduled restart/shutdown; actual exit code determines outcome.")
        add("files.browse", "Browse approved export roots", "files", "files", False,
            [field("path", "Directory", "path", False, str(self.exports))], self._browse, "Canonical path and reparse-safe approved-root browsing; protected state is never exported.")
        add("files.download", "Create downloadable artifact", "files", "files", True,
            [field("path", "File", "path")], self._download, "Export only an approved non-secret file, subject to configured quota and artifact retention.")
        add("files.largest", "Largest files in approved root", "files", "files", False,
            [field("path", "Scan root", "path", False, str(self.exports)), field("limit", "Result count", "integer", False, 20), field("max_entries", "Scan bound", "integer", False, 100000)], self._largest, "Bounded cancellable scan with progress, without traversing reparse points.")
        add("diagnostics.export_logs", "Export Windows log bundle", "diagnostics", "files", True,
            [field("scope", "Logs", "choice", False, "all", ["all", "system", "application"])], self._export_logs, "Export actual seven-day System/Application errors into a protected downloadable ZIP; no Telegram size limit.")
        add("diagnostics.dumps", "List crash dumps", "diagnostics", "manage", False, [], lambda a, c: [{"path": p, "size": size, "modified": t} for p, size, t in m._crash_dumps()], "Crash dumps can contain passwords and private data; listing requires management permission.")
        add("diagnostics.export_dump", "Export sensitive crash dump", "diagnostics", "manage", True,
            [field("path", "Listed crash dump", "path")], self._export_dump, "Only a current Windows crash-dump inventory entry may be exported; sensitive artifact retention applies.")
        add("maintenance.logs", "Read agent diagnostic log", "maintenance", "manage", False, [], self._agent_log, "Read bounded worker/monitor log tail; paths are not remotely selectable.")
        add("maintenance.export_log", "Export agent diagnostic log", "maintenance", "manage", True, [], self._export_agent_log, "Generate downloadable monitor log artifact.")
        add("maintenance.cleanup_preview", "Preview temporary cleanup", "maintenance", "operate", False,
            [field("age_hours", "Minimum age hours", "integer", False, 24)], lambda a, c: self._cleanup(a, c, False), "Enumerate old temporary files only; no recycle-bin or arbitrary-root deletion.")
        add("maintenance.cleanup", "Clean old temporary files", "maintenance", "operate", True,
            [field("age_hours", "Minimum age hours", "integer", False, 24)], lambda a, c: self._cleanup(a, c, True), "Remove eligible old temporary files, report actual bytes removed and access failures; never follows reparse directories.")
        add("activity.audit", "Privileged operation audit", "activity", "manage", False,
            [field("limit", "Entries", "integer", False, 100)], lambda a, c: self.store.audits(limit=self._int(a["limit"], 1, 1000)), "Durable attributed outcomes recorded by the worker.")
        add("activity.mute", "Mute noncritical alerts", "activity", "configure", True,
            [field("minutes", "Minutes (zero unmutes)", "integer", False, 60)], self._mute, "Bounded mute leaves security/critical alerts deliverable.")
        add("activity.test", "Test agent notification channel", "activity", "operate", False, [], self._test_alert, "Persist and deliver a real test event through the configured agent channel.")
        add("settings.status", "Effective settings and health", "settings", "view", False, [], lambda a, c: {"monitor": self.get_config("monitor"), "running": self._started}, "Secrets and legacy transport credentials are excluded.")
        add("settings.export", "Export redacted monitor configuration", "settings", "configure", False, [], self._export_config, "Safe configuration export excludes runtime state and every credential.")
        add("settings.recovery_export", "Encrypted monitor recovery export", "settings", "manage", True,
            [field("passphrase", "Recovery passphrase", "secret")], self._recovery_export, "AES-GCM encrypted monitor configuration, password-derived key; keep passphrase separately. Backup recovery has its own export operation.")
        add("settings.import", "Import validated monitor configuration", "settings", "configure", True,
            [field("configuration", "Monitor JSON", "string"), field("revision", "Expected revision", "integer")], self._import_config, "Validate the entire configuration atomically before applying; no legacy token imports.")
        add("settings.files", "Set approved file policy", "settings", "configure", True,
            [field("roots", "Absolute approved roots (JSON array)", "string"), field("max_bytes", "Maximum transfer bytes", "integer", False, 268435456), field("revision", "Expected revision", "integer")], self._file_policy, "Change export roots and quotas. Agent credential/state and Windows security material remain denied.")
        for key, default in self._editable_defaults().items():
            kind = "boolean" if isinstance(default, bool) else "integer" if isinstance(default, int) else "string"
            if isinstance(default, (list, dict)):
                continue  # Dedicated automation/security editors own structured settings.
            add("settings." + key, key.replace("_", " ").title(), "settings", "configure", True,
                [field("value", key.replace("_", " "), kind, True, default)],
                lambda a, c, key=key: self._setting(key, a["value"], c), "Typed monitor setting, persisted with revision/last-known-good validation. Enabling accounts, shell, imaging or automatic recovery permits real host changes.")
        for which, capability in (("watch", "configure"), ("keepalive", "execute"), ("svcwatch", "operate")):
            add("automation." + which + ".list", which.title() + " policies", "automation", "view", False, [], lambda a, c, which=which: copy.deepcopy(m.config[which]), "Actual persisted automation configuration.")
            extras = [field("ram_mb", "RAM threshold MiB", "integer", False, 3072)] if which == "watch" else [field("run", "Approved command", "string")] if which == "keepalive" else []
            add("automation." + which + ".set", "Set " + which + " policy", "automation", capability, True,
                [field("name", "Process/service name")] + extras, lambda a, c, which=which: self._automation(which, "set", a, c), "Validated policy applied by the sole monitor; keepalive always requires execution capability even without a custom command.")
            add("automation." + which + ".remove", "Remove " + which + " policy", "automation", capability, True,
                [field("name", "Process/service name")], lambda a, c, which=which: self._automation(which, "remove", a, c), "Remove matching policy without launching or stopping the target.")
        for op, title, fields, capability, destructive, fn in (
            ("status", "Image status/progress", [], "view", False, self._image_status),
            ("list", "List local system images", [], "view", False, lambda a, c: [{"path": p, "size": os.path.getsize(p)} for p in m.image_list_files()]),
            ("tools", "Install/verify Microsoft imaging tool", [], "manage", True, self._image_tools),
            ("volumes", "Available imaging volumes", [], "view", False, self._volumes),
            ("start", "Create system image", [field("target", "Output directory", "path"), field("volumes", "Volume letters or *", "string", False, "*"), field("vss", "Use VSS", "boolean", False, True), field("remote", "Upload destination", "string", False, "")], "manage", True, self._image_start),
            ("upload", "Upload and verify system image", [field("path", "Image file", "path"), field("remote", "rclone destination", "string")], "backup", True, self._image_upload),
            ("verify", "Verify local VHDX structure", [field("path", "Image file", "path")], "manage", False, self._image_verify),
            ("stop", "Stop active imaging/upload", [], "manage", True, self._image_stop),
            ("chart", "Image upload chart", [], "view", False, lambda a, c: self._capture(m.image_upload_chart, c)),
            ("link", "Uploaded image share link", [field("path", "Image filename", "path"), field("remote", "rclone destination", "string")], "backup", False, self._image_link),
            ("recovery", "Image recovery instructions", [], "view", False, self._image_recovery)):
            add("imaging." + op, title, "imaging", capability, destructive, fields, fn, title + ". Keep all physical-disk VHDX files together. Completion is not proof of bootability; perform an isolated VM recovery drill.")
        add("maintenance.update", "Install signed agent release", "maintenance", "manage", True,
            [field("package", "Extracted signed release directory", "path")], self._update, "Verify a pinned-publisher signed release, then hand off to the installed transactional updater. Job remains partial until the external updater commits; never replace running Python source.")
        add("help.operations", "Operation reference", "maintenance", "view", False, [], lambda a, c: self.catalog(), "Effects, permission requirements, confirmation flags and typed input reference for every callable operation.")

    def execute(self, operation, args, context):
        if context.cancel.is_set():
            return {"status": "cancelled", "message": "Cancelled before execution", "data": None}
        descriptor = next((d for d in self.catalog() if d["id"] == operation), None)
        if descriptor is None:
            raise OperationError("unknown_operation", "Unknown operation", 404)
        values = self._validate_args(descriptor, args)
        role, capability = context.actor.get("role", ""), descriptor["capability"]
        internal = role == "internal" and context.actor.get("id") == "agent"
        if not internal and capability not in ROLE_CAPABILITIES.get(role, ()):
            raise OperationError("forbidden", "This device is not authorized for this operation", 403)
        if self.read_only and capability != "view":
            raise OperationError("read_only", "Mutating operations are disabled in read-only mode", 403)
        if operation.startswith("backup."):
            try:
                return self.backup.execute(operation, values, context)
            finally:
                self._sync_backup_config()
        if os.name != "nt" and not operation.startswith(("help.", "settings.", "activity.", "automation.", "monitoring.history")):
            raise OperationError("platform_unavailable", "This operation requires Windows", 503)
        result = self._handlers[operation](values, context)
        return result if isinstance(result, dict) and "status" in result else success(result)

    def _validate_args(self, descriptor, args):
        if not isinstance(args, dict):
            raise OperationError("invalid_arguments", "Arguments must be an object")
        known = {f["name"] for f in descriptor["fields"]}
        if set(args) - known:
            raise OperationError("invalid_arguments", "Unknown input field: " + ", ".join(sorted(set(args) - known)))
        result = {}
        for f in descriptor["fields"]:
            name = f["name"]
            if name not in args:
                if "default" in f:
                    value = copy.deepcopy(f["default"])
                elif f["required"]:
                    raise OperationError("invalid_arguments", "Missing field: " + name)
                else:
                    continue
            else:
                value = args[name]
            kind = f["type"]
            if kind == "boolean" and type(value) is not bool:
                raise OperationError("invalid_arguments", name + " must be boolean")
            if kind == "integer" and type(value) is not int:
                raise OperationError("invalid_arguments", name + " must be integer")
            if kind == "number" and (type(value) not in (int, float) or not float("-inf") < value < float("inf")):
                raise OperationError("invalid_arguments", name + " must be finite number")
            if kind in ("string", "secret", "choice", "path") and (not isinstance(value, str) or "\x00" in value):
                raise OperationError("invalid_arguments", name + " must be text without NUL")
            if kind == "choice" and value not in f["choices"]:
                raise OperationError("invalid_arguments", name + " has an invalid choice")
            if isinstance(value, str) and len(value) > (24 * 1024 * 1024 if name == "content_base64" else 131072):
                raise OperationError("invalid_arguments", name + " is too long")
            result[name] = value
        return result

    @staticmethod
    def _int(value, minimum, maximum):
        if type(value) is not int or not minimum <= value <= maximum:
            raise OperationError("invalid_arguments", f"Value must be an integer between {minimum} and {maximum}")
        return value

    def _pair(self, result):
        ok, data = result
        if not ok:
            raise OperationError("operation_failed", str(data), 409)
        return success(data)

    def _text(self, fn):
        text = self.monitor._panel_text(fn())
        if "[X]" in text:
            raise OperationError("operation_failed", text, 409)
        return success({"text": text})

    def _capture(self, fn, context):
        # Monitor capture is thread-local; serialize matplotlib and legacy report
        # generators, never redirect process-global stdout or replace transports.
        m = self.monitor
        with self._capture_lock:
            previous = getattr(m._CAPTURE, "lines", None)
            old_artifact = getattr(m._CAPTURE, "artifact_sink", None)
            artifacts = []
            def receive(path, name=None, media_type="application/octet-stream"):
                artifact = context.artifact(Path(path), name=name, media_type=media_type)
                artifacts.append(artifact)
                return artifact
            m._CAPTURE.lines = []
            m._CAPTURE.artifact_sink = receive
            try:
                fn()
                text = "\n".join(m._CAPTURE.lines)
            finally:
                m._CAPTURE.lines, m._CAPTURE.artifact_sink = previous, old_artifact
        failed = "[X]" in text
        return {"status": "failed" if failed else "succeeded", "message": text or "Completed", "data": {"text": text}, "artifacts": artifacts}

    def _command(self, command, timeout=60):
        result = subprocess.run(command, capture_output=True, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        output = self.monitor._decode_out(result.stdout)[-65536:]
        error = self.monitor._decode_out(result.stderr)[-16384:]
        if result.returncode:
            raise OperationError("windows_operation_failed", error or output or f"Windows command exited {result.returncode}", 409)
        return success({"exit_code": result.returncode, "stdout": output, "stderr": error})

    def _powershell(self, script, timeout=90):
        return self._command(["powershell.exe", "-NoLogo", "-NonInteractive", "-NoProfile", "-Command", "$ErrorActionPreference='Stop'; " + script], timeout)

    def latest_snapshot(self):
        samples = self.store.metrics(limit=1, detailed=True)
        if not samples:
            raise OperationError("telemetry_unavailable", "The sampler has not collected telemetry yet.", 503)
        return samples[0]

    def snapshot(self):
        mem = psutil.virtual_memory()
        net = psutil.net_io_counters()
        sampled_at = time.monotonic()
        previous = self._network_sample
        self._network_sample = (sampled_at, net.bytes_sent, net.bytes_recv)
        cpu_percent = psutil.cpu_percent(interval=None)
        up_bps = down_bps = None
        if previous is not None and sampled_at > previous[0]:
            elapsed = sampled_at - previous[0]
            if net.bytes_sent >= previous[1]:
                up_bps = (net.bytes_sent - previous[1]) / elapsed
            if net.bytes_recv >= previous[2]:
                down_bps = (net.bytes_recv - previous[2]) / elapsed
        disks, errors = [], []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({"mount": part.mountpoint, "device": part.device, "pct": usage.percent, "used": usage.used, "free": usage.free, "total": usage.total})
            except OSError as exc:
                errors.append({"component": part.mountpoint, "message": str(exc)})
        try:
            sessions = self.monitor.get_rdp_sessions() if os.name == "nt" else []
        except Exception as exc:
            sessions = []
            errors.append({"component": "sessions", "message": str(exc)})
        return {"ts": time.time(), "cpu": {"pct": cpu_percent if previous is not None else None, "cores": psutil.cpu_count()},
                "ram": {"pct": mem.percent, "total": mem.total, "used": mem.used, "avail": mem.available},
                "disks": disks, "nics": [{"name": name, "up": st.isup, "speed_mbps": st.speed} for name, st in psutil.net_if_stats().items()],
                "bytes_sent": net.bytes_sent, "bytes_received": net.bytes_recv,
                "up_bps": up_bps, "down_bps": down_bps,
                "procs": self._processes()[:100], "sessions": sessions, "uptime": time.time() - psutil.boot_time(),
                "protection": {"panic": bool(self.monitor.config.get("panic_active")), "lockdown_until": self.monitor.config.get("lockdown_until", 0)},
                "services": {"monitor": "running" if self._started else "stopped"}, "read_only": self.read_only, "errors": errors}

    def history(self, limit=1000):
        self._int(limit, 1, 5000)
        return self.store.metrics(limit=limit)

    def _temperatures(self, args, context):
        temperatures = self.monitor.get_temps()
        if not temperatures:
            raise OperationError("sensor_unavailable", "No readable WMI/NVIDIA temperature sensor is available", 503)
        return temperatures

    def _chart(self, args, context):
        hours = self._int(args["hours"], 1, 192)
        with self._capture_lock:
            path = self.monitor.make_chart(hours)
        if not path:
            raise OperationError("history_unavailable", "A chart requires matplotlib and at least two measured samples", 409)
        try:
            return {**success(message="Historical chart generated"), "artifacts": [context.artifact(Path(path), media_type="image/png")]}
        finally:
            Path(path).unlink(missing_ok=True)

    def _event_logs(self, args, context):
        count, lines = self.monitor.fetch_system_logs(self._int(args["hours"], 1, 720), self.monitor.LOG_LEVELS[args["level"]])
        if count is None:
            raise OperationError("event_log_unavailable", "Windows event log query failed", 503)
        return {"count": count, "lines": lines}

    def _firewall(self, args, context):
        profiles, ports = self.monitor.get_firewall_report()
        if profiles is None:
            raise OperationError("firewall_unavailable", "Cannot read Windows Firewall state", 503)
        return {"profiles": [{"name": n, "enabled": e} for n, e in profiles], "inbound_allow_ports": ports}

    @staticmethod
    def _host(host):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host):
            raise OperationError("invalid_host", "Enter an IP address or DNS hostname without switches")
        return host

    def _block(self, action, args, context):
        try:
            address = ipaddress.ip_address(args["ip"])
        except ValueError:
            raise OperationError("invalid_ip", "A literal IP address is required")
        m = self.monitor
        protected = set(m.config.get("rdp_allowed_ips", [])) | set(m.get_rdp_ips())
        if action == "block_subnet":
            if address.version != 4:
                raise OperationError("invalid_ip", "Subnet escalation supports IPv4 /24 networks")
            network = ipaddress.ip_network(str(address) + "/24", strict=False)
            if any(ipaddress.ip_address(p) in network for p in protected):
                raise OperationError("lockout_guard", "This subnet contains a trusted or currently connected RDP source", 409)
        elif action == "block" and str(address) in protected:
            raise OperationError("lockout_guard", "Cannot block a trusted or currently connected RDP source", 409)
        fn = {"block": m.block_ip, "unblock": m.unblock_ip, "block_subnet": m.block_subnet}[action]
        return self._pair(fn(str(address)))

    def _forget_ip(self, args, context):
        address = str(ipaddress.ip_address(args["ip"]))
        with self._lock:
            self.monitor.config["learned_ips"].pop(address, None)
            self._save_monitor()
        return success(message="Learned address removed")

    def _rdp_port(self, args, context):
        port = self._int(args["port"], 1024, 65535)
        result = self.monitor.change_rdp_port(port)
        if not result.get("listen"):
            raise OperationError("rdp_port_failed", "Port change failed or rolled back; inspect recovery details: " + json.dumps(result), 409)
        return success(result, f"RDP now listens on port {port}; reconnect using host:{port}")

    def _lockdown(self, args, context):
        m = self.monitor
        if args["enabled"]:
            ok = m.lockdown_start(self._int(args["minutes"], 1, 1440), manual=True)
            if not ok:
                raise OperationError("lockdown_failed", "Could not establish trusted-source lockdown", 409)
        else:
            m.lockdown_release()
            if m.config.get("lockdown_until"):
                raise OperationError("lockdown_failed", "Could not release lockdown rules", 409)
        return m.api_rdp_status()

    def _panic(self, args, context):
        result = self._capture(self.monitor.panic_on if args["enabled"] else self.monitor.panic_off, context)
        if bool(self.monitor.config.get("panic_active")) != args["enabled"]:
            raise OperationError("panic_failed", result["message"], 409)
        return result

    def _trap(self, action, args):
        name = args["name"].strip()
        if not self.monitor.valid_username(name):
            raise OperationError("invalid_account", "Invalid Windows trap username")
        with self._lock:
            items = [n for n in self.monitor.config["trap_users"] if n.lower() != name.lower()]
            if action == "add":
                items.append(name)
            self.monitor.config["trap_users"] = items
            self._save_monitor()
        return items

    def _processes(self):
        rows = []
        for proc in psutil.process_iter(["pid", "name", "create_time", "memory_info", "cpu_percent", "username", "exe"], ad_value=None):
            p = proc.info
            rows.append({"pid": p["pid"], "name": p["name"], "created": p["create_time"], "rss": p["memory_info"].rss if p["memory_info"] else None, "cpu": p["cpu_percent"], "owner": p["username"], "path": p["exe"]})
        return sorted(rows, key=lambda p: p["rss"] or 0, reverse=True)

    def _terminate(self, args, context):
        try:
            proc = psutil.Process(self._int(args["pid"], 1, 0x7fffffff))
            if abs(proc.create_time() - args["created"]) > .001:
                raise OperationError("process_changed", "The PID has been reused; refresh the process list", 409)
            protected = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe", "svchost.exe"}
            if proc.pid == os.getpid() or proc.pid in {p.pid for p in psutil.Process().parents()} or proc.name().lower() in protected or "rdpmonitor" in proc.name().lower():
                raise OperationError("protected_process", "This system/agent process is protected", 409)
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except psutil.TimeoutExpired:
                raise OperationError("process_running", "Termination was requested but the process is still running", 409)
            return success({"pid": args["pid"]}, "Process exited")
        except psutil.NoSuchProcess:
            raise OperationError("process_missing", "The process no longer exists", 404)
        except psutil.AccessDenied:
            raise OperationError("access_denied", "Windows refused process termination", 403)

    def _services(self, args, context):
        return self._powershell("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Json -Compress", 60)

    def _service(self, action, args):
        name = args["name"]
        if not re.fullmatch(r"[A-Za-z0-9_. -]{1,120}", name):
            raise OperationError("invalid_service", "Invalid Windows service name")
        if action != "start" and (name.lower() in {"rpcss", "dcomlaunch", "samss", "eventlog", "mpssvc", "bfe", "plugplay", "power"} or "rdpmonitor" in name.lower()):
            raise OperationError("protected_service", "This system/agent service is protected", 409)
        q = self.monitor._ps_quote(name)
        desired = "Stopped" if action == "stop" else "Running"
        verb = {"start": "Start", "stop": "Stop", "restart": "Restart"}[action]
        return self._powershell(f"{verb}-Service -Name '{q}' -ErrorAction Stop; $s=Get-Service -Name '{q}'; $s.WaitForStatus('{desired}',[TimeSpan]::FromSeconds(45)); $s.Refresh(); $s | Select Name,Status | ConvertTo-Json -Compress")

    def _account(self, action, args):
        m = self.monitor
        if not m.config.get("user_management"):
            raise OperationError("capability_disabled", "Account management is disabled", 403)
        if not m.valid_username(args["name"]):
            raise OperationError("invalid_account", "Invalid Windows account name")
        if action == "rename" and not m.valid_username(args["new_name"]):
            raise OperationError("invalid_account", "Invalid new account name")
        if action == "create":
            self._pair(m.api_user_action("add", args["name"], args["password"]))
            # Resolve built-in groups by SID, not the localized display name.
            group_sid = "S-1-5-32-544" if args["role"] == "admin" else "S-1-5-32-555"
            q = m._ps_quote(args["name"])
            try:
                self._powershell(f"$g=Get-LocalGroup -SID '{group_sid}'; Add-LocalGroupMember -Group $g -Member '{q}' -ErrorAction Stop")
            except OperationError:
                return {"status": "partial", "message": "Account created, but requested group membership failed; no password is returned", "data": {"name": args["name"], "membership_applied": False}}
            return success({"name": args["name"], "role": args["role"]}, "Account and membership created")
        value = args.get("password", args.get("new_name", ""))
        return self._pair(m.api_user_action(action, args["name"], value))

    def _helper(self):
        from .session_helper import SessionHelper
        return SessionHelper(self.data_dir)

    def _session(self, action, args, context):
        if action == "launch" and not self.monitor.config.get("exec_enabled"):
            raise OperationError("capability_disabled", "Program execution is disabled", 403)
        values = dict(args)
        self._int(values["session_id"], 1, 0x7fffffff)
        if action == "launch":
            values["arguments"] = self._json_list(values["arguments"])
        return self._helper().execute(action, values, context)

    def _shell(self, args, context):
        if not self.monitor.config.get("exec_enabled"):
            raise OperationError("capability_disabled", "Shell execution is disabled", 403)
        timeout = self._int(args["timeout"], 1, 300)
        start = time.monotonic()
        # File-backed output avoids pipe deadlocks and unbounded in-memory output.
        with tempfile.TemporaryDirectory(dir=self.data_dir, prefix="shell-") as work:
            out_path, err_path = Path(work) / "stdout", Path(work) / "stderr"
            with out_path.open("wb") as out, err_path.open("wb") as err:
                proc = subprocess.Popen([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", args["command"]], stdout=out, stderr=err, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                cancelled, timed_out, exceeded = False, False, False
                while proc.poll() is None:
                    cancelled = context.cancel.wait(.2)
                    timed_out = time.monotonic() - start > timeout
                    exceeded = out_path.stat().st_size + err_path.stat().st_size > 8 * 1024 * 1024
                    if cancelled or timed_out or exceeded:
                        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                        proc.wait(timeout=15)
                        break
            def bounded(path):
                with path.open("rb") as stream:
                    return self.monitor._decode_out(stream.read(65536))
            result = {"exit_code": proc.returncode, "stdout": bounded(out_path), "stderr": bounded(err_path), "truncated": out_path.stat().st_size > 65536 or err_path.stat().st_size > 65536}
            status = "cancelled" if cancelled else "failed" if timed_out or exceeded or proc.returncode else "succeeded"
            return {"status": status, "message": "Cancelled" if cancelled else "Execution timeout" if timed_out else "Output quota exceeded" if exceeded else f"Shell exited {proc.returncode}", "data": result}

    def _power(self, action, args):
        delay = self._int(args["delay"], 30, 3600)
        if len(args["reason"]) > 400:
            raise OperationError("invalid_arguments", "Power reason must be at most 400 characters")
        result = self._command(["shutdown", "/r" if action == "restart" else "/s", "/t", str(delay), "/c", args["reason"]], 15)
        result["message"] = f"Windows scheduled {action} in {delay} seconds; power.cancel can cancel it"
        return result

    def _editable_defaults(self):
        excluded = {"telegram_token", "telegram_token_enc", "chat_id", "trusted_chat_ids", "trusted_user_ids", "send_backup_file", "backup_file_max_mb", "rdp_port", "rdp_allow_active", "rdp_allow_pre_active", "rdpallow_disabled_rules", "pre_default_inbound", "muted_until", "learned_ips", "lockdown_until", "panic_active", "rdpsched_blocked", "update_url", "update_hash"}
        return {k: copy.deepcopy(v) for k, v in self.monitor.DEFAULT_CONFIG.items() if k not in excluded}

    def get_config(self, domain):
        if domain == "backup":
            return self.backup.get_config()
        if domain == "files":
            return self.store.get_config("files", {"roots": [str(self.exports)], "max_bytes": 268435456})
        if domain not in ("monitor", "monitoring", "security", "automation"):
            raise OperationError("unknown_domain", "Unknown configuration domain", 404)
        with self._lock:
            value = {k: copy.deepcopy(self.monitor.config[k]) for k in self._editable_defaults()}
            record = self.store.get_config("monitor", value)
            # Effective state can be updated by automation; never return secret runtime config.
            return {"revision": record["revision"], "value": value}

    def set_config(self, domain, value, expected_revision, context=None):
        if self.read_only:
            raise OperationError("read_only", "Configuration writes are disabled in read-only mode", 403)
        if domain == "backup":
            result = self.backup.set_config(value, expected_revision, context)
            self._sync_backup_config()
            return result
        if domain == "files":
            if not isinstance(value, dict) or set(value) != {"roots", "max_bytes"}:
                raise OperationError("invalid_configuration", "File policy requires roots and max_bytes")
            roots = value["roots"]
            if not isinstance(roots, list) or not roots or len(roots) > 32 or not all(isinstance(p, str) and Path(p).is_absolute() for p in roots):
                raise OperationError("invalid_configuration", "Supply 1-32 absolute approved roots")
            normalized = {"roots": [str(Path(p).resolve()) for p in roots], "max_bytes": self._int(value["max_bytes"], 1024, 8 * 1024 ** 3)}
            for path in normalized["roots"]:
                self._deny_sensitive(Path(path), directory=True)
            return self.store.set_config("files", normalized, expected_revision)
        if domain not in ("monitor", "monitoring", "security", "automation"):
            raise OperationError("unknown_domain", "Unknown configuration domain", 404)
        validated = self._validate_config(value)
        with self._lock:
            previous = copy.deepcopy(self.monitor.config)
            record = self.store.get_config("monitor", {})
            if record["revision"] != expected_revision:
                raise OperationError("revision_conflict", "Configuration changed; reload before saving", 409)
            self.monitor.config.update(validated)
            if not self.monitor.save_config():
                self.monitor.config = previous
                raise OperationError("configuration_write_failed", "Could not persist monitor configuration; previous effective settings retained", 500)
            try:
                saved = self.store.set_config("monitor", validated, expected_revision)
            except Exception:
                self.monitor.config = previous
                self.monitor.save_config()
                raise
            return saved

    def _validate_config(self, value):
        defaults = self._editable_defaults()
        if not isinstance(value, dict) or set(value) - set(defaults):
            raise OperationError("invalid_configuration", "Unknown or protected monitor configuration fields")
        full = {k: copy.deepcopy(self.monitor.config.get(k, v)) for k, v in defaults.items()}
        full.update(copy.deepcopy(value))
        bounds = {self.monitor.SET_FIELDS[k]: limits for k, limits in self.monitor.SET_BOUNDS.items() if k in self.monitor.SET_FIELDS}
        bounds.update({"spike_cooldown": (30, 86400), "restart_delay_seconds": (30, 3600), "restart_cooldown": (60, 604800), "auto_restart_ram": (50, 100), "failed_login_window": (1, 1440), "weekly_report_hour": (0, 23), "auto_clean_hour": (0, 23)})
        for key, v in full.items():
            d = defaults[key]
            if isinstance(d, bool):
                valid = type(v) is bool
            elif isinstance(d, int):
                valid = type(v) is int
            elif isinstance(d, str):
                valid = isinstance(v, str) and "\x00" not in v and len(v) <= 4096
            else:
                valid = type(v) is type(d)
            if not valid:
                raise OperationError("invalid_configuration", "Invalid type for " + key)
            if key in bounds:
                self._int(v, *bounds[key])
        if max(full["cpu_alert_threshold"], full["ram_alert_threshold"]) > full["danger_threshold"] or full["danger_threshold"] > full["critical_threshold"]:
            raise OperationError("invalid_configuration", "Warning thresholds must not exceed danger, which must not exceed critical")
        if full["failed_logon_types"] not in ("10", "3", "3,10", "10,3"):
            raise OperationError("invalid_configuration", "Failed logon types must be 10, 3, or 3,10")
        self._host(full["ping_target"])
        if full["rdphours"] and not self.monitor._parse_hours(full["rdphours"]):
            raise OperationError("invalid_configuration", "RDP hours must be a range such as 9-23 or 22-6")
        if full["rclone_remote"] and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*:[^\s]*", full["rclone_remote"]):
            raise OperationError("invalid_configuration", "Invalid rclone destination")
        if full["rclone_path"] and not Path(full["rclone_path"]).is_absolute():
            raise OperationError("invalid_configuration", "rclone executable must be an absolute path")
        if len(full["instance_name"]) > 48:
            raise OperationError("invalid_configuration", "Machine display name is limited to 48 characters")
        upload = Path(os.path.expanduser(os.path.expandvars(full["upload_dir"])))
        if not upload.is_absolute():
            raise OperationError("invalid_configuration", "Upload directory must expand to an absolute path")
        self._deny_sensitive(upload, directory=True)
        if any(parent.is_symlink() for parent in (upload,) + tuple(upload.parents)):
            raise OperationError("invalid_configuration", "Upload directory cannot traverse symlinks")
        if not isinstance(full["rdp_allowed_ips"], list) or len(full["rdp_allowed_ips"]) > 256:
            raise OperationError("invalid_configuration", "Invalid RDP allow-list")
        for address in full["rdp_allowed_ips"]:
            try:
                ipaddress.ip_address(address)
            except ValueError:
                raise OperationError("invalid_configuration", "Allow-list entries must be literal IP addresses")
        if not all(isinstance(t, str) and self.monitor.valid_username(t) for t in full["trap_users"]):
            raise OperationError("invalid_configuration", "Invalid trap username")
        for which in ("watch", "keepalive", "svcwatch"):
            if len(full[which]) > 100:
                raise OperationError("invalid_configuration", "Too many automation policies")
            names = set()
            for item in full[which]:
                allowed = {"name", "ram_mb"} if which == "watch" else {"name", "run"} if which == "keepalive" else {"name"}
                if not isinstance(item, dict) or set(item) - allowed or not isinstance(item.get("name"), str) or not re.fullmatch(r"[A-Za-z0-9_. -]{1,120}", item["name"]) or item["name"].lower() in names:
                    raise OperationError("invalid_configuration", "Invalid or duplicate " + which + " policy")
                names.add(item["name"].lower())
                if which == "watch":
                    self._int(item.get("ram_mb"), 64, 1048576)
                if which == "keepalive":
                    if not isinstance(item.get("run", item["name"]), str) or not item.get("run", item["name"]).strip() or len(item.get("run", item["name"])) > 4096:
                        raise OperationError("invalid_configuration", "Invalid approved keepalive command")
                    # Retained dormant policies are safe: runtime independently gates every launch.
        return full

    def _setting(self, key, value, context):
        snapshot = getattr(context, "config_snapshot", None) or {}
        record = snapshot.get("monitor") or self.get_config("monitor")
        return self.set_config("monitor", {key: value}, record["revision"], context)

    def _automation(self, which, action, args, context):
        if which == "keepalive" and action == "set" and not self.monitor.config.get("exec_enabled"):
            raise OperationError("capability_disabled", "Enable execution before approving a keepalive policy", 403)
        items = [copy.deepcopy(i) for i in self.monitor.config[which] if i["name"].lower() != args["name"].lower()]
        if action == "set":
            items.append(dict(args))
        return self._setting(which, items, context)

    def _save_monitor(self):
        if not self.monitor.save_config():
            raise OperationError("configuration_write_failed", "Cannot persist monitor state", 500)

    def _mute(self, args, context):
        minutes = self._int(args["minutes"], 0, 10080)
        self.monitor.config["muted_until"] = time.time() + minutes * 60 if minutes else 0
        self._save_monitor()
        return {"muted_until": self.monitor.config["muted_until"]}

    def _test_alert(self, args, context):
        event = self._emit("notification.test", "RDPMonitor agent notification test", "info", {"actor": context.actor.get("id")})
        return success(event, "Test event persisted to agent event delivery channel")

    def _import_config(self, args, context):
        try:
            value = json.loads(args["configuration"])
        except ValueError:
            raise OperationError("invalid_configuration", "Configuration must be valid JSON")
        return self.set_config("monitor", value, args["revision"], context)

    def _export_config(self, args, context):
        path = self.exports / ("monitor-config-" + uuid.uuid4().hex + ".json")
        try:
            path.write_text(json.dumps(self.get_config("monitor")["value"], indent=2), encoding="utf-8")
            return {**success(message="Redacted monitor configuration exported"), "artifacts": [context.artifact(path, media_type="application/json")]}
        finally:
            path.unlink(missing_ok=True)

    def _recovery_export(self, args, context):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        if len(args["passphrase"]) < 12:
            raise OperationError("weak_passphrase", "Recovery passphrase must contain at least 12 characters")
        salt, nonce = os.urandom(16), os.urandom(12)
        key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(args["passphrase"].encode())
        plaintext = json.dumps({"format": 1, "monitor": self.get_config("monitor")["value"], "created": time.time()}).encode()
        header = b"RDPMONITOR-RECOVERY-1\n"
        encrypted = header + salt + nonce + AESGCM(key).encrypt(nonce, plaintext, header)
        path = self.exports / ("monitor-recovery-" + uuid.uuid4().hex + ".rdpm")
        try:
            path.write_bytes(encrypted)
            return {**success(message="AES-GCM recovery export generated; store passphrase separately"), "artifacts": [context.artifact(path)]}
        finally:
            path.unlink(missing_ok=True)

    @staticmethod
    def _json_list(text):
        try:
            value = json.loads(text)
        except ValueError:
            raise OperationError("invalid_arguments", "Expected a JSON string array")
        if not isinstance(value, list) or not all(isinstance(s, str) and "\x00" not in s for s in value):
            raise OperationError("invalid_arguments", "Expected a JSON string array")
        return value

    def _file_policy(self, args, context):
        return self.set_config("files", {"roots": self._json_list(args["roots"]), "max_bytes": args["max_bytes"]}, args["revision"], context)

    def _deny_sensitive(self, path, directory=False):
        path = path.resolve()
        protected = [self.monitor_dir, self.data_dir / "backup", self.data_dir / "legacy", self.data_dir / "artifacts", self.data_dir / "certificates", self.data_dir / "pki", self.data_dir / "session-artifacts", self.root]
        windir = Path(os.environ.get("SystemRoot", "C:/Windows"))
        protected += [windir / "System32" / "config", windir / "NTDS", windir / "System32" / "Microsoft" / "Protect"]
        for root in protected:
            root = root.resolve()
            if path == root or root in path.parents or (directory and path in root.parents):
                raise OperationError("export_denied", "Agent credentials, source and security state are not an approved file export", 403)
        if self.data_dir == path or path.parent == self.data_dir:
            if path != self.exports:
                raise OperationError("export_denied", "Agent private state cannot be exported", 403)
        if any(part.lower() in (".ssh", ".aws", ".azure", "credentials", "protect") for part in path.parts) or path.suffix.lower() in (".key", ".pfx", ".p12"):
            raise OperationError("export_denied", "Credential material cannot be exported through file operations", 403)

    def _approved(self, raw, must_exist=True):
        path = Path(os.path.expandvars(os.path.expanduser(raw)))
        if not path.is_absolute():
            raise OperationError("invalid_path", "An absolute path is required")
        # Refuse reparse/symlink traversal, including parent junctions.
        for parent in (path,) + tuple(path.parents):
            try:
                st = parent.lstat()
                if parent.is_symlink() or getattr(st, "st_file_attributes", 0) & 0x400:
                    raise OperationError("reparse_denied", "File operations cannot traverse reparse points", 403)
            except FileNotFoundError:
                if must_exist and parent == path:
                    raise OperationError("file_missing", "Path does not exist", 404)
        path = path.resolve()
        self._deny_sensitive(path)
        roots = [Path(r).resolve() for r in self.get_config("files")["value"]["roots"]]
        if not any(path == root or root in path.parents for root in roots):
            raise OperationError("export_denied", "Path is outside configured approved roots", 403)
        return path

    def _browse(self, args, context):
        path = self._approved(args["path"])
        if not path.is_dir():
            raise OperationError("not_directory", "Select a directory")
        rows = []
        for child in path.iterdir():
            if context.cancel.is_set():
                return {"status": "cancelled", "message": "Browse cancelled", "data": rows}
            try:
                approved = self._approved(str(child))
                st = approved.stat()
                rows.append({"name": child.name, "path": str(child), "directory": child.is_dir(), "size": st.st_size, "modified": st.st_mtime})
            except (OSError, OperationError):
                continue
            if len(rows) >= 2000:
                return {"status": "partial", "message": "Directory listing capped at 2000 entries", "data": rows}
        return {"path": str(path), "items": sorted(rows, key=lambda r: (not r["directory"], r["name"].lower()))}

    def _download(self, args, context):
        path = self._approved(args["path"])
        if not path.is_file():
            raise OperationError("file_missing", "Select an existing regular file", 404)
        if path.stat().st_size > self.get_config("files")["value"]["max_bytes"]:
            raise OperationError("quota_exceeded", "File exceeds transfer quota", 413)
        return {**success(message="Artifact copied into protected artifact storage"), "artifacts": [context.artifact(path, media_type=mimetypes.guess_type(path.name)[0] or "application/octet-stream")]}


    def _largest(self, args, context):
        import heapq
        root = self._approved(args["path"])
        limit, maximum = self._int(args["limit"], 1, 100), self._int(args["max_entries"], 1, 1000000)
        heap, seen, denied = [], 0, 0
        for directory, dirs, files in os.walk(root, followlinks=False):
            safe_dirs = []
            for name in dirs:
                try:
                    self._approved(str(Path(directory) / name))
                    safe_dirs.append(name)
                except (OperationError, OSError):
                    denied += 1
            dirs[:] = safe_dirs
            for name in files:
                if context.cancel.is_set():
                    return {"status": "cancelled", "message": "Scan cancelled", "data": {"files": sorted(heap, reverse=True), "scanned": seen}}
                try:
                    path = self._approved(str(Path(directory) / name))
                    size = path.stat().st_size
                    item = (size, str(path))
                    if len(heap) < limit:
                        heapq.heappush(heap, item)
                    elif item > heap[0]:
                        heapq.heapreplace(heap, item)
                except (OperationError, OSError):
                    denied += 1
                seen += 1
                if seen % 500 == 0:
                    context.progress(None, f"Scanned {seen} files")
                if seen >= maximum:
                    return {"status": "partial", "message": "Configured scan bound reached", "data": {"files": sorted(heap, reverse=True), "scanned": seen, "skipped": denied}}
        return {"files": [{"size": size, "path": path} for size, path in sorted(heap, reverse=True)], "scanned": seen, "skipped": denied}

    def _export_logs(self, args, context):
        with tempfile.TemporaryDirectory(dir=self.data_dir, prefix="event-export-") as work:
            work = Path(work)
            scopes = ["System", "Application"] if args["scope"] == "all" else [args["scope"].capitalize()]
            failed, files = [], []
            query = "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"
            for log in scopes:
                if context.cancel.is_set():
                    return {"status": "cancelled", "message": "Export cancelled", "data": None}
                path = work / (log + ".evtx")
                try:
                    self._command(["wevtutil", "epl", log, str(path), "/q:" + query, "/ow:true"], 300)
                    files.append(path)
                except OperationError as exc:
                    failed.append({"log": log, "message": str(exc)})
            if not files:
                raise OperationError("export_failed", "Windows refused all requested event log exports", 409)
            archive = work / "windows-errors-7d.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
                for path in files:
                    bundle.write(path, path.name)
            artifact = context.artifact(archive, media_type="application/zip")
            return {"status": "partial" if failed else "succeeded", "message": "Event log bundle generated", "data": {"failed": failed}, "artifacts": [artifact]}

    def _export_dump(self, args, context):
        path = Path(args["path"]).resolve()
        candidates = {Path(p).resolve() for p, size, t in self.monitor._crash_dumps()}
        if path not in candidates or path.is_symlink():
            raise OperationError("export_denied", "Only an inventoried crash dump may be exported", 403)
        if path.stat().st_size > self.get_config("files")["value"]["max_bytes"]:
            raise OperationError("quota_exceeded", "Dump exceeds artifact quota", 413)
        return {**success(message="Sensitive crash dump exported"), "artifacts": [context.artifact(path)]}

    def _agent_log(self, args, context):
        path = Path(self.monitor.LOG_FILE)
        if not path.exists():
            return {"text": "", "available": False}
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - 65536))
            return {"text": stream.read(65536).decode("utf-8", "replace"), "available": True}

    def _export_agent_log(self, args, context):
        path = Path(self.monitor.LOG_FILE)
        if not path.is_file():
            raise OperationError("log_unavailable", "No monitor diagnostic log exists yet", 404)
        return {**success(message="Agent log exported"), "artifacts": [context.artifact(path, media_type="text/plain")]}

    def _cleanup(self, args, context, remove):
        cutoff = time.time() - self._int(args["age_hours"], 1, 8760) * 3600
        roots = {Path(tempfile.gettempdir()).resolve(), (Path(os.environ.get("SystemRoot", "C:/Windows")) / "Temp").resolve()}
        count, total, errors = 0, 0, 0
        preview = []
        for root in roots:
            for directory, dirs, files in os.walk(root, followlinks=False):
                directory = Path(directory)
                dirs[:] = [d for d in dirs if not (directory / d).is_symlink() and not getattr((directory / d).stat(), "st_file_attributes", 0) & 0x400 and self.data_dir not in (directory / d).resolve().parents and (directory / d).resolve() != self.data_dir]
                for name in files:
                    if context.cancel.is_set():
                        return {"status": "cancelled", "message": "Cleanup cancelled", "data": {"files": count, "bytes": total, "errors": errors}}
                    path = directory / name
                    try:
                        st = path.lstat()
                        if path.is_symlink() or getattr(st, "st_file_attributes", 0) & 0x400 or st.st_mtime >= cutoff or self.data_dir in path.resolve().parents:
                            continue
                        if remove:
                            path.unlink()
                        count += 1
                        total += st.st_size
                        if len(preview) < 200:
                            preview.append(str(path))
                    except OSError:
                        errors += 1
        return {"status": "partial" if errors else "succeeded", "message": "Old temporary files removed" if remove else "Cleanup preview; nothing deleted", "data": {"files": count, "bytes": total, "errors": errors, "preview": preview}}

    def _image_status(self, args, context):
        state = {k: copy.deepcopy(v) for k, v in self.monitor._image_state.items() if k != "proc"}
        proc = self.monitor._image_state.get("proc")
        state["running"] = proc is not None and proc.poll() is None
        return state

    def _volumes(self, args, context):
        return [{"device": p.device, "mount": p.mountpoint, "filesystem": p.fstype, "total": psutil.disk_usage(p.mountpoint).total, "used": psutil.disk_usage(p.mountpoint).used, "free": psutil.disk_usage(p.mountpoint).free} for p in psutil.disk_partitions() if p.fstype]

    def _verify_microsoft(self, path):
        q = self.monitor._ps_quote(str(path))
        self._powershell(f"$s=Get-AuthenticodeSignature -LiteralPath '{q}'; if($s.Status -ne 'Valid' -or !$s.SignerCertificate -or $s.SignerCertificate.Subject -notmatch '(?:^|,\\s*)CN=Microsoft Corporation(?:,|$)'){{throw 'Microsoft Authenticode signature required'}}; $s.Status.ToString()", 60)

    def _image_tools(self, args, context):
        path = self.monitor._find_disk2vhd() or self.monitor._download_disk2vhd()
        if not path:
            raise OperationError("tool_install_failed", "Cannot download Microsoft Disk2vhd", 503)
        self._verify_microsoft(path)
        return {"path": path, "signature": "Microsoft Authenticode valid"}

    def _image_start(self, args, context):
        m = self.monitor
        if not m.config.get("image_enabled"):
            raise OperationError("capability_disabled", "System imaging is disabled", 403)
        if m._image_state.get("phase") in ("imaging", "uploading"):
            raise OperationError("image_busy", "An image/upload is already active", 409)
        target = Path(args["target"])
        if not target.is_absolute() or not target.is_dir():
            raise OperationError("invalid_path", "Select an existing absolute output directory")
        if not re.fullmatch(r"\*|(?:[A-Za-z]:\s*)+", args["volumes"]):
            raise OperationError("invalid_volumes", "Select * or volume letters such as C: D:")
        if args["remote"] and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*:[^\s]*", args["remote"]):
            raise OperationError("invalid_remote", "Invalid rclone destination")
        # Disable engine auto-upload here; the backend owns a single final-result job.
        previous_remote = m.config.get("rclone_remote", "")
        m.config["rclone_remote"] = ""
        try:
            started = self._capture(lambda: m.image_start(remote=None, watch=False, volumes=args["volumes"], target_dir=str(target), vss=args["vss"]), context)
            proc = m._image_state.get("proc")
            if started["status"] == "failed" or m._image_state.get("phase") != "imaging" or proc is None:
                raise OperationError("image_start_failed", started["message"], 409)
            while proc.poll() is None:
                if context.cancel.wait(1):
                    proc.kill()
                    proc.wait(timeout=30)
                    m._image_state["phase"] = None
                    m._persist_image_state()
                    return {"status": "cancelled", "message": "Imaging cancelled; partial files retained", "data": self._image_status({}, context)}
                context.progress(None, m.image_progress_line())
            finished = self._capture(lambda: m._image_finish(upload_sync=True), context)
            paths = m._image_state.get("vhdx_files", [])
            if proc.returncode != 0 or not paths or finished["status"] == "failed":
                return {"status": "failed", "message": finished["message"], "data": self._image_status({}, context)}
            verified = []
            for path in paths:
                verified.append(self._image_verify({"path": path}, context))
            if args["remote"]:
                upload = self._capture(lambda: m._upload_image_set(paths, args["remote"]), context)
                if upload["status"] == "failed":
                    return {"status": "partial", "message": "Image created but upload failed; local files retained", "data": {"files": paths, "upload": upload}}
            return success({"files": paths, "verification": verified, "recovery_drill_required": True}, "Image set created and structurally checked; perform an isolated boot/recovery drill")
        finally:
            m.config["rclone_remote"] = previous_remote

    def _known_image(self, raw):
        path = Path(raw).resolve()
        known = {Path(p).resolve() for p in self.monitor.image_list_files()}
        known.update(Path(p).resolve() for p in self.monitor._image_state.get("vhdx_files", []))
        if path not in known or not path.is_file() or path.is_symlink() or path.suffix.lower() != ".vhdx":
            raise OperationError("image_not_found", "Select an inventoried VHDX image", 404)
        return path

    def _image_upload(self, args, context):
        path = self._known_image(args["path"])
        remote = args["remote"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*:[^\s]*", remote):
            raise OperationError("invalid_remote", "Invalid rclone destination")
        if self.monitor._image_state.get("phase") in ("imaging", "uploading"):
            raise OperationError("image_busy", "An image/upload is already active", 409)
        # Engine upload returns its actual exit result; cancellation is observed by
        # a watcher which only terminates this job's current upload process.
        done = threading.Event()
        def cancel_watch():
            while not done.wait(.2):
                if context.cancel.is_set():
                    proc = self.monitor._image_state.get("proc")
                    if self.monitor._image_state.get("phase") == "uploading" and proc and proc.poll() is None:
                        proc.kill()
                    return
        watcher = threading.Thread(target=cancel_watch, daemon=True)
        watcher.start()
        try:
            result = self._capture(lambda: self.monitor._upload_job(str(path), remote, delete_after=False), context)
            if context.cancel.is_set():
                result["status"], result["message"] = "cancelled", "Upload cancelled; remote may retain a partial file"
            elif not self.monitor._verify_remote_image(str(path), remote):
                result["status"], result["message"] = "failed", "Remote image size verification failed; local copy retained"
            return result
        finally:
            done.set()
            watcher.join(timeout=1)

    def _image_verify(self, args, context):
        path = self._known_image(args["path"])
        with path.open("rb") as stream:
            signature = stream.read(8)
            if signature != b"vhdxfile":
                raise OperationError("invalid_image", "File does not have a valid VHDX file identifier", 409)
            stream.seek(64 * 1024)
            header1 = stream.read(4)
            stream.seek(128 * 1024)
            header2 = stream.read(4)
        if b"head" not in (header1, header2):
            raise OperationError("invalid_image", "VHDX redundant headers are missing", 409)
        # Windows Virtual Disk API validates metadata without attaching/mounting
        # or writing to the volume. Get-VHD is optional Hyper-V; OpenVirtualDisk
        # is available on supported Windows desktop/server editions.
        import ctypes
        class GUID(ctypes.Structure):
            _fields_ = [("a", ctypes.c_uint32), ("b", ctypes.c_uint16), ("c", ctypes.c_uint16), ("d", ctypes.c_ubyte * 8)]
        class StorageType(ctypes.Structure):
            _fields_ = [("DeviceId", ctypes.c_uint32), ("VendorId", GUID)]
        class Parameters(ctypes.Structure):
            _fields_ = [("Version", ctypes.c_uint32), ("RWDepth", ctypes.c_uint32)]
        storage = StorageType(3, GUID(0xec984aec, 0xa0f9, 0x47e9, (ctypes.c_ubyte * 8)(0x90, 0x1f, 0x71, 0x41, 0x5a, 0x66, 0x34, 0x5b)))
        params, handle = Parameters(1, 1), ctypes.c_void_p()
        api = ctypes.WinDLL("virtdisk", use_last_error=True)
        api.OpenVirtualDisk.argtypes = [ctypes.POINTER(StorageType), ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(Parameters), ctypes.POINTER(ctypes.c_void_p)]
        rc = api.OpenVirtualDisk(ctypes.byref(storage), str(path), 0x00080000, 0, ctypes.byref(params), ctypes.byref(handle))
        if rc:
            raise OperationError("invalid_image", f"Windows Virtual Disk validation failed (error {rc})", 409)
        ctypes.windll.kernel32.CloseHandle(handle)
        return {"path": str(path), "size": path.stat().st_size, "vhdx_identifier": True, "windows_metadata_open": True, "boot_tested": False}

    def _image_stop(self, args, context):
        proc = self.monitor._image_state.get("proc")
        if not proc or proc.poll() is not None:
            raise OperationError("image_not_running", "No imaging/upload process is running", 409)
        proc.kill()
        proc.wait(timeout=30)
        self.monitor._image_state["phase"] = None
        self.monitor._persist_image_state()
        return success(message="Process stopped; partial local/remote files were retained")

    def _image_link(self, args, context):
        name = Path(args["path"]).name
        link = self.monitor._rclone_link(args["remote"], name)
        if not link:
            raise OperationError("link_unavailable", "The remote did not return a share link", 409)
        return {"url": link}

    def _image_recovery(self, args, context):
        return {"files": self.monitor._image_state.get("vhdx_files", []), "instructions": ["Keep every VHDX in the image set, plus offline recovery keys and matching firmware settings.", "Verify the VHDX files and restore to an isolated VM with matching BIOS/UEFI boot mode and disk controller.", "Attach all physical-disk images to the VM in source disk order. Do not attach writable source-production images directly; work from copies.", "Boot in isolation, check Windows, accounts, applications and data; record the drill outcome. Metadata verification alone does not establish bootability.", "For bare-metal recovery, boot trusted Windows recovery media and restore/copy partitions to suitably sized disks; check BCD/EFI boot configuration before reconnecting networking."]}

    def _update(self, args, context):
        package = Path(args["package"])
        if not package.is_absolute() or not package.is_dir():
            raise OperationError("invalid_package", "Select an extracted local signed release directory")
        deployment_file = self.data_dir / "deployment.json"
        try:
            deployment = json.loads(deployment_file.read_text(encoding="utf-8"))
            release = Path(deployment["release"])
        except (OSError, ValueError, KeyError, TypeError):
            raise OperationError("updater_unavailable", "Installed deployment identity is missing; repair this installation", 503)
        script = release / "scripts" / "update-agent.ps1"
        if not script.is_file():
            raise OperationError("updater_unavailable", "Installed release updater is missing; repair this installation", 503)
        command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                   "AllSigned", "-File", str(script), "-Package", str(package)]
        self._command(command + ["-VerifyOnly"], 600)
        if context.cancel.is_set():
            return {"status": "cancelled", "message": "Update cancelled after verification, before installation", "data": None}
        flags = getattr(subprocess, "DETACHED_PROCESS", 8) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 512)
        process = subprocess.Popen(command, cwd=script.parent, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=flags, close_fds=True)
        return {"status": "partial", "message": "Signed release verified; external updater owns service restart and rollback. Installation completion is not yet known.",
                "data": {"updater_pid": process.pid, "state_file": str(self.data_dir / "update-state.json"), "restart_pending": True}}
