"""Agent-owned backup configuration, durable scheduling and recovery adapters.

No UI or Telegram module is imported here. Existing ZIP/restic/rclone engines are
shared with legacy recovery consumers, but only the agent submits scheduled work.
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from zoneinfo import ZoneInfo

from .contracts import OperationError

_ENGINE_LOCK = threading.RLock()
_SECRET_KEYS = {("backup", "archive_password"), ("restic", "password"),
                ("monitoring", "healthcheck_url"), ("monitoring", "heartbeat_url")}
_SECTIONS = ("backup", "schedule", "cloud", "restic", "monitoring", "restore_drill")
_STATUS = {"ok": "succeeded", "warn": "partial", "partial": "partial",
           "error": "failed", "cancelled": "cancelled", "busy": "failed"}


def _field(name, kind="string", required=False, default=None, choices=None, help=None):
    value = {"name": name, "label": name.replace("_", " ").title(),
             "type": kind, "required": required}
    if default is not None:
        value["default"] = default
    if choices is not None:
        value["choices"] = choices
    if help:
        value["help"] = help
    return value


def _result(message, data=None, status="succeeded"):
    return {"status": status, "message": message, "data": data}


class BackupManager:
    def __init__(self, root: Path, data_dir: Path, emit):
        self.root, self.data_dir = Path(root), Path(data_dir)
        self.home = self.data_dir / "backup"
        self.home.mkdir(parents=True, exist_ok=True)
        engine_path = str(self.root / "backup" / "app")
        if engine_path not in sys.path:
            sys.path.insert(0, engine_path)
        import backup_engine
        import cloud_uploader
        import config_manager
        import logger_utils
        import restic_engine
        import restore
        import scheduler
        import secrets_store
        self.zip, self.cloud, self.config = backup_engine, cloud_uploader, config_manager
        self.restic, self.restore, self.scheduler = restic_engine, restore, scheduler
        self.secrets = secrets_store
        self.emit = emit
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        self._submit = None
        self._active_cancel = None
        self._active = None
        self._started = dt.datetime.now(dt.timezone.utc)
        self._last_heartbeat = 0.0
        self._last_stale = 0.0
        self._bind_paths()
        with _ENGINE_LOCK:
            self._migrate_legacy()
            self._cfg = self.config.load_config()
            if not self.config.LOAD_OK:
                raise OperationError("backup_config_invalid", "Backup configuration or protected secrets cannot be read; repair migration before starting", 503)
            self._cfg["cloud"]["rclone_config"] = str(self.home / "rclone" / "rclone.conf")
            self._cfg["schedule"].setdefault("timezone", "local")
            self._cfg["schedule"].setdefault("catch_up", True)
            self._validate(self._cfg)
            for name in ("logs", "control", "local_backups", "restores", "rclone", "restic"):
                (self.home / name).mkdir(exist_ok=True)
            self.config.harden_path(str(self.home), directory=True)

    def _bind_paths(self):
        self.config.CONFIG_FILE = str(self.home / "config.json")
        self.zip.TOOL_ROOT = str(self.home)
        self.zip.BACKUP_DIR = str(self.home / "local_backups")
        self.zip.LOCAL_STATE_FILE = str(self.home / "logs" / "local_state.json")
        self.scheduler.STATE_FILE = str(self.home / "logs" / "last_run.json")
        self.scheduler.RESULT_FILE = str(self.home / "control" / "last_result.json")
        self.cloud.RCLONE_DIR = str(self.home / "rclone")
        self.cloud.RCLONE_CONFIG = str(self.home / "rclone" / "rclone.conf")
        self.restic.RESTIC_DIR = str(self.home / "restic")
        import logger_utils
        logger_utils.LOG_DIR = str(self.home / "logs")

    def _migrate_legacy(self):
        # Packaging normally performs this under the original account. The fallback
        # only fills absent targets and never runs legacy processes or overwrites data.
        if (self.home / "config.json").exists():
            return
        legacy = self.root / "backup"
        for name in ("config.json", "local_backups", "logs", "control", "rclone", "restic"):
            source, dest = legacy / name, self.home / name
            if not source.exists() or dest.exists():
                continue
            if source.is_dir():
                shutil.copytree(source, dest, ignore=shutil.ignore_patterns("*.exe", "*.dll", "cache", "request.json", "processing-*.json"))
            else:
                shutil.copy2(source, dest)
        source = legacy / "config.json"
        if source.exists():
            manifest = {"source": str(legacy), "time": dt.datetime.now(dt.timezone.utc).isoformat(),
                        "config_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
            self._atomic_json(self.home / "migration.json", manifest)

    @staticmethod
    def _atomic_json(path, value):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _snapshot(self):
        with self._lock:
            return copy.deepcopy(self._cfg)

    def job_snapshot(self):
        """Private effective settings for DPAPI-protected durable job storage only."""
        cfg = self._snapshot()
        # Retired transport credentials are never needed by the native engine.
        cfg["telegram"] = copy.deepcopy(self.config.DEFAULT_CONFIG["telegram"])
        return {"revision": self.config.config_revision(cfg), "value": cfg}

    def get_config(self):
        cfg = self._snapshot()
        value = {section: cfg[section] for section in _SECTIONS}
        for section, key in _SECRET_KEYS:
            value[section][key] = "***" if value[section].get(key) else ""
        # Credentials and legacy transport tokens never leave their protected files.
        value["cloud"].pop("rclone_config", None)
        return {"revision": self.config.config_revision(cfg), "value": value}

    def _validate(self, cfg):
        self.config._validate_structure(cfg)
        for section in _SECTIONS:
            if not isinstance(cfg.get(section), dict):
                raise ValueError("Missing configuration section: " + section)
        b, s, r, c = cfg["backup"], cfg["schedule"], cfg["restic"], cfg["cloud"]
        if b.get("engine") not in ("zip", "restic"):
            raise ValueError("Backup engine must be zip or restic")
        if s.get("mode") not in ("daily", "interval", "times"):
            raise ValueError("Schedule mode must be daily, interval or times")
        for value in [s.get("time", "03:00")] + s.get("times", []):
            if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
                raise ValueError("Schedule times must use HH:MM (24 hours)")
        if s.get("mode") == "times" and not s.get("times"):
            raise ValueError("Multiple-time schedule needs at least one time")
        zone = s.get("timezone", "local")
        if zone != "local":
            ZoneInfo(zone)
        bounds = [(b, "keep_local_copies", 1, 10000), (b, "exclude_max_size_mb", 0, 100000000),
                  (b, "hook_timeout_minutes", 1, 1440), (s, "interval_hours", 1, 87600),
                  (s, "retry_count", 1, 100), (s, "retry_delay_minutes", 1, 10080),
                  (c, "retention_days", 0, 365000), (r, "keep_daily", 0, 100000),
                  (r, "keep_weekly", 0, 100000), (r, "keep_monthly", 0, 100000),
                  (cfg["restore_drill"], "interval_days", 1, 36500)]
        for section, key, minimum, maximum in bounds:
            val = section.get(key)
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not minimum <= val <= maximum or int(val) != val:
                raise ValueError(f"{key} must be an integer from {minimum} to {maximum}")
        if sum(r[k] for k in ("keep_daily", "keep_weekly", "keep_monthly")) == 0:
            raise ValueError("At least one restic retention period must be positive")
        for section in _SECTIONS:
            for key, default in self.config.DEFAULT_CONFIG[section].items():
                if isinstance(default, bool) and not isinstance(cfg[section].get(key), bool):
                    raise ValueError(section + "." + key + " must be boolean")
        for remote in c.get("remotes", []):
            if not re.fullmatch(r"[A-Za-z0-9_-]+:?", remote):
                raise ValueError("Choose a named rclone remote, not an arbitrary path")
        folder = c.get("remote_folder", "")
        if not isinstance(folder, str) or any(p in ("..", ".") for p in folder.replace("\\", "/").split("/")) or ":" in folder:
            raise ValueError("Cloud folder must be a relative path without traversal")
        for key in ("pre_command", "post_command"):
            if not isinstance(b.get(key), str):
                raise ValueError(key + " must be a string")
        for key in ("healthcheck_url", "heartbeat_url"):
            value = cfg["monitoring"].get(key, "")
            if value and urllib.parse.urlparse(value).scheme != "https":
                raise ValueError("External monitoring URLs require HTTPS")
        hours = cfg["monitoring"].get("alert_after_hours", 26)
        if isinstance(hours, bool) or not isinstance(hours, (int, float)) or not 0 <= hours <= 87600:
            raise ValueError("Stale backup alert hours must be between 0 and 87600")

    def set_config(self, value, expected_revision, context=None):
        if not isinstance(value, dict):
            raise OperationError("invalid_config", "Backup configuration must be an object")
        with self._lock:
            if expected_revision != self.config.config_revision(self._cfg):
                raise OperationError("revision_conflict", "Backup settings changed; reload before saving", 409)
            candidate = copy.deepcopy(self._cfg)
            try:
                for section, updates in value.items():
                    if section not in _SECTIONS or not isinstance(updates, dict):
                        raise ValueError("Unknown configuration section: " + section)
                    allowed = set(self.config.DEFAULT_CONFIG[section]) | ({"timezone", "catch_up"} if section == "schedule" else set())
                    for key, item in updates.items():
                        if key.endswith("_configured"):
                            continue
                        if (section, key) in _SECRET_KEYS:
                            if item == "***":
                                continue
                            if not isinstance(item, str):
                                raise ValueError("Write-only secrets must be strings")
                            candidate[section][key] = item
                            continue
                        if key not in allowed or (section == "cloud" and key == "rclone_config"):
                            raise ValueError("Unknown or managed setting: " + section + "." + key)
                        candidate[section][key] = copy.deepcopy(item)
                self._validate(candidate)
                self._save(candidate)
            except ValueError as error:
                raise OperationError("invalid_config", str(error)) from error
        return self.get_config()

    def _save(self, candidate):
        # The settings lock, not the long-running engine lock, protects publication.
        # Running jobs already own deep copies; saving cannot change their inputs.
        if not self.secrets.is_available() and any(candidate[s].get(k) for s, k in _SECRET_KEYS):
            raise OperationError("secret_storage_unavailable", "Backup secrets require Windows DPAPI", 503)
        self.config.save_config(candidate)
        self._cfg = candidate

    def set_submitter(self, callback):
        self._submit = callback

    def start(self, read_only=False):
        if read_only or self._thread is not None:
            return
        if self._submit is None:
            raise OperationError("scheduler_unbound", "Backup scheduler requires the durable agent submitter", 503)
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="agent-backup-schedules", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._active_cancel is not None:
            self._active_cancel.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    def catalog(self):
        def op(name, title, fields=(), capability="backup", destructive=False, description=""):
            return {"id": "backup." + name, "title": title, "section": "backups",
                    "description": description or title, "capability": capability,
                    "destructive": destructive, "fields": list(fields)}
        operations = [
            op("status", "Backup worker status", capability="view"),
            op("config", "Read backup settings (secrets redacted)", capability="view"),
            op("run", "Run backup", [_field("scheduled", "boolean", False, False)], description="Captures an immutable settings revision; hooks execute as the worker identity; uses configured retention and destinations."),
            op("archives", "List ZIP archives and restic snapshots", capability="view"),
            op("progress", "Read current backup progress", capability="view"),
            op("cancel", "Cancel active backup or recovery"),
            op("restore", "Restore and verify isolated copy", [_field("engine", "choice", True, "zip", ["zip", "restic"]), _field("archive", help="ZIP archive name, or restic snapshot ID")]),
            op("drill", "Perform real isolated restore drill", [_field("keep", "boolean", False, False)], description="Restores newest ZIP/snapshot, verifies actual content, removes only its own temporary directory unless keep is selected."),
            op("archive.download", "Download backup archive", [_field("archive", required=True)], capability="files"),
            op("archive.delete", "Delete local archive", [_field("archive", required=True)], destructive=True),
            op("repository.init", "Initialize configured restic repository", destructive=True, description="Creates an encrypted repository with the saved write-only password. Does not replace an existing repository."),
            op("repository.check", "Verify repository data"),
            op("repository.prune", "Apply restic retention", destructive=True),
            op("tools.status", "Inspect backup tool versions", capability="view"),
            op("tools.install", "Install verified backup binary", [_field("tool", "choice", True, "restic", ["restic", "rclone"]), _field("url", required=True), _field("sha256", required=True), _field("version", required=True)], capability="manage", destructive=True, description="HTTPS official release, mandatory SHA-256 and executable version verification; atomic install into protected agent data."),
            op("cloud.remotes", "List configured cloud remotes", capability="view"),
            op("cloud.providers", "List cloud provider onboarding options", capability="view"),
            op("cloud.create", "Configure provider credentials", [_field("name", required=True), _field("provider", required=True), _field("options", "secret", True, help="Provider option JSON, including credentials/OAuth token; write-only and never returned")], capability="configure", destructive=True),
            op("cloud.oauth", "Authorize cloud provider", [_field("provider", required=True), _field("client_id"), _field("client_secret", "secret")], capability="configure", description="Returns rclone's explicit authorization URL. Open it in an administrator browser; complete using cloud.create with the issued token; never launches a SYSTEM browser."),
            op("cloud.remove", "Remove cloud remote credentials", [_field("name", required=True)], capability="configure", destructive=True),
            op("cloud.test", "Verify cloud write/read access", [_field("remote", required=True)], description="Writes random probe bytes under the selected backup folder, downloads and hashes them, then deletes only that probe."),
            op("cloud.archives", "List cloud backup archives", capability="view"),
            op("secrets.update", "Update write-only backup secrets", [_field("archive_password", "secret"), _field("repository_password", "secret"), _field("healthcheck_url", "secret"), _field("heartbeat_url", "secret"), _field("clear", help="Comma-separated secret field names to explicitly erase")], capability="configure", destructive=True),
            op("recovery.export", "Export portable encrypted recovery configuration", [_field("passphrase", "secret", True)], capability="manage", destructive=True),
            op("recovery.import", "Import portable encrypted recovery configuration", [_field("bundle", "secret", True, help="Base64 recovery bundle"), _field("passphrase", "secret", True)], capability="manage", destructive=True),
        ]
        cfg = self._snapshot()
        for section in _SECTIONS:
            fields = []
            for key, value in cfg[section].items():
                if (section, key) in _SECRET_KEYS or key == "rclone_config":
                    continue
                choices = {"engine": ["zip", "restic"], "mode": ["daily", "interval", "times"]}.get(key)
                kind = "choice" if choices else "boolean" if isinstance(value, bool) else "integer" if isinstance(value, int) else "number" if isinstance(value, float) else "string"
                fields.append(_field(key, kind, default="\n".join(value) if isinstance(value, list) else value,
                                     choices=choices, help="One entry per line" if isinstance(value, list) else None))
            operations.append(op(section + ".set", "Configure " + section.replace("_", " "), fields + [_field("revision", "integer", True, self.config.config_revision(cfg))], capability="execute" if section == "backup" else "configure", destructive=True,
                                 description="Revision-checked settings update. Hooks are privileged shell commands executed under the worker identity; settings may change retention and future scheduled actions."))
        return operations

    def execute(self, operation, args, context):
        name = operation.removeprefix("backup.")
        if operation not in {item["id"] for item in self.catalog()}:
            raise OperationError("unknown_operation", "Unknown backup operation", 404)
        if name == "config":
            return self.get_config()
        if name.endswith(".set") and name.split(".")[0] in _SECTIONS:
            section = name.split(".")[0]
            changes = {key: value for key, value in args.items() if key != "revision"}
            for key in ("sources", "exclude_extensions", "exclude_patterns", "times", "remotes"):
                if key in changes and isinstance(changes[key], str):
                    changes[key] = [line.strip() for line in changes[key].splitlines() if line.strip()]
            return _result("Backup settings saved", self.set_config({section: changes}, args.get("revision"), context))
        if name == "secrets.update":
            mapping = {"archive_password": ("backup", "archive_password"), "repository_password": ("restic", "password"),
                       "healthcheck_url": ("monitoring", "healthcheck_url"), "heartbeat_url": ("monitoring", "heartbeat_url")}
            clear = {p.strip() for p in args.get("clear", "").split(",") if p.strip()}
            if clear - set(mapping):
                raise OperationError("invalid_secret", "Unknown secret name to erase")
            with self._lock:
                cfg = copy.deepcopy(self._cfg)
                for key, (section, field) in mapping.items():
                    if key in clear:
                        cfg[section][field] = ""
                    elif args.get(key):
                        cfg[section][field] = args[key]
                self._validate(cfg)
                self._save(cfg)
            return _result("Write-only secrets updated", self.get_config())
        if name in ("status", "progress"):
            return _result("Backup worker status", {"active": copy.deepcopy(self._active), "last_result": self._read_json(self.home / "control" / "last_result.json"),
                "last_success": self.scheduler.last_successful_run().isoformat() if self.scheduler.last_successful_run() else None,
                "schedule": self._snapshot()["schedule"], "scheduler_running": bool(self._thread and self._thread.is_alive())})
        if name == "cancel":
            if self._active_cancel is not None:
                self._active_cancel.set()
                return _result("Cancellation requested; committed effects are not rolled back")
            return _result("No active backup or recovery")
        # Config updates never wait for a long engine operation. All data-plane
        # operations share one process lock and one OS file lock, including reads
        # that inspect a repository being pruned or a credential file being changed.
        if not _ENGINE_LOCK.acquire(blocking=False):
            raise OperationError("backup_busy", "A backup/recovery/cloud operation is already active", 409)
        lockfile = None
        try:
            self._bind_paths()
            lockfile = self._claim_owner()
            cfg = self._snapshot()
            snapshot = getattr(context, "config_snapshot", None) or {}
            if name in ("run", "restore", "drill", "repository.init", "repository.check", "repository.prune"):
                stored = snapshot.get("backup", {}).get("value")
                if stored is not None:
                    cfg = copy.deepcopy(stored)
                    self._validate(cfg)
                # Revoking hooks takes effect even for an older queued settings
                # revision; a different/new command must be explicitly requeued.
                live = self._snapshot()
                for key in ("pre_command", "post_command"):
                    if cfg["backup"].get(key) != live["backup"].get(key):
                        raise OperationError("hook_revision_changed", "Backup hooks changed after this job was queued; submit a new job", 409)
            self._active_cancel = context.cancel
            self._active = {"operation": operation, "percent": None, "message": "Starting", "revision": self.config.config_revision(cfg)}
            def progress(percent, message):
                self._active.update(percent=percent, message=message)
                context.progress(percent, message)
            return self._execute(name, args, cfg, context, progress)
        finally:
            self._active_cancel = None
            self._active = None
            if lockfile is not None:
                lockfile.close()
            _ENGINE_LOCK.release()

    def _claim_owner(self):
        stream = (self.home / "worker.lock").open("a+b")
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                if stream.read(1) == b"":
                    stream.write(b"0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            stream.close()
            raise OperationError("backup_busy", "Another backup worker owns this data directory", 409) from error
        return stream

    def _archive(self, name):
        if not isinstance(name, str) or not name or Path(name).name != name or "/" in name or "\\" in name or ":" in name:
            raise OperationError("invalid_archive", "Choose an archive name from backup.archives")
        path = self.home / "local_backups" / name
        if path.is_symlink() or not path.is_file() or path.resolve().parent != (self.home / "local_backups").resolve():
            raise OperationError("archive_not_found", "Backup archive not found", 404)
        if not (name.endswith(".zip") or ".zip.part" in name):
            raise OperationError("invalid_archive", "Only backup ZIP archive files are downloadable")
        return path

    def _execute(self, name, args, cfg, context, progress):
        if name == "run":
            self._atomic_json(self.home / "control" / "last_result.json", {"status": "running", "engine": cfg["backup"]["engine"]})
            status = self.scheduler.run_with_retries(cfg, tg=None, manual=not bool(args.get("scheduled")),
                                                     progress_cb=progress, cancel_event=context.cancel)
            detail = self._read_json(self.home / "control" / "last_result.json")
            detail.update(status=status, config_revision=self.config.config_revision(cfg))
            self._atomic_json(self.home / "control" / "last_result.json", detail)
            context.emit("backup.result", "Backup " + status, "info" if status == "ok" else "warning", detail)
            return _result("Backup " + status, detail, _STATUS.get(status, "failed"))
        if name == "archives":
            data = {"zip": self.restore.list_backups(), "restic": []}
            if cfg["restic"].get("repository"):
                error = self.restic.validate(cfg)
                if error:
                    data["restic_error"] = error
                else:
                    try:
                        data["restic"] = self.restic.snapshot_details(cfg)
                    except ValueError as error:
                        data["restic_error"] = str(error)
            return _result("Available backup archives", data, "partial" if data.get("restic_error") else "succeeded")
        if name == "archive.download":
            path = self._archive(args.get("archive"))
            return {**_result("Archive ready"), "artifacts": [context.artifact(path, path.name, "application/zip")]}
        if name == "archive.delete":
            path = self._archive(args.get("archive"))
            if str(path.resolve()) in self.zip._files_in_use:
                raise OperationError("archive_busy", "Archive is in use", 409)
            path.unlink()
            return _result("Local archive deleted")
        if name in ("restore", "drill"):
            engine = args.get("engine", cfg["backup"]["engine"])
            target = self.restore.new_restore_dir(str(self.home / "restores"), name)
            if engine == "zip":
                archive = args.get("archive")
                if not archive:
                    archives = self.restore.list_backups()
                    if not archives:
                        raise OperationError("no_archive", "No local ZIP archive is available", 404)
                    archive = archives[0]["name"]
                path = self._archive(archive)
                result = self.restore.restore_archive(str(path), target, cfg["backup"].get("archive_password", ""), progress, context.cancel)
                result["archive"] = archive
            elif engine == "restic":
                error = self.restic.validate(cfg)
                if error:
                    raise OperationError("repository_unavailable", error, 503)
                snapshot = args.get("archive")
                if not snapshot:
                    snapshots = self.restic.snapshot_details(cfg, 1)
                    if not snapshots:
                        raise OperationError("no_snapshot", "No restic snapshot is available", 404)
                    snapshot = snapshots[-1]["id"]
                result = self.restic.restore_snapshot(cfg, snapshot, target, progress, context.cancel)
            else:
                raise OperationError("invalid_engine", "Choose ZIP or restic")
            if name == "drill" and result.get("created") and not args.get("keep", cfg["restore_drill"].get("keep", False)):
                # Only our newly generated, non-linked child can ever be removed.
                if Path(target).parent.resolve() != (self.home / "restores").resolve():
                    raise OperationError("unsafe_restore", "Refusing to remove an unexpected recovery directory")
                self.restore._assert_no_links(target)
                try:
                    shutil.rmtree(target)
                    result["cleaned"] = True
                except OSError as error:
                    result.update(status="error", cleaned=False, message=result.get("message", "") + "; cleanup failed: " + str(error))
            result["drilled_at"] = time.time() if name == "drill" else None
            return _result(result.get("message", "Recovery finished"), result, _STATUS.get(result.get("status"), "failed"))
        if name.startswith("repository."):
            error = self.restic.validate(cfg)
            if error:
                raise OperationError("repository_unavailable", error, 503)
            if name == "repository.init":
                code, output = self.restic._run(cfg, ["init"], timeout=600, cancel_event=context.cancel)
            elif name == "repository.check":
                code, output = self.restic._run(cfg, ["check", "--read-data"], timeout=24 * 3600, cancel_event=context.cancel)
            else:
                r = cfg["restic"]
                code, output = self.restic._run(cfg, ["forget", "--prune", "--keep-daily", str(r["keep_daily"]), "--keep-weekly", str(r["keep_weekly"]), "--keep-monthly", str(r["keep_monthly"])], timeout=24 * 3600, cancel_event=context.cancel)
            return _result("Repository operation completed" if code == 0 else "Repository operation failed", {"output": self._clean_output(output, cfg)}, "cancelled" if context.cancel.is_set() else "succeeded" if code == 0 else "failed")
        if name == "tools.status":
            return _result("Backup tool availability", {tool: self._tool_status(tool) for tool in ("restic", "rclone")})
        if name == "tools.install":
            return self._install_tool(args, context)
        if name.startswith("cloud."):
            return self._cloud_operation(name, args, cfg, context)
        if name in ("recovery.export", "recovery.import"):
            return self._recovery(name, args, context)
        raise OperationError("unknown_operation", "Unknown backup operation", 404)

    @staticmethod
    def _read_json(path):
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}

    @staticmethod
    def _clean_output(output, cfg):
        for section, key in _SECRET_KEYS:
            secret = cfg[section].get(key)
            if secret:
                output = output.replace(secret, "[redacted]")
        return output[-2000:]

    def _tool_status(self, tool):
        executable = self.restic.find_restic() if tool == "restic" else self.cloud.find_rclone()
        if not executable:
            return {"available": False, "message": "Install a verified " + tool + " release using backup.tools.install"}
        result = subprocess.run([executable, "version"], capture_output=True, text=True, timeout=30,
                                creationflags=0x08000000 if os.name == "nt" else 0)
        return {"available": result.returncode == 0, "path": executable, "version": result.stdout.splitlines()[0] if result.stdout else "", "sha256": self.zip.file_sha256(executable)}

    def _install_tool(self, args, context):
        tool, url = args.get("tool"), args.get("url", "")
        parsed = urllib.parse.urlparse(url)
        allowed = {"restic": {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"},
                   "rclone": {"downloads.rclone.org"}}
        digest, version = args.get("sha256", "").lower(), args.get("version", "").lstrip("v")
        if tool not in allowed or parsed.scheme != "https" or parsed.hostname not in allowed[tool] or parsed.username:
            raise OperationError("invalid_download", "Use an official HTTPS restic GitHub release or downloads.rclone.org release")
        if tool == "restic" and parsed.hostname == "github.com" and not parsed.path.startswith("/restic/restic/releases/download/"):
            raise OperationError("invalid_download", "Use the official restic/restic release")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
            raise OperationError("invalid_verification", "A release SHA-256 and exact version are mandatory")
        class VerifiedRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(inner, req, fp, code, msg, headers, newurl):
                redirect = urllib.parse.urlparse(newurl)
                if redirect.scheme != "https" or redirect.hostname not in allowed[tool]:
                    raise OperationError("unsafe_redirect", "Release download redirected outside trusted hosts")
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        with tempfile.TemporaryDirectory(dir=self.home, prefix="tool-install-") as temp:
            download = Path(temp) / "release"
            checksum = hashlib.sha256()
            count = 0
            with urllib.request.build_opener(VerifiedRedirect()).open(url, timeout=60) as response, download.open("xb") as output:
                while True:
                    if context.cancel.is_set():
                        return _result("Tool install cancelled", status="cancelled")
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > 512 * 1024 * 1024:
                        raise OperationError("release_too_large", "Tool release exceeds 512 MiB")
                    checksum.update(chunk)
                    output.write(chunk)
            if checksum.hexdigest() != digest:
                raise OperationError("hash_mismatch", "Downloaded release SHA-256 does not match; nothing installed")
            exe_name = tool + (".exe" if os.name == "nt" else "")
            candidate = Path(temp) / exe_name
            if parsed.path.endswith(".zip"):
                with zipfile.ZipFile(download) as archive:
                    members = [m for m in archive.infolist() if Path(m.filename).name == exe_name]
                    if len(members) != 1 or members[0].file_size > 256 * 1024 * 1024:
                        raise OperationError("invalid_release", "Release must contain exactly one bounded tool executable")
                    with archive.open(members[0]) as source, candidate.open("xb") as dest:
                        shutil.copyfileobj(source, dest)
            elif parsed.path.endswith(".bz2"):
                import bz2
                with bz2.open(download) as source, candidate.open("xb") as dest:
                    total = 0
                    while chunk := source.read(1024 * 1024):
                        total += len(chunk)
                        if total > 256 * 1024 * 1024:
                            raise OperationError("invalid_release", "Executable exceeds release size limit")
                        dest.write(chunk)
            else:
                shutil.copy2(download, candidate)
            candidate.chmod(0o700)
            process = subprocess.run([str(candidate), "version"], capture_output=True, text=True, timeout=30,
                                     creationflags=0x08000000 if os.name == "nt" else 0)
            first = process.stdout.splitlines()[0] if process.stdout else ""
            if process.returncode or not re.search(r"\b" + re.escape(version) + r"\b", first) or tool not in first.lower():
                raise OperationError("version_mismatch", "Release executable does not report the requested tool version")
            target = self.home / tool / exe_name
            target.parent.mkdir(exist_ok=True)
            os.replace(candidate, target)
            self.config.harden_path(str(target))
            metadata = {"version": version, "release_sha256": digest, "binary_sha256": self.zip.file_sha256(target), "url": url}
            self._atomic_json(target.with_suffix(".verified.json"), metadata)
        return _result("Verified tool installed", metadata)

    def _cloud_operation(self, name, args, cfg, context):
        executable = self.cloud.find_rclone()
        if not executable:
            raise OperationError("rclone_missing", "rclone is missing; install an official verified release with backup.tools.install", 503)
        if name == "cloud.remotes":
            ok, out = self.cloud._run(["listremotes"], timeout=60)
            if not ok:
                raise OperationError("cloud_failed", "Cannot list cloud remotes", 502)
            return _result("Cloud remotes", [r for r in out.splitlines() if r])
        if name == "cloud.providers":
            ok, out = self.cloud._run(["config", "providers"], timeout=60)
            if not ok:
                raise OperationError("cloud_failed", "Cannot read rclone provider onboarding schema", 502)
            providers = json.loads(out)
            # Provider schema contains option definitions/defaults, never saved credentials.
            return _result("Provider onboarding options", providers)
        if name == "cloud.archives":
            return _result("Remote backup archives", self.cloud.list_remote_backups(cfg))
        if name == "cloud.oauth":
            provider = args.get("provider", "")
            if not re.fullmatch(r"[a-z0-9_-]+", provider):
                raise OperationError("invalid_provider", "Choose a provider from backup.cloud.providers")
            return self._oauth(provider, args, context)
        if name in ("cloud.create", "cloud.remove"):
            remote = args.get("name", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]+", remote):
                raise OperationError("invalid_remote", "Remote names may contain letters, numbers, underscore and hyphen")
            if name == "cloud.remove":
                if any(r.rstrip(":") == remote for r in cfg["cloud"]["remotes"]) or ("rclone:" + remote + ":") in cfg["restic"].get("repository", ""):
                    raise OperationError("remote_in_use", "Remove this destination from backup/repository settings before deleting its credentials", 409)
                ok, _ = self.cloud._run(["config", "delete", remote], timeout=60)
            else:
                provider = args.get("provider", "")
                if not re.fullmatch(r"[a-z0-9_-]+", provider):
                    raise OperationError("invalid_provider", "Choose a provider from backup.cloud.providers")
                try:
                    options = json.loads(args.get("options", "{}"))
                except ValueError as error:
                    raise OperationError("invalid_credentials", "Provider options must be a JSON object") from error
                if not isinstance(options, dict) or any(not re.fullmatch(r"[A-Za-z0-9_]+", k) or not isinstance(v, (str, bool, int)) for k, v in options.items()):
                    raise OperationError("invalid_credentials", "Provider options must contain named scalar values")
                # Temporary authenticated loopback RC keeps provider secrets out
                # of argv, console output, event history and durable job results.
                body = {"name": remote, "type": provider, "parameters": options,
                        "opt": {"nonInteractive": True, "obscure": True}}
                ok, payload = self._rclone_create(body, context)
                if ok and payload.get("State"):
                    raise OperationError("provider_setup_incomplete", "Provider requires additional onboarding; use cloud.oauth and supply its token before creating this remote")
            self.config.harden_path(self.cloud.RCLONE_CONFIG)
            if not ok:
                raise OperationError("cloud_config_failed", "Cloud provider configuration failed; check provider-required options without exposing credentials", 502)
            return _result("Cloud credentials " + ("removed" if name.endswith("remove") else "saved"))
        if name == "cloud.test":
            remote = args.get("remote", "").rstrip(":")
            if not re.fullmatch(r"[A-Za-z0-9_-]+", remote):
                raise OperationError("invalid_remote", "Choose a configured cloud remote")
            dest = remote + ":" + cfg["cloud"]["remote_folder"].strip("/") + "/.rdpmonitor-probe-" + uuid.uuid4().hex
            with tempfile.TemporaryDirectory(dir=self.home, prefix="cloud-probe-") as temp:
                probe = Path(temp) / "probe"
                probe.write_bytes(os.urandom(65536))
                try:
                    ok, _ = self.cloud._run(["copyto", str(probe), dest], timeout=120)
                    if not ok:
                        return _result("Cloud write probe failed", status="failed")
                    returned = Path(temp) / "returned"
                    ok, _ = self.cloud._run(["copyto", dest, str(returned)], timeout=120)
                    verified = bool(ok and returned.is_file() and self.zip.file_sha256(probe) == self.zip.file_sha256(returned))
                finally:
                    cleaned, _ = self.cloud._run(["deletefile", dest], timeout=120)
                return _result("Cloud write/read/hash verification " + ("passed" if verified else "failed"), {"verified": verified, "probe_cleaned": cleaned}, "succeeded" if verified and cleaned else "partial" if verified else "failed")
        raise OperationError("unknown_operation", "Unknown cloud operation", 404)

    def _oauth(self, provider, args, context):
        # Local authorization endpoint remains private to this worker process;
        # URL is delivered to the approved client, never opened under SYSTEM.
        executable = self.cloud.find_rclone()
        command = [executable] + self.cloud.base_args() + ["authorize", provider, "--auth-no-open-browser"]
        if args.get("client_id"):
            command.append(args["client_id"])
            command.append(args.get("client_secret", ""))
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace",
                                   creationflags=0x08000000 if os.name == "nt" else 0)
        lines = []
        def consume():
            for line in process.stdout:
                lines.append(line)
                match = re.search(r"https?://[^\s]+", line)
                if match:
                    context.emit("backup.oauth", "Cloud authorization URL; accessible only from the agent host or approved tunnel", "info", {"url": match.group(0), "provider": provider})
        reader = threading.Thread(target=consume, daemon=True)
        reader.start()
        deadline = time.monotonic() + 600
        while process.poll() is None:
            if context.cancel.wait(0.2) or time.monotonic() > deadline:
                process.kill()
                process.wait(timeout=10)
                reader.join(timeout=5)
                return _result("Cloud authorization cancelled or expired", status="cancelled" if context.cancel.is_set() else "failed")
        reader.join(timeout=5)
        output = "".join(lines)
        # Token is a secret: store it immediately, never emit/return it in job results.
        tokens = re.findall(r'\{[^\n]*"access_token"[^\n]*\}', output)
        if process.returncode or not tokens:
            return _result("Cloud authorization failed; no credentials saved", status="failed")
        name = "oauth_" + provider + "_" + uuid.uuid4().hex[:8]
        return self._cloud_operation("cloud.create", {"name": name, "provider": provider,
                                     "options": json.dumps({"token": tokens[-1], "client_id": args.get("client_id", ""), "client_secret": args.get("client_secret", "")})}, self._snapshot(), context) | {"data": {"remote": name + ":"}}

    def _recovery(self, name, args, context):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        password = args.get("passphrase", "")
        if not isinstance(password, str) or len(password) < 12:
            raise OperationError("weak_recovery_key", "Use an operator-held recovery passphrase of at least 12 characters")
        if name == "recovery.export":
            cfg = self._snapshot()
            rclone = Path(self.cloud.RCLONE_CONFIG)
            payload = {"format": 1, "config": {section: cfg[section] for section in _SECTIONS},
                       "rclone": rclone.read_text(encoding="utf-8") if rclone.exists() else ""}
            salt, nonce = os.urandom(16), os.urandom(12)
            key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())
            encrypted = AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), b"RDPMonitor/recovery/1")
            target = self.home / "control" / ("recovery-" + uuid.uuid4().hex + ".rdpr")
            target.write_bytes(b"RDPR1" + salt + nonce + encrypted)
            self.config.harden_path(str(target))
            try:
                artifact = context.artifact(target, "rdpmonitor-recovery.rdpr", "application/octet-stream")
            finally:
                target.unlink(missing_ok=True)
            return {**_result("Portable encrypted recovery bundle created; keep its passphrase off this machine"), "artifacts": [artifact]}
        try:
            raw = base64.b64decode(args.get("bundle", ""), validate=True)
            if not raw.startswith(b"RDPR1") or len(raw) > 16 * 1024 * 1024:
                raise ValueError("Invalid recovery bundle")
            salt, nonce, encrypted = raw[5:21], raw[21:33], raw[33:]
            key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())
            payload = json.loads(AESGCM(key).decrypt(nonce, encrypted, b"RDPMonitor/recovery/1"))
            if payload.get("format") != 1:
                raise ValueError("Unsupported recovery format")
            with self._lock:
                cfg = copy.deepcopy(self._cfg)
                for section in _SECTIONS:
                    cfg[section] = payload["config"][section]
                cfg["cloud"]["rclone_config"] = self.cloud.RCLONE_CONFIG
                # Import is configuration recovery, never automatic execution.
                cfg["schedule"]["enabled"] = False
                cfg["restore_drill"]["enabled"] = False
                self._validate(cfg)
                rclone_data = payload.get("rclone", "")
                if not isinstance(rclone_data, str):
                    raise ValueError("Invalid rclone recovery configuration")
                self._save(cfg)
                target = Path(self.cloud.RCLONE_CONFIG)
                temporary = target.with_suffix(".import")
                temporary.write_text(rclone_data, encoding="utf-8")
                self.config.harden_path(str(temporary))
                os.replace(temporary, target)
        except OperationError:
            raise
        except Exception as error:
            raise OperationError("recovery_import_failed", "Recovery bundle is invalid or its passphrase is incorrect; no repository operation was executed") from error
        return _result("Recovery configuration imported with schedules disabled", self.get_config())

    def _due_slot(self, cfg, now):
        schedule = cfg["schedule"]
        if not schedule.get("enabled"):
            return None
        zone = now.astimezone().tzinfo if schedule.get("timezone", "local") == "local" else ZoneInfo(schedule["timezone"])
        local = now.astimezone(zone)
        if schedule["mode"] == "interval":
            seconds = int(schedule["interval_hours"]) * 3600
            slot = int(now.timestamp()) // seconds
            return "interval:" + str(slot) if schedule.get("catch_up", True) or now.timestamp() % seconds < 30 else None
        times = schedule.get("times", []) if schedule["mode"] == "times" else [schedule["time"]]
        # Local date/time slot gives DST fallback one execution, not two. On a
        # spring gap catch-up runs once when the clock passes the missing time.
        due = [value for value in times if value <= local.strftime("%H:%M")]
        if not due:
            return None
        latest = max(due)
        if not schedule.get("catch_up", True) and latest != local.strftime("%H:%M"):
            return None
        return "daily:" + local.date().isoformat() + ":" + latest

    def _loop(self):
        state_path = self.home / "control" / "schedule.json"
        while not self._stop.is_set():
            try:
                cfg = self._snapshot()
                now = dt.datetime.now(dt.timezone.utc)
                state = self._read_json(state_path)
                slot = self._due_slot(cfg, now)
                if slot and state.get("slot") != slot:
                    request_id = "backup-schedule:" + slot
                    job = self._submit("backup.run", {"scheduled": True}, request_id)
                    state.update(slot=slot, job_id=job.get("id"), submitted=now.isoformat())
                    self._atomic_json(state_path, state)
                drill = cfg["restore_drill"]
                drill_slot = int(now.timestamp()) // (int(drill["interval_days"]) * 86400)
                if drill.get("enabled") and state.get("drill_slot") != drill_slot:
                    job = self._submit("backup.drill", {"keep": drill.get("keep", False)}, "backup-drill:" + str(drill_slot))
                    state.update(drill_slot=drill_slot, drill_job_id=job.get("id"))
                    self._atomic_json(state_path, state)
                if time.monotonic() - self._last_heartbeat >= 60:
                    self._last_heartbeat = time.monotonic()
                    import monitor
                    monitor.heartbeat(cfg)
                hours = cfg["monitoring"].get("alert_after_hours", 26)
                last = self.scheduler.last_successful_run()
                reference = last.replace(tzinfo=now.astimezone().tzinfo).astimezone(dt.timezone.utc) if last and last.tzinfo is None else last or self._started
                if hours and (now - reference).total_seconds() > hours * 3600 and time.monotonic() - self._last_stale > 12 * 3600:
                    self._last_stale = time.monotonic()
                    self.emit("backup.stale", "No successful backup within the configured alert period", "warning", {"last_success": last.isoformat() if last else None})
            except Exception as error:
                self.emit("backup.scheduler", "Backup scheduling failed: " + str(error), "error")
            self._stop.wait(20)

    def _rclone_create(self, body, context):
        import socket
        import urllib.error
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        user, password = uuid.uuid4().hex, uuid.uuid4().hex
        environment = os.environ.copy()
        environment.update(RCLONE_RC_USER=user, RCLONE_RC_PASS=password)
        process = subprocess.Popen([self.cloud.find_rclone()] + self.cloud.base_args() +
                                   ["rcd", "--rc-addr", "127.0.0.1:" + str(port)],
                                   env=environment, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL,
                                   creationflags=0x08000000 if os.name == "nt" else 0)
        authorization = "Basic " + base64.b64encode((user + ":" + password).encode()).decode()
        url = "http://127.0.0.1:" + str(port)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def post(endpoint, value):
            request = urllib.request.Request(url + endpoint, json.dumps(value).encode(),
                {"Content-Type": "application/json", "Authorization": authorization}, method="POST")
            with opener.open(request, timeout=30) as response:
                return json.load(response)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None or context.cancel.is_set():
                    return False, {}
                try:
                    post("/core/version", {})
                    break
                except (OSError, urllib.error.URLError):
                    context.cancel.wait(0.1)
            else:
                return False, {}
            try:
                return True, post("/config/create", body)
            except (OSError, urllib.error.URLError, ValueError):
                return False, {}
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
