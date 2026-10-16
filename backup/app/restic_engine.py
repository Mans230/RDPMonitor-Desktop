# -*- coding: utf-8 -*-
"""Incremental copy engine via restic — Uploads only variable parts, no duplicates, and always encrypted.

warehouse (repository) It could be:
    rclone:drive:VPS-Restic   ← Any destination rclone Pre-set (Google Drive, OneDrive, ...)
    D:\\restic-repo            ← A local folder or on another disk
    s3:..., b2:..., sftp:...  ← Other types restic

Restoration:  restic -r <repo> restore latest --target D:\\restore
"""

import os
import json
import shutil
import subprocess
import threading
import time

from logger_utils import log as _default_log
from i18n import tr
import backup_engine
import cloud_uploader

RESTIC_DIR = os.path.join(backup_engine.TOOL_ROOT, "restic")
_NO_WINDOW = 0x08000000


def find_restic():
    exe = "restic.exe" if os.name == "nt" else "restic"
    local = os.path.join(RESTIC_DIR, exe)
    if os.path.exists(local):
        return local
    return shutil.which("restic")


def is_available():
    return find_restic() is not None


def _env(cfg):
    env = os.environ.copy()
    env["RESTIC_REPOSITORY"] = cfg["restic"].get("repository", "").strip()
    env["RESTIC_PASSWORD"] = cfg["restic"].get("password", "")
    if cloud_uploader.RCLONE_CONFIG:
        env["RCLONE_CONFIG"] = cloud_uploader.RCLONE_CONFIG
    # restic On "rclone" Who PATH (Cucumber rclone.program Corrupts Windows paths)
    rclone = cloud_uploader.find_rclone()
    if rclone:
        env["PATH"] = os.path.dirname(os.path.abspath(rclone)) + os.pathsep + env.get("PATH", "")
    env.setdefault("RESTIC_CACHE_DIR", os.path.join(backup_engine.TOOL_ROOT, "restic", "cache"))
    return env


def _base(cfg):
    return [find_restic()]


def _run(cfg, args, timeout=3600, cancel_event=None):
    """Run with cancellation even when the child emits no output."""
    if not find_restic():
        return -1, "restic is missing; install a verified binary with backup.tools.install"
    launch = ({"creationflags": _NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
              if os.name == "nt" else {"start_new_session": True})
    try:
        proc = subprocess.Popen(_base(cfg) + args, env=_env(cfg), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                errors="replace", **launch)
        deadline = time.monotonic() + timeout
        while True:
            try:
                out, err = proc.communicate(timeout=0.25)
                return proc.returncode, (out if proc.returncode == 0 else out + err).strip()
            except subprocess.TimeoutExpired:
                if (cancel_event is not None and cancel_event.is_set()) or time.monotonic() >= deadline:
                    _terminate_tree(proc)
                    proc.communicate()
                    return -1, "cancelled" if cancel_event is not None and cancel_event.is_set() else "restic timed out"
    except OSError as e:
        return -1, str(e)


def validate(cfg):
    """Returns an error message None."""
    if not is_available():
        return tr("core.restic.missing")
    if not cfg["restic"].get("repository", "").strip():
        return tr("core.restic.no_repo")
    if not cfg["restic"].get("password"):
        return tr("core.restic.no_password")
    return None


def ensure_repo(cfg, log):
    code, _out = _run(cfg, ["cat", "config"], timeout=300)
    if code == 0:
        return True
    log(tr("core.restic.init"))
    code, out = _run(cfg, ["init"], timeout=600)
    if code != 0:
        log(tr("core.restic.init_failed", err=out[-500:]), "ERROR")
        return False
    return True


def _backup_args(cfg):
    bcfg = cfg["backup"]
    args = ["backup", "--json", "--exclude", backup_engine.TOOL_ROOT]
    if bcfg.get("use_vss") and os.name == "nt":
        args.append("--use-fs-snapshot")
    for ext in bcfg.get("exclude_extensions", []):
        ext = ext.strip()
        if ext:
            args += ["--iexclude", "*" + (ext if ext.startswith(".") else "." + ext)]
    for pat in backup_engine.normalize_patterns(bcfg.get("exclude_patterns", [])):
        args += ["--iexclude", pat]
    max_mb = int(bcfg.get("exclude_max_size_mb", 0) or 0)
    if max_mb > 0:
        args += ["--exclude-larger-than", f"{max_mb}M"]
    sources = [os.path.abspath(s.strip().strip('"')) for s in bcfg.get("sources", []) if s.strip()]
    sources = [s for s in sources if os.path.exists(s) and not backup_engine.is_inside_tool(s)]
    return args, sources


def _terminate_tree(proc):
    """Kill restic and its children (for example the rclone helper process).

    Terminating only restic can leave rclone running and the repository locked.
    """
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, creationflags=_NO_WINDOW)
        else:
            import signal
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        pass
    try:
        proc.wait(timeout=15)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_backup(cfg, log=None, progress_cb=None, cancel_event=None):
    """He comes back dict: status ("ok"|"warn"|"cancelled"|"error"), summary, message."""
    _log = log or _default_log
    err = validate(cfg)
    if err:
        _log(err, "ERROR")
        return {"status": "error", "message": err}
    bcfg = cfg["backup"]
    try:
        eligible, _skipped, missing = backup_engine.collect_files(
            bcfg.get("sources", []), bcfg.get("exclude_extensions", []),
            bcfg.get("exclude_max_size_mb", 0),
            exclude_patterns=bcfg.get("exclude_patterns", []), cancel_event=cancel_event)
    except backup_engine._Cancelled:
        return {"status": "cancelled"}
    if missing and bcfg.get("require_all_sources", True):
        return {"status": "error", "message": "Missing/unreadable sources: " + ", ".join(missing[:5]),
                "missing": missing}
    args, sources = _backup_args(cfg)
    if not sources or not eligible:
        return {"status": "error", "message": tr("core.backup.no_files"), "missing": missing}
    if not ensure_repo(cfg, _log):
        return {"status": "error", "message": "repository init failed"}
    _log(tr("core.restic.start", repo=cfg["restic"]["repository"], count=len(sources)))

    launch = {}
    if os.name == "nt":
        launch["creationflags"] = _NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        launch["start_new_session"] = True
    proc = subprocess.Popen(_base(cfg) + args + sources, env=_env(cfg), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
                            **launch)
    finished = threading.Event()
    def cancel_watch():
        while not finished.wait(0.2):
            if cancel_event is not None and cancel_event.is_set():
                _terminate_tree(proc)
                return
    threading.Thread(target=cancel_watch, daemon=True).start()
    summary, errors, last_pct = None, [], -1
    import collections
    # Bounded: only the tail is ever reported, so do not grow without limit.
    stderr_lines = collections.deque(maxlen=200)
    t = threading.Thread(target=lambda: stderr_lines.extend(proc.stderr), daemon=True)
    t.start()
    for line in proc.stdout:
        if cancel_event is not None and cancel_event.is_set():
            _terminate_tree(proc)
            break
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        kind = msg.get("message_type")
        if kind == "status" and progress_cb:
            pct = int(float(msg.get("percent_done", 0)) * 90)
            if pct != last_pct:
                last_pct = pct
                progress_cb(pct, tr("core.restic.progress", percent=int(pct / 0.9)))
        elif kind == "error":
            item = msg.get("item") or ""
            e = (msg.get("error") or {}).get("message", "")
            errors.append(f"{item}: {e}")
            _log(tr("core.backup.compress_failed", path=item, err=e), "WARN")
        elif kind == "summary":
            summary = msg
    proc.wait()
    t.join(timeout=5)
    finished.set()
    if cancel_event is not None and cancel_event.is_set():
        _log(tr("core.backup.cancelled"), "WARN")
        return {"status": "cancelled"}
    # 0 = success, 3 = Snapshot completed but some files could not be read
    if proc.returncode not in (0, 3) or not summary:
        tail = "".join(stderr_lines)[-500:]
        _log(tr("core.restic.failed", code=proc.returncode, err=tail), "ERROR")
        return {"status": "error", "message": tail}
    status = "ok" if proc.returncode == 0 and not errors and not missing else "warn"
    _log(tr("core.restic.done", snapshot=summary.get("snapshot_id", "")[:8],
            new=summary.get("files_new", 0), changed=summary.get("files_changed", 0),
            added_mb=f"{summary.get('data_added', 0) / 1024 / 1024:.1f}",
            total_mb=f"{summary.get('total_bytes_processed', 0) / 1024 / 1024:.1f}"))

    r = cfg["restic"]

    verified = None
    if r.get("check_after_backup", True) and cfg["backup"].get("verify", True):
        if progress_cb:
            progress_cb(96, tr("core.verify.running"))
        code, out = _run(cfg, ["check", "--read-data"], timeout=6 * 3600, cancel_event=cancel_event)
        verified = code == 0
        if verified:
            _log(tr("core.restic.check_ok"))
        else:
            _log(tr("core.restic.check_failed", err=out[-500:]), "ERROR")
            status = "error"
    if status == "ok":
        code, out = _run(cfg, ["forget", "--prune",
                              "--keep-daily", str(int(r.get("keep_daily", 7))),
                              "--keep-weekly", str(int(r.get("keep_weekly", 4))),
                              "--keep-monthly", str(int(r.get("keep_monthly", 12)))],
                         timeout=6 * 3600, cancel_event=cancel_event)
    else:
        code, out = 0, ""
    if code != 0:
        _log(tr("core.restic.forget_failed", err=out[-300:]), "WARN")
        status = "warn"
    if progress_cb:
        progress_cb(100, tr("core.restic.finished"))
    if cancel_event is not None and cancel_event.is_set():
        status = "cancelled"
    return {"status": status, "summary": summary, "errors": errors, "missing": missing,
            "verified": verified, "vss": "requested" if bcfg.get("use_vss") else "off"}


def list_snapshots(cfg, limit=20):
    code, out = _run(cfg, ["snapshots", "--json"], timeout=300)
    if code != 0:
        return []
    try:
        snaps = json.JSONDecoder().raw_decode(out[out.find("["):])[0]
    except Exception:
        return []
    lines = [f"{s.get('short_id', '')}  {s.get('time', '')[:19].replace('T', ' ')}" for s in snaps]
    return lines[-limit:]


def snapshot_details(cfg, limit=100):
    code, out = _run(cfg, ["snapshots", "--json"], timeout=300)
    if code:
        raise ValueError("Cannot list restic snapshots: " + out[-500:])
    snapshots = json.loads(out)
    if not isinstance(snapshots, list):
        raise ValueError("Invalid snapshot list returned by restic")
    return snapshots[-limit:]


def restore_snapshot(cfg, snapshot, dest_root, progress_cb=None, cancel_event=None):
    """Restore repository data, then verify against repository content and file metadata."""
    import restore
    result = {"status": "error", "dest": dest_root, "created": False,
              "restored": 0, "checked": 0, "missing": [], "message": ""}
    try:
        restore._assert_safe_dest(dest_root)
        if not snapshot or str(snapshot).startswith("-"):
            raise ValueError("Choose an explicit snapshot ID")
        matches = [s for s in snapshot_details(cfg, 100000)
                   if snapshot in (s.get("id"), s.get("short_id"))]
        if len(matches) != 1:
            raise ValueError("Snapshot ID is missing or ambiguous")
        snapshot = matches[0]["id"]
        code, listing = _run(cfg, ["ls", snapshot, "--json"], cancel_event=cancel_event)
        if code:
            raise ValueError("Cannot read snapshot inventory: " + listing[-500:])
        entries = []
        for line in listing.splitlines():
            node = json.loads(line)
            if node.get("type") == "symlink":
                raise ValueError("Snapshot contains links; isolated restore refuses link traversal")
            if node.get("type") == "file":
                relative = node["path"].lstrip("/\\")
                target = restore._safe_target(dest_root, relative)
                entries.append((target, int(node["size"])))
        if not entries:
            raise ValueError("Snapshot contains no regular files")
        if cancel_event is not None and cancel_event.is_set():
            result.update(status="cancelled", message="Restore cancelled")
            return result
        restore._assert_safe_dest(dest_root)
        os.makedirs(os.path.dirname(os.path.abspath(dest_root)), exist_ok=True)
        os.mkdir(dest_root)
        result["created"] = True
        if progress_cb:
            progress_cb(5, "Restoring and verifying repository content")
        code, out = _run(cfg, ["restore", snapshot, "--target", dest_root, "--verify"],
                         timeout=24 * 3600, cancel_event=cancel_event)
        if cancel_event is not None and cancel_event.is_set():
            result.update(status="cancelled", message="Restore cancelled")
            return result
        if code:
            raise ValueError("Restic restore/content verification failed: " + out[-500:])
        for target, size in entries:
            restore._check_cancel(cancel_event)
            restore._assert_no_links(target)
            if not os.path.isfile(target) or os.path.getsize(target) != size:
                result["missing"].append(os.path.relpath(target, dest_root))
            else:
                result["restored"] += 1
            result["checked"] += 1
        result.update(status="error" if result["missing"] else "ok",
                      verified=not result["missing"], snapshot=snapshot,
                      message="Restic content verification and snapshot file inventory checked")
        if progress_cb:
            progress_cb(100, result["message"])
    except restore._RestoreCancelled:
        result.update(status="cancelled", message="Restore cancelled")
    except Exception as e:
        result["message"] = str(e)
    return result
