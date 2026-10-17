# -*- coding: utf-8 -*-
"""
RDP Monitor - A comprehensive device monitoring tool Windows (Suitable for devices RDP) With Telegram

Features:
  - Set up the first run: Requests bot token Chat ID And keep them in config.json
  - Monitor the processor and RAM with graded alerts (Warning 50% / Danger 80% / Critical 95%)
  - Alert "The situation returned to normal" + Immediate alert when there is a sudden rise
  - Real-time internet consumption (/net) And measure speed (/speedtest)
  - Monitor disk space and alert you when it is close to full
  - Highest consuming processes (/top) And another graph 24 hours (/chart)
  - Daily report/Scheduled weekly + Order /report Immediate
  - Monitor a specific program by name (/watch)
  - Monitor sessions RDP Active and IP Callers + Alert upon entry/User logout
  - Control commands: /screenshot /exec /kill /download /restart /listusers /update
  - Receive files from Telegram and save them on the device automatically
  - Manual and automatic restart at a certain limit

Requirements:
  pip install psutil requests matplotlib pillow
"""

import copy
import difflib
import contextlib
import base64
import ctypes
import hashlib
import hmac
import html
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timedelta

import psutil
import requests


# Hide console windows for subcommands (powershell A black screen appeared every minute pythonw)
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


try:
    import matplotlib
    matplotlib.use("Agg")
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# ----------------------------- Settings -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.abspath(__file__)
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
HISTORY_FILE = os.path.join(BASE_DIR, "history.json")


IMAGE_STATE_FILE = os.path.join(BASE_DIR, "image_state.json")

# The agent supplies transports explicitly; importing this engine starts nothing.
_event_sink = None
_artifact_sink = None
_session_sink = None
_transport_lock = threading.RLock()
_engine_stop = threading.Event()
_engine_threads = []
_engine_lock = threading.RLock()
_agent_mode = False

_engine_read_only = False
_runtime_scratch = tempfile.gettempdir()

def configure_runtime(data_dir, event_sink, artifact_sink, session_sink=None):
    """Bind writable state and transport hooks before load/start (no host changes)."""
    global BASE_DIR, CONFIG_FILE, HISTORY_FILE, ALERT_QUEUE_FILE, FILE_QUEUE_FILE
    global IMAGE_STATE_FILE, LOG_FILE, AUDIT_FILE, BLOCKED_FILE, TRAFFIC_FILE
    global BACKUP_DIR, _event_sink, _artifact_sink, _session_sink, _agent_mode, _runtime_scratch
    BASE_DIR = os.path.abspath(os.fspath(data_dir))
    os.makedirs(BASE_DIR, exist_ok=True)
    _runtime_scratch = os.path.join(BASE_DIR, "scratch")
    os.makedirs(_runtime_scratch, exist_ok=True)
    for variable, filename in (
            ("CONFIG_FILE", "config.json"), ("HISTORY_FILE", "history.json"),
            ("ALERT_QUEUE_FILE", "alert_queue.json"), ("FILE_QUEUE_FILE", "file_queue.json"),
            ("IMAGE_STATE_FILE", "image_state.json"), ("LOG_FILE", "rdp_monitor.log"),
            ("AUDIT_FILE", "audit.json"), ("BLOCKED_FILE", "blocked.json"),
            ("TRAFFIC_FILE", "traffic.json")):
        globals()[variable] = os.path.join(BASE_DIR, filename)
    BACKUP_DIR = os.path.join(os.path.dirname(BASE_DIR), "backup")
    with _transport_lock:
        _event_sink, _artifact_sink, _session_sink = event_sink, artifact_sink, session_sink
        _agent_mode = True


def _emit_runtime(text):
    with _transport_lock:
        sink = _event_sink
    if sink is None:
        return False
    message = _strip_tags(str(text)).replace("\u200f", "")
    severity = "error" if "[X]" in message else (
        "warning" if any(t in message.upper() for t in ("WARN", "CRITICAL", "ALERT")) else "info")
    sink("monitor", message, severity)
    return True


def _artifact_runtime(path, caption, media_type):
    sink = getattr(_CAPTURE, "artifact_sink", None)
    if sink is None:
        with _transport_lock:
            sink = _artifact_sink
    if sink is None:
        return False
    sink(path, name=os.path.basename(path), media_type=media_type)
    if caption:
        _emit_runtime(caption)
    return True


def start_monitoring(read_only=False):
    """Start only monitoring/protection; no bot, panel, legacy backup worker."""
    global _engine_read_only
    with _engine_lock:
        if any(t.is_alive() for t in _engine_threads):
            return
        _engine_stop.clear()
        _engine_read_only = bool(read_only)
        load_history()
        load_audit()
        load_blocked()
        load_traffic()
        if not read_only:
            recover_image_state()
            if config.get("panic_active"):
                panic_rearm()
        _engine_threads[:] = [
            threading.Thread(target=read_only_monitor_loop if read_only else monitor_loop, name="monitor", daemon=True),
            threading.Thread(target=account_events_loop, name="account-events", daemon=True)]
        for thread in _engine_threads:
            thread.start()


def stop_monitoring():
    _engine_stop.set()
    for thread in tuple(_engine_threads):
        thread.join(timeout=65)
    save_history()
    save_traffic()

DEFAULT_CONFIG = {
    "telegram_token": "",            # Bot token from @BotFather
    "chat_id": "",                   # The Chat ID User’s own
    "send_backup_file": True,        # Send the finished backup archive via this bot (small files)
    "backup_file_max_mb": 45,        # Telegram Bot API upload limit is 50 MB
    # Limits of tiered alerts
    "cpu_alert_threshold": 50,       # Warning: Processor %
    "ram_alert_threshold": 50,       # Warning: rams %
    "danger_threshold": 80,          # Danger %
    "critical_threshold": 95,        # Critical %
    "alert_interval": 300,           # Alert period in seconds (5 Minutes)
    "spike_threshold": 30,           # Leap % Within a minute is a sudden spike
    "spike_cooldown": 600,           # Delay between spike alerts
    # Automatic restart
    "auto_restart_enabled": False,
    "auto_restart_cpu": 95,
    "auto_restart_ram": 95,
    "auto_restart_consecutive": 3,   # The number of consecutive minutes is over the limit
    "restart_delay_seconds": 30,
    "restart_cooldown": 900,
    # Discs
    "disk_threshold": 90,            # Alert when the disk is full %
    # Reports
    "daily_report_enabled": True,
    "daily_report_hour": 20,         # The hour 8 Evening
    "weekly_report_enabled": False,
    "weekly_report_day": 4,          # 0=Monday ... 4=Friday ... 6=Sunday
    "weekly_report_hour": 20,
    # network
    "speedtest_interval_hours": 0,   # 0 = Disabled, otherwise measure periodically every N hours
    # Monitor programs by name: [{"name": "chrome", "ram_mb": 3072}]
    "watch": [],
    # Control
    "exec_enabled": False,           # Allow an order /exec And/run (The most dangerous — Activate it
                                     # The moment of need /set exec on)
    "uploads_enabled": False,        # File reception is disabled by default; Activate it only when needed
    "upload_dir": "~/Downloads/RDPMonitor",
    "update_url": "",                # Direct link to a copy rdp_monitor.py New (https Only)
    "update_hash": "",                # Imprint SHA256 For the approved copy — /update Any non-matching file is rejected
    "user_management": False,        # Account management is disabled by default; Activate it only when needed
    "account_watch": True,           # Immediate alert upon any change in accounts (4720/4724/4725/4726...)
    # Sessions
    "session_alerts": True,          # Alert upon entry/User logout
    # Advanced security
    "instance_name": "",             # The name appears before each message (To distinguish multiple devices)
    "trusted_chat_ids": [],          # Additional Telegram accounts are allowed (legacy)
    "trusted_user_ids": [],          # Identifiers Telegram User ID Allowed to send orders
    "telegram_token_enc": "",        # The bot token is encrypted with DPAPI (Plain text is never written)
    "failed_login_alerts": True,     # Failed login attempts alert (breakthrough RDP)
    "failed_login_block": True,      # Ban IP Automatically in the firewall
    "failed_login_block_threshold": 10,  # Number of attempts before ban
    "failed_login_window": 15,       # Attempt counting window in minutes
    "failed_logon_types": "10",      # 10 = RDP Only (Safe). "3,10" Adds attempts NLA
                                     # Before authentication but including SMB Also (Risk of banning innocent people)
    "critical_alerts": True,         # Immediate alert of any critical event (Level 1) In the System and Applications logs
    "temp_threshold": 85,            # Heat alert °C
    "auto_lock_minutes": 0,          # Lock the session after inactivity (0 = Disabled)
    "auto_clean_enabled": False,     # Automatic weekly cleaning
    "auto_clean_day": 5,             # 0=Monday ... 5=Saturday
    "auto_clean_hour": 3,
    # RDP
    "rdp_port": 3389,                # outlet RDP Current (It changes with /setrdpport)
    "rdp_allowed_ips": [],           # Palace RDP On IP Specific (/rdpallow)
    "rdp_allow_active": False,       # Are the restriction rules activated?
    "rdp_allow_pre_active": False,   # Confinement status before locking (To continue after reboot)
    "rdpallow_disabled_rules": [],   # Broad rules of permission are invalidated by restrictions (Returned at clear)
    "pre_default_inbound": {},       # Original import policy before inventory (To undo)
    # Reliability and self-maintenance
    "muted_until": 0,                # Mutes regular notifications until this time (unix timestamp)
    "heartbeat_hours": 6,            # Message "It still works" Eat N hours (0 = Disabled)
    "keepalive": [],                 # Programs are automatically restarted: [{"name": "app.exe", "run": "Path"}]
    "rdp_watch": True,               # Outlet monitoring RDP: Alert + Restart the service if it stops
    "net_watch": True,               # Internet monitoring: Warning when cutting and returning
    "ping_target": "1.1.1.1",        # The target that checks to see the status of the Internet
    "update_check_hours": 24,        # Check for a newer version of update_url Eat N hours (0 = Disabled)
    "fw_guard": True,                # Firewall guarding: If it turns off, it activates it and notifies you
                                     # (All protection: Ban, confine, lock, panic - Depend on it)
    # Automatic locking against intrusion waves (Residential proxies are switched IP)
    "lockdown": False,               # Activate automatic lock
    "lockdown_limit": 30,            # Total failed attempts (Eat IP Combined) The one who works has the lock
    "lockdown_minutes": 60,          # Lock duration in minutes
    "auto_learn_ips": True,          # Learn IP Automatically log in RDP Successful (4624)
    "learn_for_lockdown": False,     # Login IP Learner in emergency lock automatically?
                                     # Default OK Manual Safer: Login success
                                     # It does not mean trust (Password theft = Reliable!) —
                                     # Activate it if IPAs a variable, you realize the trade-off
    "learned_ips": {},               # {ip: Last login success} - Educated whitelist
    "lockdown_until": 0,             # The expiry time of the current lock (0 = No lock)
    # Account for transferred data (The pendulum)
    "traffic_quota_gb": 0,           # Monthly quota in gigabytes (0 = Without share alert)
    "traffic_reset_day": 1,          # Quota reset day (Billing day) 1-28
    # Imaging the complete system (VHDX) And automatic upload
    "rclone_path": "",               # Path rclone.exe For automatic upload (Optional)
    "rclone_remote": "",             # Lifting remote such as gdrive:backups
    "image_delete_after": False,     # Delete the local copy after successful upload
    "image_enabled": False,          # System imaging is disabled by default; Heavy and delicate operation
    # Complete control and advanced protection
    "trap_users": [],                # Traps: Any attempt to log in with this name = Immediate permanent ban
    "subnetblock": False,            # Escalate the ban for a network /24 Complete
    "panic_active": False,           # Panic mode: RDP Completely closed (It remains after reboot)
    "new_ip_alerts": True,           # Alert upon successful entry from IP Never seen before
    "startup_report": False,         # Send a "Startup report" message each time the tool starts
    "baseline_alerts": False,        # Announce the learned-IP baseline on startup
    "rdphours": "",                  # Working hours RDP Like "9-23" (Empty = 24 hours)
    "rdpsched_blocked": False,       # Is a scheduling rule RDP Currently implemented?
    "selfheal_disk": False,          # Automatically clean up when the system disk is full 95%
    "svcwatch": [],                  # Services are monitored: [{"name": "W32Time"}] - If you stop, it will be repeated
}

config = {}
_config_lock = threading.Lock()

# ----------------------------- General condition -----------------------------

_net_speed = {"down": 0.0, "up": 0.0}
_last_net_time = 0.0
_last_net_counters = (0, 0)

_short = deque(maxlen=24)          # ~5s samples used for 60-second spike detection
_was_over = False
_last_alert_time = 0.0
_last_alert_level = "ok"          # Suppress repeats of the same level; escalate immediately
_last_spike = 0.0

_auto_streak = 0                   # Consecutive minutes above the auto-replay limit
_last_auto_check = 0.0
_last_auto_restart = 0.0

_disk_alerted = {}
_last_disk_check = 0.0

_watch_cooldown = {}
_last_watch_check = 0.0

_known_sessions = None
_last_session_check = 0.0

_history = []                      # [{"t": ts, "c": cpu, "r": ram}] Every minute
_last_history_append = 0.0
_last_history_save = 0.0

_last_speedtest = 0.0
_last_daily = None
_last_weekly = None

_failed_logins = {}                # {ip: {"times": [ts]}} Failed attempts
_seen_4625 = {}                    # {key: True} Failure events we read (Insert order)
_blocked = {}                      # {ip: ts} IP Blocked in firewall
_audit = []                        # Audit log
_session_locked = False
_last_lock_time = 0.0
_last_temp_check = 0.0
_last_temp_alert = 0.0
_last_failed_check = 0.0
_last_clean_day = None
_seen_critical = {}               # {key: True} Critical events we have read (Insert order)
_critical_baseline = False         # First reading of critical events = Reference point without alerts
_last_critical_check = 0.0
_last_heartbeat = 0.0              # Last pulse message
_keepalive_last = {}               # {name: ts} Last attempt to revive each program
_last_keepalive_check = 0.0
_rdp_down_since = None             # When did we notice that? RDP What he hears on his outlet
_last_rdp_check = 0.0
_last_rdp_restart = 0.0
_net_down_streak = 0               # Consecutive minutes in which the... ping
_last_net_watch = 0.0
_last_update_check = 0.0
_last_learn = 0.0                  # Last time we learned IP Success
_pre_lockdown_allow_active = None  # case rdp_allow_active Before locking (To undo)
_traffic = {}                      # {"YYYY-MM-DD": {"down": MB, "up": MB}}
_traffic_lock = threading.Lock()   # Guards _traffic against concurrent read/write
_last_traffic_counters = None      # (bytes_sent, bytes_recv) Last sample
_last_traffic_save = 0.0
_last_traffic_check = 0.0
_traffic_alerted = {}              # Quota alerts: {"YYYY-MM_50": True, ...}
_last_svcwatch_check = 0.0
_last_rdpsched_check = 0.0        # Last check to schedule hours RDP
_svcwatch_last = {}                # {name: ts} Last attempt to restart the service
_last_selfheal = 0.0               # Post self cleaning
_learn_alerts_ready = False        # First learn = Reference point without warning IP New
_seen_acct = {}                    # {key: True} Manage readable accounts events
_acct_baseline = False             # First reading of accounts events = Reference point

# ----------------------------- Imaging the complete system (VHDX) -----------------------------

DISK2VHD_URL = "https://download.sysinternals.com/files/Disk2vhd.zip"

_image_state = {                   # Status of the imaging process/Ongoing lifting
    "proc": None, "vhdx": None, "started": 0.0,
    "size_est": 0, "remote": None, "phase": None, "last_progress": 0.0,
}


class _RecoveredImageProcess:
    """Monitor PID After restarting RDP Monitor; He does not claim to know exit code The old one."""
    recovered = True

    def __init__(self, pid, created=None, executable=None):
        self.pid = int(pid)
        self.created = created
        self.executable = executable
        self.returncode = None

    def _process(self):
        if self.created is None or not self.executable:
            return None  # Legacy state cannot safely identify a recycled PID.
        p = psutil.Process(self.pid)
        if p.create_time() != self.created:
            return None
        exe = p.exe()
        if os.path.normcase(os.path.realpath(exe)) != \
                os.path.normcase(os.path.realpath(self.executable)):
            return None
        if os.path.basename(exe).lower() not in ("disk2vhd.exe", "disk2vhd64.exe"):
            return None
        return p

    def poll(self):
        try:
            if self._process() is not None:
                return None
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        self.returncode = 1  # The original exit code is unknown, never success.
        return self.returncode

    def kill(self):
        p = self._process()
        if p is None:
            raise RuntimeError("The recovered imaging process no longer matches its saved identity")
        p.kill()


def _persist_image_state():
    data = {k: v for k, v in _image_state.items() if k != "proc"}
    proc = _image_state.get("proc")
    data["pid"] = getattr(proc, "pid", None)
    if proc is not None:
        try:
            if getattr(proc, "recovered", False):
                data["proc_created"] = proc.created
                data["proc_executable"] = proc.executable
            else:
                p = psutil.Process(proc.pid)
                data["proc_created"] = p.create_time()
                data["proc_executable"] = p.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            data["proc_created"] = None
            data["proc_executable"] = None
    try:
        _atomic_write_json(IMAGE_STATE_FILE, data, ensure_ascii=False, indent=1)
    except Exception as e:
        print(f"[image] state save error: {e}")


def _find_rclone_upload_proc():
    """Return a psutil.Process for a running 'rclone copy' upload, or None."""
    try:
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                nm = (p.info.get("name") or "").lower()
                if not nm.startswith("rclone"):
                    continue
                cl = p.info.get("cmdline") or []
                if "copy" in cl:
                    return p
            except Exception:
                continue
    except Exception:
        pass
    return None


def _reattach_upload_watch(proc, path, remote):
    """Wait for a re-attached rclone upload to end, then report the result."""
    try:
        proc.wait()
    except Exception:
        pass
    name = os.path.basename(path or "image")
    remote = remote or config.get("rclone_remote") or ""
    ok, out = _rclone_run(["lsf", remote.rstrip("/") + "/" + name], timeout=120)
    if ok and out.strip():
        url = _rclone_link(remote, name)
        msg = ("[OK] <b>Upload complete</b>\n"
               "File: <code>" + esc(name) + "</code>\n"
               "To: <b>" + esc(remote) + "</b>")
        if url:
            msg += "\nShare link: " + esc(url)
        send_message(msg)
    else:
        send_message("[X] <b>Upload ended</b> but the file is not on the remote.\n"
                     "Check /rclone test and retry /image upload.")
    _image_state["phase"] = "done"
    _persist_image_state()


def recover_image_state():
    """Restores control Disk2vhd Or clearly reports a process that has been interrupted."""
    if not os.path.exists(IMAGE_STATE_FILE):
        return
    try:
        with open(IMAGE_STATE_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
        phase = saved.get("phase")
        if phase == "imaging" and saved.get("pid"):
            proc = _RecoveredImageProcess(saved["pid"], saved.get("proc_created"),
                                          saved.get("proc_executable"))
            if proc.poll() is None:
                _image_state.update(saved)
                _image_state["proc"] = proc
                threading.Thread(target=_image_watch, daemon=True).start()
                send_message("I regained practical control Disk2vhd That was working before restarting the tool.")
                return
        if phase == "uploading":
            proc = _find_rclone_upload_proc()
            if proc is not None:
                _image_state.update(saved)
                _image_state["phase"] = "uploading"
                _image_state["proc"] = proc
                _persist_image_state()
                threading.Thread(target=_reattach_upload_watch,
                                 args=(proc, saved.get("vhdx"), saved.get("remote")),
                                 daemon=True).start()
                send_message("<b>Upload re-attached</b>\n"
                             "An upload from before the restart is still running; "
                             "I will report when it finishes.")
                return
        if phase in ("imaging", "uploading"):
            _image_state.update(saved)
            _image_state["proc"] = None
            _image_state["phase"] = "done"
            _persist_image_state()
            what = "upload" if phase == "uploading" else "imaging"
            send_message("<b>Interrupted " + what + "</b>\n"
                         "The tool restarted while this job was running, so its result is "
                         "unknown.\nFile: <code>" + esc(str(saved.get("vhdx") or "unknown")) +
                         "</code>\nVerify it, then retry with /image " +
                         ("upload" if phase == "uploading" else "start") + ".")
    except Exception as e:
        print(f"[image] state recovery error: {e}")


def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _find_disk2vhd():
    """Looking for disk2vhd In the tool folder or PATH"""
    for name in ("disk2vhd64.exe", "disk2vhd.exe"):
        p = os.path.join(BASE_DIR, name)
        if os.path.isfile(p):
            return p
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        for name in ("disk2vhd64.exe", "disk2vhd.exe"):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return None


def _microsoft_signed(path):
    """Return (ok, status, subject) for a Microsoft Authenticode-signed binary.

    A valid signature alone is not enough: the signer subject must name Microsoft,
    because any signed file would otherwise pass.
    """
    sig = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"$s = Get-AuthenticodeSignature -LiteralPath '{_ps_quote(path)}'; "
         f"$sub = if ($s.SignerCertificate) {{ $s.SignerCertificate.Subject }} else {{ '' }}; "
         f"Write-Output ($s.Status.ToString() + '|' + $sub)"],
        capture_output=True, timeout=60, creationflags=NO_WINDOW)
    status, _, subject = _decode_out(sig.stdout).strip().partition("|")
    microsoft_signer = bool(re.search(
        r"(?:^|,\s*)CN=Microsoft Corporation(?:,|$)", subject, flags=re.I))
    return (status.lower() == "valid" and microsoft_signer), status, subject


def _download_disk2vhd():
    """Download Disk2vhd, verify its Microsoft Authenticode publisher, then deploy it.

    The archive is extracted into a private staging directory and only the signed
    binaries are copied into the tool folder, so a tampered or unexpected archive
    can never write arbitrary files next to the agent.
    """
    import shutil
    import tempfile
    import zipfile
    try:
        r = requests.get(DISK2VHD_URL, timeout=120)
        r.raise_for_status()
        with tempfile.TemporaryDirectory(prefix="disk2vhd-") as staging:
            zpath = os.path.join(staging, "Disk2vhd.zip")
            with open(zpath, "wb") as f:
                f.write(r.content)
            with zipfile.ZipFile(zpath) as z:
                z.extractall(staging)
            deployed = []
            for name in ("disk2vhd64.exe", "disk2vhd.exe"):
                candidate = os.path.join(staging, name)
                if not os.path.isfile(candidate):
                    continue
                ok, status, subject = _microsoft_signed(candidate)
                if not ok:
                    print("[image] disk2vhd rejected: %s status=%s signer=%s"
                          % (name, status, subject[:60]))
                    return None
                shutil.copyfile(candidate, os.path.join(BASE_DIR, name))
                deployed.append(name)
            if not deployed:
                print("[image] disk2vhd archive contained no expected executable")
                return None
        return _find_disk2vhd()
    except Exception as e:
        print(f"[image] disk2vhd download error: {e}")
        return None


def _pick_image_target(need_bytes):
    """Selects the most suitable disk to receive the image: Irregular with space, otherwise the largest space"""
    sys_drive = os.environ.get("SystemDrive", "C:").upper()
    candidates = []
    for part in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(part.mountpoint)
            candidates.append((part.mountpoint, part.device, u.free))
        except Exception:
            pass
    if not candidates:
        return os.path.expanduser("~"), 0
    for mp, dev, free in candidates:
        if not dev.upper().startswith(sys_drive) and free >= need_bytes:
            return mp, free
    mp, _dev, free = max(candidates, key=lambda x: x[2])
    return mp, free


def _fixed_volumes_used():
    """Total used bytes across fixed volumes, for the free-space estimate."""
    total = 0
    for part in psutil.disk_partitions(all=False):
        try:
            total += psutil.disk_usage(part.mountpoint).used
        except Exception:
            pass
    return total or psutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\").used


def image_progress_line():
    """Current shooting progress line"""
    st = _image_state
    try:
        target = st["vhdx"]
        stem = os.path.splitext(os.path.basename(target))[0].lower()
        done = sum(os.path.getsize(os.path.join(os.path.dirname(target), name))
                   for name in os.listdir(os.path.dirname(target))
                   if name.lower().endswith(".vhdx")
                   and (name.lower() == stem + ".vhdx"
                        or name.lower().startswith(stem + "-")))
    except (OSError, KeyError, TypeError):
        done = 0
    est = st.get("size_est") or 1
    pct = min(100.0, done / est * 100)
    elapsed = int(time.time() - st["started"])
    return (f"{pct:.0f}% ({format_size(done)} of ~{format_size(est)}) "
            f"- elapsed {format_duration(elapsed)}")


def image_start(remote=None, *, watch=True, volumes="*", target_dir=None, vss=True):
    """Depicts the complete system VHDX And the system is working (Shadow Copy) He raises it later if he kicks it correctly"""
    if _image_state.get("phase") in ("imaging", "uploading"):
        send_message("In the process of filming/Upload is currently working - Status: /image")
        return
    if not _is_admin():
        send_message("[X] Photography requires administrator privileges - Run the tool as administrator (install.bat)")
        return
    vhdexe = _find_disk2vhd()
    if not vhdexe:
        send_message(" I didn’t find anything Disk2vhd - Download it now from the official Microsoft website...")
        vhdexe = _download_disk2vhd()
        if not vhdexe:
            send_message("[X] Download failed Disk2vhd (network?) - Download it manually:\n"
                         "https://download.sysinternals.com/files/Disk2vhd.zip\n"
                         "Unzip the files in the tool folder and then restore /image start")
            return
    sys_drive = os.environ.get("SystemDrive", "C:")
    used = _fixed_volumes_used()
    # Margin 5 GB: the image grows while imaging and Windows keeps writing to disk.
    need = used + 5 * 1024 ** 3
    out_dir, free = ((os.fspath(target_dir), psutil.disk_usage(target_dir).free)
                     if target_dir else _pick_image_target(need))
    same_drive = out_dir[:2].upper() == sys_drive.upper()
    out_path = os.path.join(out_dir,
                            f"FULLSYSTEM_{datetime.now():%Y%m%d_%H%M%S_%f}.vhdx")
    if free < need:
        send_message(
            f"[X] There is not enough space for the image\n"
            f" Used on fixed volumes: {format_size(used)}\n"
            f" Free on {out_dir}: {format_size(free)}\n"
            "The image needs at least as much space as your data used.\n"
            "Free up space (/clean helps) or attach a second disk."
        )
        return
    if same_drive:
        send_message(
            "[WARN] No second disk with enough free space was found - the image "
            "will be written to the system disk.\n"
            "The free-space check passed, but keep Console access: if this disk "
            "fills up, Windows can become unreachable.")
    try:
        # Verify the Authenticode signature and the signer identity before running:
        # the executable is fetched from the Internet, so a valid signature alone is
        # not enough — the signer must be Microsoft/Sysinternals.
        ok, status, subject = _microsoft_signed(vhdexe)
        if not ok:
            send_message("[X] Signature Disk2vhd Invalid or not signed "
                         "Microsoft/Sysinternals — I canceled filming and nothing happened\n"
                         f"Status: {esc(status)} | Signer: {esc(subject[:60])}")
            audit_record("System imaging was cancelled: Signature Disk2vhd Rejected")
            return
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        # Disk2vhd's CLI needs a leading option; with none it prints usage and
        # hangs. "-c" copies volumes directly (VSS is unavailable on some hosts)
        # and "*" includes every volume, so the System Reserved / boot partition
        # is captured and the image boots on another VM.
        proc = subprocess.Popen([vhdexe] + ([] if vss else ["-c"]) + [volumes, out_path],
                                creationflags=flags,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        # Disk2vhd shows its usage dialog and hangs when arguments are rejected,
        # so detect an immediate exit instead of reporting a false "started".
        time.sleep(3)
        if proc.poll() is not None:
            send_message("[X] Disk2vhd exited immediately - imaging did not start "
                         "(arguments rejected). Nothing was written; check the log.")
            audit_record("System imaging failed to start (disk2vhd rejected args)")
            return
    except Exception as e:
        send_message(f"[X] Failed to start shooting: {e}")
        return
    _image_state.update({"proc": proc, "vhdx": out_path, "started": time.time(),
                         "size_est": used, "remote": remote,
                         "phase": "imaging", "last_progress": time.time()})
    _persist_image_state()
    audit_record(f"System imaging has begun: {out_path}")
    send_message(
        "<b>Imaging started</b>\n"
        "Data to image: " + format_size(used) + "\n"
        "Destination: <code>" + esc(out_path) + "</code>\n"
        "Free on destination: " + format_size(free) + "\n"
        "Windows keeps running during the copy.\n"
        "Progress is reported every 10 minutes; check anytime with /image status.\n"
        "Stop: /image stop"
    )
    if watch:
        threading.Thread(target=_image_watch, daemon=True).start()


def _image_watch():
    """Monitors the shooting process: Periodic progress + Completion → Auto upload"""
    while True:
        st = _image_state
        proc = st.get("proc")
        if st.get("phase") != "imaging" or not proc:
            return
        time.sleep(30)
        if st.get("phase") != "imaging":
            return
        if proc.poll() is not None:
            _image_finish()
            return
        now_ts = time.time()
        if now_ts - st.get("last_progress", 0) >= 600:
            st["last_progress"] = now_ts
            send_message("<b>Imaging</b> " + image_progress_line())


def _image_finish(upload_sync=False):
    """When filming is complete: Report + Auto upload if there is a destination"""
    st = _image_state
    proc = st.get("proc")
    path = st.get("vhdx")
    # Disk2vhd may append a physical-disk suffix. Only accept outputs with
    # this job's unique base name, created after this job started.
    paths = []
    if path:
        stem = os.path.splitext(os.path.basename(path))[0].lower()
        directory = os.path.dirname(path)
        try:
            paths = [os.path.join(directory, name) for name in os.listdir(directory)
                     if name.lower().endswith(".vhdx")
                     and (name.lower() == stem + ".vhdx"
                          or name.lower().startswith(stem + "-"))
                     and os.path.getmtime(os.path.join(directory, name)) >= st.get("started", 0) - 2
                     and os.path.getsize(os.path.join(directory, name)) > 0]
        except OSError:
            paths = []
    st["vhdx_files"] = sorted(paths)
    if paths:
        path = paths[0]
        st["vhdx"] = path
    if getattr(proc, "recovered", False):
        st["phase"] = "done"
        _persist_image_state()
        send_message("<b>Imaging finished (recovered)</b>\n"
                     "The imaging process ended after a tool restart, so I cannot confirm "
                     "the exit code and will not auto-upload.\n"
                     "Verify the file, then upload it with /image upload:\n<code>"
                     + esc(str(path or "unknown")) + "</code>")
        return
    ok = proc is not None and proc.returncode == 0 and bool(paths)
    if not ok:
        st["phase"] = None
        _persist_image_state()
        audit_record("System imaging failed")
        send_message("[X] <b>Imaging failed</b> - see rdp_monitor.log for details.\n"
                     "Nothing was uploaded.")
        return
    size = sum(os.path.getsize(item) for item in paths)
    st["phase"] = "done"
    _persist_image_state()
    audit_record(f"System imaging is complete: {path} ({format_size(size)})")
    msg = ("[OK] <b>Imaging complete</b>\n"
           "Files: " + str(len(paths)) + "\n" +
           "\n".join("<code>" + esc(item) + "</code>" for item in paths) + "\n"
           "Size: " + format_size(size) + "\n"
           "Took: " + format_duration(time.time() - st["started"]))
    remote = st.get("remote") or config.get("rclone_remote")
    if remote:
        if _find_rclone():
            send_message(msg)
            if upload_sync:
                _upload_image_set(paths, remote)
            else:
                threading.Thread(target=_upload_image_set, args=(paths, remote),
                                 daemon=True).start()
            return
        msg += ("\n[WARN] rclone is not installed, so auto-upload is off.\n"
                "Set it up with /rclone install, then upload this file with /image upload.")
    send_message(msg)


def _find_rclone():
    """Looking for rclone: Saved path, tool folder, or PATH"""
    p = config.get("rclone_path", "")
    if p and os.path.isfile(p):
        return p
    for name in ("rclone.exe", "rclone"):
        p2 = os.path.join(BASE_DIR, name)
        if os.path.isfile(p2):
            return p2
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        for name in ("rclone.exe", "rclone"):
            p2 = os.path.join(d, name)
            if os.path.isfile(p2):
                return p2
    return None


def _parse_rclone_size(tok):
    m = re.match(r"\s*([\d.]+)\s*([KMGTP]?i?B)", tok)
    if not m:
        return None
    try:
        val = float(m.group(1))
    except ValueError:
        return None
    unit = m.group(2).lower()
    mult = {"b": 1, "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3, "tib": 1024 ** 4,
            "kb": 1000, "mb": 1000 ** 2, "gb": 1000 ** 3, "tb": 1000 ** 4}
    return int(val * mult.get(unit, 1))


def _parse_rclone_stats(line):
    """Return (transferred_bytes, total_bytes, percent) from an rclone stats line."""
    m = re.search(
        r"([\d.]+\s*[KMGTP]?i?B)\s*/\s*([\d.]+\s*[KMGTP]?i?B)\s*[,\s]+(\d{1,3})%", line)
    if m:
        return (_parse_rclone_size(m.group(1)), _parse_rclone_size(m.group(2)),
                int(m.group(3)))
    m = re.search(r"(\d{1,3})%", line)
    if m:
        return None, None, int(m.group(1))
    return None, None, None


def _rclone_link(remote, filename):
    """Return a shareable link for an uploaded file, or ''."""
    full = remote.rstrip("/") + "/" + filename
    ok, out = _rclone_run(["link", full], timeout=60)
    if ok:
        for ln in out.splitlines():
            ln = ln.strip()
            if ln.startswith("http"):
                return ln
    return ""


def image_upload_chart():
    """Send a chart of uploaded GB over time for the running/finished upload."""
    samples = _image_state.get("upload_samples") or []
    if len(samples) < 2:
        send_message("Not enough progress data yet - try again in a few minutes.")
        return
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        send_message("[X] Charts need matplotlib: " + esc(str(e)))
        return
    xs = [s[0] for s in samples]
    gbs = [(s[2] or 0) / (1024 ** 3) for s in samples]
    pcts = [s[1] for s in samples]
    name = os.path.basename(_image_state.get("vhdx") or "image")
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.plot(xs, gbs, color="#2563eb", linewidth=2, marker="o", markersize=3)
    ax.set_title("Upload progress - " + name)
    ax.set_xlabel("Minutes")
    ax.set_ylabel("Uploaded (GB)")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    path = os.path.join(BASE_DIR, "upload_chart.png")
    fig.savefig(path, dpi=110)
    plt.close(fig)
    last = samples[-1]
    send_photo(path, "<b>Upload progress</b>\n"
                     f"{last[1]}% - {last[2] / (1024 ** 3):.2f} GB uploaded\n"
                     "To: " + esc(_image_state.get("remote") or ""))





def _verify_remote_image(path, remote):
    """Check that rclone reports the expected byte count at the destination."""
    target = remote.rstrip("/") + "/" + os.path.basename(path)
    ok, output = _rclone_run(["size", "--json", target], timeout=120)
    if not ok:
        return False
    try:
        result = json.loads(output)
        return result.get("count") == 1 and result.get("bytes") == os.path.getsize(path)
    except (ValueError, OSError, TypeError):
        return False


def _upload_image_set(paths, remote):
    """Upload every disk image before allowing local cleanup."""
    for path in paths:
        if not _upload_job(path, remote, delete_after=False, finalize_phase=False):
            _image_state["phase"] = "done"
            _persist_image_state()
            send_message("[X] The image set is incomplete on the remote. Local files were kept.")
            return
    if config.get("image_delete_after"):
        if not all(_verify_remote_image(path, remote) for path in paths):
            _image_state["phase"] = "done"
            _persist_image_state()
            send_message("[WARN] Remote image set verification failed. Local files were kept.")
            return
        for path in paths:
            try:
                os.remove(path)
            except OSError as e:
                send_message("[WARN] Could not delete <code>" + esc(path) + "</code>: " + esc(str(e)))
    _image_state["phase"] = "done"
    _persist_image_state()
    send_message("[OK] <b>System image set uploaded</b>\n"
                 f"Files: {len(paths)}\nDestination: <code>{esc(remote)}</code>")


def _upload_job(path, remote, delete_after=None, finalize_phase=True):
    """Upload a local image file to the rclone remote, reporting progress and result."""
    rc = _find_rclone()
    name = os.path.basename(path)
    if not rc:
        send_message("[X] <b>Upload not started</b> - rclone is not installed.\n"
                     "Install it with /rclone install, then retry /image upload.")
        if finalize_phase:
            _image_state["phase"] = "done"
            _persist_image_state()
        return False
    try:
        size = os.path.getsize(path)
    except OSError as e:
        send_message("[X] <b>Upload failed</b> - cannot read the file:\n"
                     + esc(name) + "\n" + esc(str(e)))
        if finalize_phase:
            _image_state["phase"] = "done"
            _persist_image_state()
        return False
    started = time.time()
    _image_state.update({"phase": "uploading", "vhdx": path, "remote": remote,
                         "upload_pct": 0, "upload_started": started,
                         "upload_detail": "", "upload_samples": []})
    _persist_image_state()
    audit_record("Upload started: %s -> %s" % (path, remote))
    send_message("[UP] <b>Upload started</b>\n"
                 "File: <code>" + esc(name) + "</code>\n"
                 "Size: " + format_size(size) + "\n"
                 "To: <b>" + esc(remote) + "</b>\n"
                 "I will report progress and the final result. Chart: /image chart")
    pct = 0
    out = ""
    samples = []
    logf = os.path.join(_rclone_dir(), "upload.log")
    try:
        open(logf, "w").close()
    except OSError:
        pass
    try:
        proc = subprocess.Popen(
            [rc, "--config", _rclone_conf_path(), "copy", path, remote,
             "--transfers", "4", "--stats", "15s", "--stats-one-line",
             "--log-file", logf, "--log-level", "INFO"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=NO_WINDOW)
        _image_state["proc"] = proc
        last_report = time.time()
        last_line = None
        while proc.poll() is None:
            time.sleep(5)
            try:
                with open(logf, "r", encoding="utf-8", errors="replace") as f:
                    logtext = f.read()
            except OSError:
                logtext = ""
            latest = None
            for ln in reversed(logtext.splitlines()):
                if "%" in ln and "/" in ln:
                    latest = ln.strip()
                    break
            if latest and latest != last_line:
                last_line = latest
                tr, _tot, p = _parse_rclone_stats(latest)
                if p is not None:
                    pct = p
                detail = re.sub(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \S+\s*:\s*", "",
                                latest).strip()
                samples.append([round((time.time() - started) / 60.0, 2), pct, tr or 0])
                _image_state["upload_pct"] = pct
                _image_state["upload_detail"] = detail
                _image_state["upload_samples"] = samples[-3000:]
            if time.time() - last_report >= 300:
                last_report = time.time()
                send_message("[UP] <b>Uploading</b>\n" +
                             esc(_image_state.get("upload_detail") or (str(pct) + "%")) +
                             "\n" + esc(name) + " -> " + esc(remote) +
                             "\nChart: /image chart")
        time.sleep(1)
        rc_ok = (proc.returncode == 0)
        try:
            with open(logf, "r", encoding="utf-8", errors="replace") as f:
                out = f.read()
        except OSError:
            out = ""
    except Exception as e:
        send_message("[X] <b>Upload failed</b>\nFile: <code>" + esc(name) + "</code>\n"
                     "To: <b>" + esc(remote) + "</b>\nError: " + esc(str(e)))
        if finalize_phase:
            _image_state["phase"] = "done"
            _persist_image_state()
        return False
    dur = format_duration(time.time() - started)
    if rc_ok:
        audit_record("Upload complete: %s -> %s" % (path, remote))
        msg = ("[OK] <b>Upload complete</b>\n"
               "File: <code>" + esc(name) + "</code> (" + format_size(size) + ")\n"
               "To: <b>" + esc(remote) + "</b>\n"
               "Took: " + dur)
        link = _rclone_link(remote, name)
        if link:
            msg += "\nShare link: " + esc(link)
        if delete_after is None:
            delete_after = bool(config.get("image_delete_after"))
        if delete_after:
            if not _verify_remote_image(path, remote):
                send_message("[WARN] rclone returned success, but the remote file size "
                             "could not be verified. Local copy kept: <code>" +
                             esc(path) + "</code>")
                if finalize_phase:
                    _image_state["phase"] = "done"
                    _persist_image_state()
                return False
            try:
                os.remove(path)
                msg += "\nLocal copy deleted (image_delete_after is on)."
            except OSError as e:
                msg += "\nCould not delete the local copy: " + esc(str(e))
        send_message(msg)
    else:
        send_message("[X] <b>Upload failed</b>\n"
                     "File: <code>" + esc(name) + "</code>\n"
                     "To: <b>" + esc(remote) + "</b>\n"
                     "After " + dur + ". Reason:\n" + esc(out[-600:] or "(no details)"))
    if finalize_phase:
        _image_state["phase"] = "done"
        _persist_image_state()
    return rc_ok


def _image_search_roots():
    """Folders where a FULLSYSTEM image may live: tool dir, last target, drive roots."""
    roots = [BASE_DIR]
    st = _image_state.get("vhdx")
    if st:
        roots.append(os.path.dirname(st))
    for part in psutil.disk_partitions(all=False):
        roots.append(part.mountpoint)
    out, seen = [], set()
    for r in roots:
        if r and os.path.isdir(r):
            a = os.path.abspath(r)
            if a not in seen:
                seen.add(a)
                out.append(a)
    return out


def image_list_files():
    """Existing FULLSYSTEM_*.vhdx files, newest first."""
    found, seen = [], set()
    for root in _image_search_roots():
        try:
            for x in os.listdir(root):
                if x.lower().startswith("fullsystem_") and x.lower().endswith(".vhdx"):
                    p = os.path.join(root, x)
                    ap = os.path.abspath(p)
                    if ap not in seen:
                        seen.add(ap)
                        found.append(p)
        except OSError:
            pass
    found.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return found











# ----------------------------- rclone setup from chat -----------------------------
# Lets the user install rclone and create cloud remotes entirely from Telegram,
# without touching the machine. Remotes live in one shared rclone.conf so the
# monitor and the SYSTEM backup worker both see them.




# Remote types that need a browser OAuth sign-in; create these with a token.



def _rclone_dir():
    return os.path.join(BACKUP_DIR, "rclone")


def _rclone_conf_path():
    d = _rclone_dir()
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "rclone.conf")
    if not os.path.exists(p):
        try:
            open(p, "a", encoding="utf-8").close()
        except OSError:
            pass
    return p


def _rclone_exe():
    exe = _find_rclone()
    if exe:
        return exe
    local = os.path.join(_rclone_dir(), "rclone.exe")
    return local if os.path.isfile(local) else None


def _rclone_run(args, timeout=120):
    """Run rclone against the shared config. Returns (ok, combined output)."""
    exe = _rclone_exe()
    if not exe:
        return False, "rclone is not installed - run /rclone install first"
    try:
        r = subprocess.run([exe, "--config", _rclone_conf_path()] + list(args),
                           capture_output=True, timeout=timeout,
                           creationflags=NO_WINDOW)
        out = (_decode_out(r.stdout) + "\n" + _decode_out(r.stderr)).strip()
        return r.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, "rclone timed out"
    except Exception as e:
        return False, repr(e)












































_state_lock = threading.Lock()     # Lock the writing of state files (history/audit/blocked)
_busy_checks = set()               # Tests are running now - Prevents overlapping of two parallel copies
_busy_lock = threading.Lock()


def _check_start(name):
    """True If we start the examination now - False If a copy of it is working (Its cycle is longer than scheduling)"""
    with _busy_lock:
        if name in _busy_checks:
            return False
        _busy_checks.add(name)
        return True


def _check_end(name):
    with _busy_lock:
        _busy_checks.discard(name)

RDP_STATE_WORDS = {"active", "disc", "conn", "idle", "Active", "Online", "Cut", "Inactive"}


_instance_mutex = None


def _instance_mutex_name():
    """Fixed name for each installed instance, with no port occupation TCP Or conflict with other programs."""
    install_id = hashlib.sha256(BASE_DIR.lower().encode("utf-8")).hexdigest()[:20]
    return "Global\\RDPMonitor_" + install_id


def acquire_instance_lock():
    """Lock Windows mutex Real: A second copy cannot choose an alternative port and start."""
    global _instance_mutex
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.CreateMutexW(None, False, _instance_mutex_name())
        if not handle:
            print("[lock] CreateMutexW failed")
            return False
        if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            return False
        _instance_mutex = handle
        return True
    except Exception as e:
        print(f"[lock] mutex error: {e}")
        return False


# ----------------------------- Settings: Save/Download -----------------------------

# ----------------------------- Token encryption (DPAPI) -----------------------------

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi_blob(data):
    buf = ctypes.create_string_buffer(data, len(data))
    ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))
    blob = _DATA_BLOB(len(data), ptr)
    blob._buf = buf  # Prevent memory from being released before the call finishes
    return blob


def dpapi_protect(plain):
    """Encrypt text with word/mechanism Windows DPAPI - It can only be unlocked for the same user on the same device"""
    in_blob = _dpapi_blob(plain.encode("utf-8"))
    out = _DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise OSError("CryptProtectData failed")
    try:
        return base64.b64encode(
            ctypes.string_at(out.pbData, out.cbData)).decode("ascii")
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def dpapi_unprotect(b64):
    """Decrypt DPAPI - It fails if the user or device changes"""
    raw = base64.b64decode(b64)
    in_blob = _dpapi_blob(raw)
    out = _DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


_acl_warned = {"config": False, "dir": False}


def _harden_config_acl(path=None):
    """Reducing powers config.json On Administrators/SYSTEM Only (Best effort)"""
    try:
        r = subprocess.run(
            ["icacls", path or CONFIG_FILE, "/inheritance:r",
             "/grant:r", "*S-1-5-32-544:F", "*S-1-5-18:F"],
            capture_output=True, timeout=15, creationflags=NO_WINDOW)
        if r.returncode != 0 and not _acl_warned["config"]:
            _acl_warned["config"] = True
            print("[security] WARNING: could not restrict config.json permissions (icacls failed)")
    except Exception as e:
        if not _acl_warned["config"]:
            _acl_warned["config"] = True
            print(f"[security] WARNING: config.json ACL hardening error: {e}")








def _clamp_config_int(key, low, high):
    try:
        config[key] = max(low, min(high, int(config.get(key, low))))
    except (TypeError, ValueError):
        config[key] = int(DEFAULT_CONFIG[key])


def _normalize_config():
    """Security limits also apply to config.json Manually modified or coming from an old version."""
    for key in ("cpu_alert_threshold", "ram_alert_threshold",
                "danger_threshold", "critical_threshold", "spike_threshold"):
        _clamp_config_int(key, 1, 100)
    _clamp_config_int("disk_threshold", 10, 99)
    _clamp_config_int("alert_interval", 30, 86400)
    _clamp_config_int("auto_restart_cpu", 50, 100)
    _clamp_config_int("auto_restart_ram", 50, 100)
    _clamp_config_int("auto_restart_consecutive", 1, 60)
    _clamp_config_int("failed_login_block_threshold", 1, 100)
    _clamp_config_int("lockdown_minutes", 1, 1440)
    _clamp_config_int("temp_threshold", 40, 120)
    _clamp_config_int("failed_login_window", 1, 1440)
    _clamp_config_int("weekly_report_day", 0, 6)
    _clamp_config_int("auto_clean_day", 0, 6)
    _clamp_config_int("auto_clean_hour", 0, 23)
    _clamp_config_int("daily_report_hour", 0, 23)
    _clamp_config_int("weekly_report_hour", 0, 23)
    _clamp_config_int("heartbeat_hours", 0, 720)
    _clamp_config_int("update_check_hours", 0, 720)
    _clamp_config_int("speedtest_interval_hours", 0, 720)
    _clamp_config_int("auto_lock_minutes", 0, 1440)
    if str(config.get("failed_logon_types")) not in ("10", "3,10", "10,3"):
        config["failed_logon_types"] = "10"


def load_config():
    global config, CONFIG_LOAD_OK
    saved = {}
    CONFIG_LOAD_OK = False
    # We read the main one first, and if it is damaged, we return to the backup copy .bak
    for path in (CONFIG_FILE, CONFIG_FILE + ".bak"):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    candidate = json.load(f)
                if not isinstance(candidate, dict):
                    raise ValueError("configuration must be a JSON object")
                saved = candidate
                CONFIG_LOAD_OK = True
                break
            except Exception:
                continue  # Corrupt file - We try the next one
    config = copy.deepcopy(DEFAULT_CONFIG)
    config.update(saved)
    _normalize_config()
    # Token migration to crypto: Existing plaintext from an older version is encrypted and deleted
    if config.get("telegram_token_enc"):
        try:
            config["telegram_token"] = dpapi_unprotect(
                config["telegram_token_enc"])
        except Exception:
            config["telegram_token"] = ""   # Device/Different user - We request the token again
            print("[config] token decryption failed - setup required")
    elif config.get("telegram_token"):
        try:
            config["telegram_token_enc"] = dpapi_protect(
                config["telegram_token"])
            print("[config] plaintext token migrated to DPAPI encryption")
        except Exception:
            pass


def save_config():
    """Atomic conservation: We write to a temporary file and then replace - A power outage corrupts the file
    - The explicit token is never written to disk (encryption DPAPI Only)"""
    with _config_lock:
        tmp = CONFIG_FILE + ".tmp"
        try:
            # dict(config) is a single C-level copy, so it cannot observe a
            # concurrent insert from another thread mid-iteration.
            snapshot = dict(config)
            persist = {k: v for k, v in snapshot.items()
                       if k != "telegram_token"}
            if snapshot.get("telegram_token"):
                # If setup/migration could not encrypt, fail without discarding
                # the only credential or replacing the previous configuration.
                persist["telegram_token_enc"] = dpapi_protect(snapshot["telegram_token"])
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(persist, f, indent=2, ensure_ascii=False)
            if os.path.exists(CONFIG_FILE):
                bak = CONFIG_FILE + ".bak"
                try:
                    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                        previous = json.load(f)
                except (OSError, ValueError):
                    previous = None
                if isinstance(previous, dict):
                    token = previous.pop("telegram_token", "")
                    if token:
                        previous["telegram_token_enc"] = dpapi_protect(token)
                    if not _atomic_write_json(bak, previous, indent=2, ensure_ascii=False):
                        raise OSError("could not persist configuration backup")
                    _harden_config_acl(bak)
            os.replace(tmp, CONFIG_FILE)
            # os.replace Creates a new file that inherits the folder’s permissions - We?re shrinking it again
            # After each replacement without dilution: The ten minute window was leaving the file
            # Readable for Users After the second save, it is included
            _harden_config_acl()
            if snapshot.get("telegram_token"):
                config["telegram_token_enc"] = persist["telegram_token_enc"]
            return True
        except Exception as e:
            print(f"[config] save error: {e}")
            try:
                os.remove(tmp)
            except OSError:
                pass
            return False


_OEM_CP = ""


def _oem_cp():
    """encoding OEM For console (net.exe And qwinsta.exe And cmd.exe They issue it)
    - Mostly in Arabic cp720 - Unscrew UTF-8 It distorts Arabic usernames"""
    global _OEM_CP
    if not _OEM_CP:
        try:
            _OEM_CP = f"cp_{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:
            _OEM_CP = "cp437"
    return _OEM_CP


def _decode_out(b):
    """Decode Windows command output into correct console encoding"""
    if not b:
        return ""
    try:
        return b.decode(_oem_cp(), "replace")
    except Exception:
        return b.decode("utf-8", "replace")


def _atomic_write_json(path, data, **json_kwargs):
    """Atomic writing of state files: Temporary file + os.replace
    - Direct writing would corrupt the file if the power was cut off while writing
      (The tool checks the ban history/Complete audit silently)"""
    with _state_lock:
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, **json_kwargs)
            os.replace(tmp, path)
            return True
        except Exception as e:
            print(f"[state] save error ({os.path.basename(path)}): {e}")
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return False





LOG_FILE = os.path.join(BASE_DIR, "rdp_monitor.log")











# ----------------------------- Telegram -----------------------------













# ----------------------------- Queue pending alerts -----------------------------
# Permanent queue on disk: Restart the tool or Windows do not lose text alerts.





























# When the WebConsole panel asks for a read-only report, the bot's own
# formatting helpers are redirected into this buffer instead of Telegram.
_CAPTURE = threading.local()








def _capture_add(text):
    lines = getattr(_CAPTURE, "lines", None)
    if lines is not None:
        lines.append(_strip_tags(str(text)).replace("\u200f", ""))
        return True
    return False


def send_message(text):
    if _capture_add(text) or _emit_runtime(text):
        return
    raise RuntimeError("The monitoring engine requires an agent event sink")


def _strip_tags(text):
    """He removes tags HTML From the text - For places that are sent without analysis HTML"""
    return re.sub(r"</?[a-zA-Z][^>]*>", "", text)


RLM = "\u200f"  # Right turn sign-left







def rtl(text):
    """Forces direction RTL On the line - It is prohibited to mix numbers and English with Arabic"""
    return RLM + text


def esc(text):
    """Smuggling typefaces HTML For dynamic content (Process names, event messages...)"""
    return html.escape(str(text), quote=False)





def send_buttons(text, rows):
    send_message(text)


# ----------------------------- Queue of deferred buttons (Confirm/Deny) -----------------------------
# Telegram limit 64 byte on callback_data: The entire command is stored in memory and the button holds only its identifier
                      # {id: {"cmd": Text} Or {"fn": function, "args": tuple}}


                 # Confirm button expired: 30 Minute














# ----------------------------- Unified suite: WebConsole + Backup -----------------------------
# The monitor bot is the single Telegram interface. It exposes the browser
# panel and drives the isolated SYSTEM backup worker through a fixed-path
# control file, then relays the backup result back to chat.


BACKUP_DIR = os.path.join(BASE_DIR, "backup")









































































# ----------------------------- Panel control channel (RDP security) -----------------------------





def api_rdp_status():
    load_blocked()
    return {
        "port": int(config.get("rdp_port", 3389)),
        "allow_active": bool(config.get("rdp_allow_active")),
        "lockdown": lockdown_active(),
        "panic": bool(config.get("panic_active")),
        "allowed_ips": [str(i) for i in (config.get("rdp_allowed_ips") or [])],
        "blocked_count": len(_blocked),
    }


def api_rdp_allow_add(ip):
    ip = str(ip).strip()
    if not _valid_ip(ip):
        return False, "invalid IP"
    ips = [str(i) for i in (config.get("rdp_allowed_ips") or [])]
    if ip in ips:
        return True, "already in the list"
    ips.append(ip)
    config["rdp_allowed_ips"] = ips
    save_config()
    if config.get("rdp_allow_active") or lockdown_active():
        apply_rdp_allow(lockdown_ips() if lockdown_active() else ips)
    audit_record("Panel: allow-list add " + ip)
    return True, "added " + ip


def api_rdp_allow_remove(ip):
    ip = str(ip).strip()
    ips = [str(i) for i in (config.get("rdp_allowed_ips") or [])]
    if ip not in ips:
        return False, "not in the list"
    ips.remove(ip)
    config["rdp_allowed_ips"] = ips
    save_config()
    if lockdown_active():
        apply_rdp_allow(lockdown_ips())
    elif config.get("rdp_allow_active"):
        apply_rdp_allow(ips)
    audit_record("Panel: allow-list remove " + ip)
    return True, "removed " + ip


def api_rdp_allow_apply():
    ips = [str(i) for i in (config.get("rdp_allowed_ips") or [])]
    if not ips:
        return False, "the allow-list is empty"
    if not apply_rdp_allow(ips):
        return False, _allow_fail_info or "failed to apply the restriction"
    config["rdp_allow_active"] = True
    save_config()
    audit_record("Panel: allow-list applied")
    return True, "RDP is now restricted to the allow-list"


def api_rdp_allow_clear():
    if lockdown_active():
        return False, "a lockdown is active; release it first"
    apply_rdp_allow([])
    config["rdp_allow_active"] = False
    config["rdp_allowed_ips"] = []
    save_config()
    audit_record("Panel: allow-list cleared")
    return True, "restriction cleared (RDP is open to any IP)"








def _valid_user_name(name):
    return bool(re.fullmatch(r"[A-Za-z0-9_.\- ]{1,40}", str(name or "")))





def api_user_action(action, name, value=""):
    if not config.get("user_management", False):
        return False, "account management is disabled"
    if action in ("disable", "delete", "password", "rename"):
        allowed, warning = last_admin_guard(str(name))
        if not allowed:
            return False, _panel_text(warning)
    if action in ("add", "password"):
        weak = _password_weak(str(value))
        if weak:
            return False, "weak password: " + weak
    name = str(name or "").strip()
    if not _valid_user_name(name):
        return False, "invalid user name"
    q = _ps_quote(name)
    if action == "enable":
        ok = ps_ok(f"Enable-LocalUser -Name '{q}' -ErrorAction Stop")
    elif action == "disable":
        ok = ps_ok(f"Disable-LocalUser -Name '{q}' -ErrorAction Stop")
    elif action == "delete":
        ok = ps_ok(f"Remove-LocalUser -Name '{q}' -ErrorAction Stop")
    elif action == "password":
        ok = ps_ok("$p=ConvertTo-SecureString '" + _ps_quote(str(value)) +
                   "' -AsPlainText -Force; Set-LocalUser -Name '" + q +
                   "' -Password $p -ErrorAction Stop")
    elif action == "rename":
        if not _valid_user_name(value):
            return False, "invalid new name"
        ok = ps_ok(f"Rename-LocalUser -Name '{q}' -NewName '{_ps_quote(str(value))}' -ErrorAction Stop")
    elif action == "add":
        ok = ps_ok("$p=ConvertTo-SecureString '" + _ps_quote(str(value)) +
                   "' -AsPlainText -Force; New-LocalUser -Name '" + q +
                   "' -Password $p -ErrorAction Stop")
    else:
        return False, "unknown action"
    audit_record("Panel user %s: %s" % (action, name))
    return ok, ("done" if ok else "failed")


def _panel_text(value):
    """Plain text for the panel: drop HTML tags and RTL markers."""
    return _strip_tags(str(value)).replace("\u200f", "")

















































































































# ----------------------------- List of buttons (/menu) -----------------------------



# command -> (what it does in detail, usage, needs confirm?)


# Pairing rule: every command must be explained in COMMAND_INFO and classified
# here as a WebConsole panel action or "bot-only". A new command must be added
# to BOTH (help + this map), and to the WebConsole when a panel action is named.


# Documentation database: for key commands, what runs behind them, the effect,
# and troubleshooting. Commands without an entry fall back to COMMAND_INFO text.



# Detailed per-command documents: ordered steps with the EXACT backend commands.
# Used by /docs <command> and by docs/COMMANDS.md. Commands without an entry fall
# back to COMMAND_BACKEND (one line) and then COMMAND_INFO.

























# Icon for each command according to its section in the list (For unified command explanation cards)











def send_photo(path, caption=None, *, cleanup=False):
    if not _artifact_runtime(path, caption, "image/png"):
        raise RuntimeError("The monitoring engine requires an agent artifact sink")
    return False








# ----------------------------- Measurements -----------------------------

def get_usage():
    """You come back (Processor ratio, RAM ratio, user ratio GBTotal GB)"""
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    used_gb = (mem.total - mem.available) / (1024 ** 3)
    total_gb = mem.total / (1024 ** 3)
    return cpu, mem.percent, used_gb, total_gb


def update_net_speed():
    """Current network speed is calculated from the difference of meters - Each monitoring session is called"""
    global _last_net_time, _last_net_counters
    c = psutil.net_io_counters()
    now = time.time()
    if _last_net_time and now > _last_net_time:
        dt = now - _last_net_time
        _net_speed["down"] = max(0.0, (c.bytes_recv - _last_net_counters[1]) * 8 / dt / 1e6)
        _net_speed["up"] = max(0.0, (c.bytes_sent - _last_net_counters[0]) * 8 / dt / 1e6)
    _last_net_time = now
    _last_net_counters = (c.bytes_sent, c.bytes_recv)


def get_disks():
    """You come back [(Letter, Usage rate, remaining GB, Total GB)]"""
    res = []
    for part in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(part.mountpoint)
            res.append((part.device, u.percent,
                        (u.total - u.used) / (1024 ** 3), u.total / 1024 ** 3))
        except Exception:
            pass
    return res


def get_top_processes(n=10):
    """You come back (higher n By processor, higher n In Ramat): [(name, pid, cpu, mem_mb)]"""
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            p.cpu_percent(None)  # Account configuration
            procs.append(p)
        except Exception:
            pass
    time.sleep(0.5)
    items = []
    for p in procs:
        try:
            mi = p.info.get('memory_info')
            items.append((p.info.get('name') or '?', p.info['pid'],
                          p.cpu_percent(None),
                          (mi.rss / (1024 ** 2)) if mi else 0.0))
        except Exception:
            pass
    top_cpu = sorted(items, key=lambda x: -x[2])[:n]
    top_ram = sorted(items, key=lambda x: -x[3])[:n]
    return top_cpu, top_ram


def get_rdp_sessions():
    """Active user sessions: qwinsta If available, otherwise psutil.users()"""
    # method 1: qwinsta (Available on Windows Pro It gives the session status and number)
    try:
        try:
            raw = subprocess.run(["qwinsta"], capture_output=True, timeout=10, creationflags=NO_WINDOW).stdout
        except FileNotFoundError:
            raw = subprocess.run(["query", "session"], capture_output=True, timeout=10, creationflags=NO_WINDOW).stdout
        sessions = []
        for line in _decode_out(raw).splitlines():
            toks = line.split()
            state_idx = None
            for i, t in enumerate(toks):
                if t.lower() in RDP_STATE_WORDS or t in RDP_STATE_WORDS:
                    state_idx = i
                    break
            if state_idx is None or state_idx < 2:
                continue
            user = toks[state_idx - 2]
            if not user or user.startswith(("rdp-tcp", "console", "service", ">")):
                continue
            sessions.append({
                "session": toks[0].lstrip(">"),
                "user": user,
                "id": toks[state_idx - 1],
                "state": toks[state_idx],
            })
        return sessions
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[sessions] qwinsta error: {e}")

    # method 2 (Alternative for Windows Home): psutil.users()
    sessions = []
    for u in psutil.users():
        term = u.terminal or "console"
        state = "RDP" if "rdp" in term.lower() else "Active"
        sessions.append({"session": term, "user": u.name, "id": "", "state": state})
    return sessions


def _net_names(out):
    """Extracting names from outputs net user / net localgroup (One or two line breaks)"""
    lines = out.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith("---"):
            start = i
            break
    if start is None:
        return []
    names = []
    for ln in lines[start + 1:]:
        s = ln.strip()
        if not s or s.startswith("---") \
                or "command" in s.lower() or "Order" in s:
            break
        names.extend(s.split())
    return names


# ----------------------------- User management -----------------------------

INVALID_USER_CHARS = set('/\\[]":;|<>+=,?*')


def valid_username(name):
    """Basic username verification (Windows rules)"""
    return (1 <= len(name) <= 20
            and not name.startswith("-")
            and not any(c in INVALID_USER_CHARS for c in name)
            and name.strip() == name
            and name not in (".", ".."))











def get_rdp_ips():
    """Addresses IP Currently connected to a port RDP Cross netstat"""
    rdp_port = str(config.get("rdp_port", 3389))
    ips = []
    try:
        raw = subprocess.run(["netstat", "-ano", "-p", "tcp"],
                             capture_output=True, timeout=15, creationflags=NO_WINDOW).stdout
        out = _decode_out(raw)
        for line in out.splitlines():
            toks = line.split()
            if len(toks) >= 4 and toks[0] == "TCP" \
                    and toks[1].endswith(":" + rdp_port) \
                    and toks[3] == "ESTABLISHED":
                ip = toks[2].rsplit(":", 1)[0].strip("[]")
                if ip and ip not in ips:
                    ips.append(ip)
    except Exception as e:
        print(f"[netstat] error: {e}")
    return ips


def get_local_users():
    """Local user accounts + Distinguishing supervisors: [(name, is_admin)]"""
    names = []
    try:
        out = subprocess.run(["net", "user"], capture_output=True, timeout=15, creationflags=NO_WINDOW)\
            .stdout
        names = _net_names(_decode_out(out))
    except Exception as e:
        print(f"[users] error: {e}")

    admins = set()
    try:
        r = subprocess.run(["net", "localgroup", "administrators"],
                           capture_output=True, timeout=15, creationflags=NO_WINDOW)
        if r.returncode == 0:
            admins.update(_net_names(_decode_out(r.stdout)))
    except Exception:
        pass

    admins_lower = {a.lower() for a in admins}
    return [(u, u.lower() in admins_lower) for u in names]


def run_speedtest():
    """Measure internet speed via Cloudflare: (ping ms, Download Mbps, Raise Mbps)"""
    t0 = time.time()
    requests.get("https://speed.cloudflare.com/__down?bytes=1000", timeout=15)
    ping_ms = (time.time() - t0) * 1000

    t0 = time.time()
    r = requests.get("https://speed.cloudflare.com/__down?bytes=25000000", timeout=120)
    dl_secs = max(0.001, time.time() - t0)
    down_mbps = len(r.content) * 8 / dl_secs / 1e6

    payload = b"0" * 8_000_000
    t0 = time.time()
    requests.post("https://speed.cloudflare.com/__up", data=payload, timeout=120)
    ul_secs = max(0.001, time.time() - t0)
    up_mbps = len(payload) * 8 / ul_secs / 1e6

    return ping_ms, down_mbps, up_mbps


# ----------------------------- Consumption record -----------------------------

def load_history():
    global _history
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                _history = json.load(f)
            cutoff = time.time() - 8 * 24 * 3600  # We keep 8 Weekly reporting days
            _history = [h for h in _history if h.get("t", 0) >= cutoff]
    except Exception:
        _history = []


def save_history():
    _atomic_write_json(HISTORY_FILE, _history)


def append_history(cpu, ram):
    _history.append({"t": time.time(), "c": round(cpu, 1), "r": round(ram, 1)})
    max_pts = 8 * 24 * 60  # 8 Sample days every minute
    if len(_history) > max_pts:
        del _history[:len(_history) - max_pts]


def stats_since(ts):
    """Consumption statistics from a certain time
    - .get With default: Bad point/The old formula was silently breaking the daily report"""
    pts = [h for h in _history
           if h.get("t", 0) >= ts and isinstance(h.get("c"), (int, float))
           and isinstance(h.get("r"), (int, float))]
    if not pts:
        return None
    cpus = [h["c"] for h in pts]
    rams = [h["r"] for h in pts]
    n = len(pts)
    return {
        "points": n,
        "cpu_avg": sum(cpus) / n, "cpu_max": max(cpus),
        "ram_avg": sum(rams) / n, "ram_max": max(rams),
    }


# ----------------------------- Chart -----------------------------

def make_chart(hours=24):
    """Plots another consumption N hours and returns the image path or None"""
    if not HAS_MATPLOTLIB or len(_history) < 2:
        return None
    import matplotlib.pyplot as plt
    now = time.time()
    pts = [h for h in _history if h["t"] >= now - hours * 3600]
    if len(pts) < 2:
        return None

    ts = [datetime.fromtimestamp(h["t"]) for h in pts]
    cpus = [h["c"] for h in pts]
    rams = [h["r"] for h in pts]

    fig, ax = plt.subplots(figsize=(10, 4.5), dpi=110)
    ax.plot(ts, cpus, label="CPU %", color="#e74c3c", linewidth=1.4)
    ax.plot(ts, rams, label="RAM %", color="#3498db", linewidth=1.4)
    ax.axhline(config["cpu_alert_threshold"], color="gray",
               linestyle="--", linewidth=0.8, alpha=0.6)
    ax.axhline(config["critical_threshold"], color="red",
               linestyle="--", linewidth=0.8, alpha=0.4)
    ax.set_ylim(0, 100)
    ax.set_ylabel("Percent %")
    ax.set_title(f"CPU / RAM - last {hours}h")
    ax.grid(alpha=0.3)
    ax.legend(loc="upper left")
    fig.autofmt_xdate()
    fig.tight_layout()

    path = os.path.join(_runtime_scratch,
                        f"rdp_monitor_chart_{time.time_ns()}.png")
    fig.savefig(path)
    plt.close(fig)
    return path


# ----------------------------- Scheduled reports -----------------------------

def send_daily_report():
    midnight = datetime.now().replace(hour=0, minute=0, second=0,
                                      microsecond=0).timestamp()
    s = stats_since(midnight)
    if not s:
        send_message(" Daily report: There is not enough data yet.")
        return
    traffic_line = ""
    rec = _traffic.get(datetime.now().strftime("%Y-%m-%d"))
    if rec:
        traffic_line = (f"\n Data today: DL  {rec['down'] / 1024:.2f} GB "
                        f"| UL  {rec['up'] / 1024:.2f} GB")
    txt = (
        f"<b>Daily report</b> - {datetime.now():%Y-%m-%d}\n"
        f" Processor: Average {s['cpu_avg']:.0f}% / higher {s['cpu_max']:.0f}%\n"
        f" rams: Average {s['ram_avg']:.0f}% / higher {s['ram_max']:.0f}%\n"
        f" Number of measurements: {s['points']}" + traffic_line
    )
    chart = make_chart(24)
    if chart:
        send_photo(chart, txt)
    else:
        send_message(txt)


def send_weekly_report():
    week_ago = time.time() - 7 * 24 * 3600
    s = stats_since(week_ago)
    if not s:
        send_message(" Weekly report: There is not enough data yet.")
        return
    try:
        extra = "\n\n" + logstats_summary()
    except Exception:
        extra = ""
    send_message(
        f"<b>Weekly report</b>\n"
        f" Processor: Average {s['cpu_avg']:.0f}% / higher {s['cpu_max']:.0f}%\n"
        f" rams: Average {s['ram_avg']:.0f}% / higher {s['ram_max']:.0f}%\n"
        f" Number of measurements: {s['points']}" + extra
    )


# ----------------------------- Text reports -----------------------------

def format_uptime():
    secs = int(time.time() - psutil.boot_time())
    h, m = secs // 3600, (secs % 3600) // 60
    return f"{h}h {m}m"





def format_net_report():
    c = psutil.net_io_counters()
    return (
        rtl("<b>Use the network</b>") + "\n"
        + rtl(f"DL  Download now: <b>{_net_speed['down']:.2f} Mbps</b>") + "\n"
        + rtl(f"UL  Upload now: <b>{_net_speed['up']:.2f} Mbps</b>") + "\n"
        + rtl(" Since turning on the device:") + "\n"
        + rtl(f"He arrived: {c.bytes_recv / 1024 ** 3:.2f} GB") + "\n"
        + rtl(f"He came out: {c.bytes_sent / 1024 ** 3:.2f} GB")
    )


def format_top_report():
    top_cpu, top_ram = get_top_processes(10)
    lines = ["<b>Highest consuming processes</b>", "",
             " <b>Depending on the processor:</b>", "<pre>"]
    for i, (name, pid, cpu, mem) in enumerate(top_cpu, 1):
        lines.append(esc(f"{i:2}. {name[:26]:26} {cpu:5.1f}% {mem:6.0f} MB"))
    lines.append("</pre>\n <b>According to the rams:</b>\n<pre>")
    for i, (name, pid, cpu, mem) in enumerate(top_ram, 1):
        lines.append(esc(f"{i:2}. {name[:26]:26} {mem / 1024:5.2f} GB {cpu:5.1f}%"))
    lines.append("</pre>")
    return "\n".join(lines)


def format_rdp_report():
    sess = get_rdp_sessions()
    ips = get_rdp_ips()
    lines = ["<b>Sessions RDP Active</b>", ""]
    if sess:
        lines.append("<pre>")
        for s in sess:
            lines.append(esc(f"{s['user'][:20]:20} {s['state'][:10]:10} ID {s['id']}"))
        lines.append("</pre>")
    else:
        lines.append("There are currently no user sessions registered")
    if ips:
        lines.append(f"\n <b>IPs connected to a port RDP ({config.get('rdp_port', 3389)}):</b>\n<pre>")
        for ip in ips:
            lines.append(esc(ip))
        lines.append("</pre>")
    return "\n".join(lines)


PS_LOCAL_USERS_DETAIL = (
    "$ErrorActionPreference='Stop'; $admins=@{}; "
    "$g=Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop; "
    "Get-LocalGroupMember -Group $g -ErrorAction Stop | "
    "ForEach-Object { $admins[$_.Name.Split('\\')[-1].ToLower()] = $true }; "
    "Get-LocalUser | ForEach-Object { "
    "$a = if ($admins.ContainsKey($_.Name.ToLower())) { 1 } else { 0 }; "
    "$pls = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd') } else { '-' }; "
    "$pex = if ($_.PasswordExpires) { $_.PasswordExpires.ToString('yyyy-MM-dd') } else { 'never' }; "
    "$ll = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') } else { '-' }; "
    "Write-Output ($_.Name + '|' + [int][bool]$_.Enabled + '|' + $a + '|' + $pls + '|' + $pex + '|' + $ll) "
    "}"
)


def _local_users_detail(strict=False):
    """Accounts details: [{name, enabled, admin, pwlastset, pwexpires, lastlogon}]
    - Cross Get-LocalUser (More accurate than net user): Status and password dates"""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            PS_LOCAL_USERS_DETAIL],
                           capture_output=True, timeout=60, creationflags=NO_WINDOW)
        if r.returncode:
            raise RuntimeError("Windows local-account inventory failed")
        users = []
        for ln in _decode_out(r.stdout).splitlines():
            parts = ln.strip().split("|")
            if len(parts) != 6:
                continue
            users.append({
                "name": parts[0], "enabled": parts[1] == "1",
                "admin": parts[2] == "1", "pwlastset": parts[3],
                "pwexpires": parts[4], "lastlogon": parts[5],
            })
        if users:
            return users
    except Exception as e:
        print(f"[users-detail] error: {e}")
        if strict:
            raise RuntimeError("Cannot verify Windows accounts and administrator membership") from e
    # Precaution: Who net user No details
    if strict:
        raise RuntimeError("Windows returned no verifiable local accounts")
    return [{"name": n, "enabled": True, "admin": a,
             "pwlastset": "-", "pwexpires": "-", "lastlogon": "-"}
            for n, a in get_local_users()]


def _password_weak(pw):
    """Check password strength locally before Windows rejects it - Due to weakness or None"""
    if len(pw) < 8:
        return ("less than 8 Typefaces / less than 8 characters")
    if not re.search(r"[A-Za-z]", pw):
        return "There are no letters in it / no letters"
    if not re.search(r"[0-9]", pw):
        return "There is no number in it / no digit"
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "There is no symbol in it / no symbol"
    return None


def last_admin_guard(name):
    """Deletion is prohibited/Disable/Change the password of the last activated admin = Protect yourself from being locked out of your device
    - He comes back (Allowed?, warning message or None)"""
    try:
        users = _local_users_detail(strict=True)
        target = next((u for u in users
                       if u["name"].lower() == name.lower()), None)
        if target is None:
            return False, "Account not found; refusing an unverified account change."
        admins = [u for u in users if u["admin"] and u["enabled"]]
        if target["admin"] and target["enabled"] and len(admins) <= 1:
            return False, (
                f" <b>{esc(name)}</b> He is the only active administrator on the device!\n"
                f" <b>{esc(name)}</b> is the ONLY enabled administrator!\n\n"
                "Executing the order will permanently lock you out.\n"
                "Create a second first supervisor: /adduser backup Admin@123 admin\n\n"
                "Running this would lock you out. Create a second admin first.")
        current_names = {str(u.name).split("\\")[-1].lower() for u in psutil.users()}
        current_names.add(os.environ.get("USERNAME", "").lower())
        if target["name"].lower() in current_names:
            return False, "This account owns a signed-in session; sign it out before changing it."
        return True, None
    except Exception:
        return False, "Could not verify administrator/session safety; no account change was made."





# ----------------------------- Procedures -----------------------------

def do_restart(reason, auto=False):
    """Perform a reboot with user notification"""
    delay = int(config.get("restart_delay_seconds", 30))
    kind = "Automatic restart" if auto else "Manual restart"
    send_message(
        f"[WARN] <b>{kind}</b>\n"
        f"The reason: {reason}\n"
        f"The device will then reboot {delay} Again.\n"
        f"To cancel send /cancel_restart During this period."
    )
    try:
        subprocess.run(
            ["shutdown", "/r", "/t", str(delay), "/c", f"RDP Monitor: {reason}"],
            check=True, creationflags=NO_WINDOW)
        return True
    except Exception as e:
        send_message(f"[X] Failed to perform restart: {e}")
        return False























# ----------------------------- Additional safety and maintenance -----------------------------

AUDIT_FILE = os.path.join(BASE_DIR, "audit.json")
BLOCKED_FILE = os.path.join(BASE_DIR, "blocked.json")


def load_audit():
    global _audit
    try:
        if os.path.exists(AUDIT_FILE):
            with open(AUDIT_FILE, "r", encoding="utf-8") as f:
                _audit = json.load(f)
    except Exception:
        _audit = []


def audit_record(entry):
    _audit.append({"t": time.time(), "e": entry})
    if len(_audit) > 300:
        del _audit[:len(_audit) - 300]
    _atomic_write_json(AUDIT_FILE, _audit, ensure_ascii=False)


def format_size(n):
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.2f} GB"
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:.1f} MB"
    return f"{n / 1024:.0f} KB"


def get_temps():
    """Temperature reading: Trans processor WMI And I decided NVIDIA Cross nvidia-smi"""
    temps = {}
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature "
             "-ErrorAction Stop | Measure-Object -Property CurrentTemperature -Maximum).Maximum"],
            capture_output=True, timeout=20, creationflags=NO_WINDOW)
        temps["CPU"] = float(r.stdout.decode().strip()) / 10.0 - 273.15
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["nvidia-smi", "--query-gpu=temperature.gpu",
             "--format=csv,noheader,nounits"],
            capture_output=True, timeout=15, creationflags=NO_WINDOW)
        temps["GPU"] = float(r.stdout.decode().split()[0])
    except Exception:
        pass
    return temps








def idle_seconds():
    """How many seconds have passed since the last press?/User movement"""
    if _agent_mode:
        return _session_sink("idle", {}) if _session_sink is not None else 0
    try:
        import ctypes

        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            return max(0.0, (ctypes.windll.kernel32.GetTickCount()
                             - lii.dwTime) / 1000.0)
    except Exception:
        pass
    return 0.0


def lock_session():
    if _agent_mode:
        if _session_sink is None:
            send_message("[X] No interactive session helper is available for idle locking.")
            return False
        return bool(_session_sink("lock", {}))
    try:
        subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"],
                       capture_output=True, timeout=15, creationflags=NO_WINDOW)
        return True
    except Exception:
        return False





def clean_temp_files(max_age_hours=24):
    """Clean files TEMP Older than a day + Recycle Bin - Returns the size of the editor"""
    freed = 0
    cutoff = time.time() - max_age_hours * 3600
    win_temp = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")
    for d in {tempfile.gettempdir(), win_temp}:
        if not os.path.isdir(d):
            continue
        for root, dirs, files in os.walk(d, topdown=False):
            for f in files:
                p = os.path.join(root, f)
                try:
                    st = os.stat(p)
                    if st.st_mtime < cutoff:
                        os.remove(p)
                        freed += st.st_size
                except OSError:
                    pass
            for dd in dirs:
                p = os.path.join(root, dd)
                try:
                    if not os.listdir(p):
                        os.rmdir(p)
                except OSError:
                    pass
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"],
            capture_output=True, timeout=90, creationflags=NO_WINDOW)
    except Exception:
        pass
    return freed


def _failed_logon_ps():
    """Inquiry 4625 For specified entry types only.
    - Presumption 10 = RDP Interactive only. LogonType 3 Includes SMB And network services as well
      Its inclusion may ban innocent people — Only add it if you understand the trade-off (Attempts NLA Before
      Authentication is shown by type 3): /set logontypes 3,10"""
    types = ",".join(f"'{t.strip()}'" for t in
                     str(config.get("failed_logon_types", "10") or "10").split(",")
                     if t.strip() in ("3", "10"))
    if not types:
        types = "'10'"
    return (
        "$st=(Get-Date).AddMinutes(-3); "
        "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$st} "
        "-ErrorAction SilentlyContinue | ForEach-Object { "
        "try { $x=[xml]$_.ToXml(); $d=@{}; "
        "$x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }; "
        "$ip=$d['IpAddress']; "
        "if ($ip -and $ip -ne '-' -and $ip -ne '::1' -and $ip -ne '127.0.0.1' "
        f"-and @({types}) -contains $d['LogonType'] "
        # Type 3 Includes SMB — We accept it only with a fingerprint NLA Discretionary. NtLmSsp It is located in
        # LogonProcessName And not ProcessName, andKerberos/NTLM In the Authentication Package field.
        # The type remains 3 Optionally because Windows does not give a flag RDP Conclusive in every version.
        "-and ($d['LogonType'] -ne '3' "
        "-or ((($d['LogonProcessName'] -like 'NtLmSsp*') "
        "-or (@('NTLM','Negotiate','Kerberos') -contains "
        "$d['AuthenticationPackageName'])) "
        "-and (-not $d['WorkstationName']))) "
        "{ Write-Output ($d['TargetUserName']+'|'+$ip+'|'"
        "+$_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fff')) } "
        "} catch {} }"
    )


def load_blocked():
    global _blocked
    try:
        if os.path.exists(BLOCKED_FILE):
            with open(BLOCKED_FILE, "r", encoding="utf-8") as f:
                _blocked = json.load(f)
    except Exception:
        _blocked = {}


def save_blocked():
    _atomic_write_json(BLOCKED_FILE, _blocked, ensure_ascii=False, indent=1)


@contextlib.contextmanager
def _blocked_file_guard():
    """Cross-process mutex shared with the optional hardened WebConsole."""
    handle = None
    try:
        name = "Global\\RDPMonitorBlocked_" + hashlib.sha256(
            BASE_DIR.lower().encode()).hexdigest()[:20]
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.CreateMutexW(None, False, name)
        if not handle:
            raise TimeoutError("blocked.json lock creation failed")
        wait = kernel32.WaitForSingleObject(handle, 15000)
        # WAIT_OBJECT_0 (0) and WAIT_ABANDONED (0x80) both grant ownership.
        if wait not in (0, 0x80):
            raise TimeoutError("blocked.json lock timeout")
        yield
    finally:
        if handle:
            ctypes.windll.kernel32.ReleaseMutex(handle)
            ctypes.windll.kernel32.CloseHandle(handle)


def _valid_ip(ip):
    """Accept only a real IPv4 or IPv6 address (no hostnames or junk)."""
    ip = (ip or "").strip()
    if not ip or len(ip) > 45:
        return False
    if ":" in ip:
        import ipaddress
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or len(part) > 3 or int(part) > 255:
            return False
    return True


def _netsh(args):
    """Implementation netsh Returning error text - Failure was swallowed silently, he says 'Administrator powers'
    For any mysterious error"""
    try:
        r = subprocess.run(["netsh"] + args, capture_output=True, timeout=30,
                           creationflags=NO_WINDOW)
        err = (_decode_out(r.stderr).strip()
               or _decode_out(r.stdout).strip())[:160]
        return r.returncode == 0, err
    except Exception as e:
        return False, str(e)[:160]


def block_ip(ip):
    """Permanent ban on IP Via base in Windows Firewall
    - He comes back (succeeded?, status): "added" block now, "exists" Already blocked, otherwise error text netsh
    - He was coming back False For previously banned, it says alerts 'Blocking failed' Wrong"""
    if not _valid_ip(ip):
        return False, "IP Invalid"
    try:
        with _blocked_file_guard():
            load_blocked()
            if ip in _blocked:
                return True, "exists"
            ok, err = _netsh(["advfirewall", "firewall", "add", "rule",
                              f"name=RDPMonitor Block {ip}", "dir=in", "action=block",
                              f"remoteip={ip}"])
            if ok:
                _blocked[ip] = time.time()
                save_blocked()
                return True, "added"
    except TimeoutError:
        # Another process holds the block list; fail this IP only instead of
        # aborting the whole failed-login scan.
        return False, "block list is busy (lock timeout)"
    print(f"[block] netsh error ({ip}): {err}")
    return False, (err or "Failed netsh Without a message")


def unblock_ip(ip):
    """Lifting the ban with actual verification that the rule has been removed — He was deleting it from blocked.json
    And he says 'Done' Even if the rule remains in the firewall"""
    if not _valid_ip(ip):
        return False, "IP Invalid"
    with _blocked_file_guard():
        load_blocked()
        _netsh(["advfirewall", "firewall", "delete", "rule",
                f"name=RDPMonitor Block {ip}"])
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-NetFirewallRule -DisplayName 'RDPMonitor Block {ip}' "
             "-ErrorAction SilentlyContinue).Count"],
            capture_output=True, timeout=60, creationflags=NO_WINDOW)
        gone = _decode_out(r.stdout).strip() in ("", "0")
        if gone:
            _blocked.pop(ip, None)
            save_blocked()
    return gone


def check_failed_logons():
    """Reads login failure events (4625) It alerts and blocks intruders
    - Interference gate: The scan may take longer than the scheduling cycle (60 Again)"""
    if not _check_start("failed_logons"):
        return
    try:
        _check_failed_logons_impl()
    finally:
        _check_end("failed_logons")


def _check_failed_logons_impl():
    global _seen_4625
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            _failed_logon_ps()],
                           capture_output=True, timeout=90, creationflags=NO_WINDOW)
    except Exception as e:
        print(f"[failed-logons] error: {e}")
        return
    new_by_ip = {}
    for ln in _decode_out(r.stdout).splitlines():
        parts = ln.strip().split("|")
        if len(parts) != 3:
            continue
        user, ip, ts = parts
        key = f"{user}|{ip}|{ts}"
        if key in _seen_4625:
            continue
        _seen_4625[key] = True
        new_by_ip.setdefault(ip, {"users": set(), "count": 0})
        new_by_ip[ip]["users"].add(user)
        new_by_ip[ip]["count"] += 1
    if len(_seen_4625) > 2000:
        # dict Listed in order: We grab the newest and effectively throw away the oldest (It was set In no order)
        _seen_4625 = dict(list(_seen_4625.items())[-1000:])
    if not new_by_ip:
        return
    # User traps: Any login attempt is a trap = Permanent ban on the first attempt
    traps = [str(t).lower() for t in (config.get("trap_users") or [])]
    if traps:
        trap_alerts = []
        for ip, info in new_by_ip.items():
            hit = [u for u in info["users"] if u.lower() in traps]
            if hit and ip not in _blocked:
                bok, _st = block_ip(ip)
                if bok:
                    trap_alerts.append((ip, hit))
                    if config.get("subnetblock"):
                        block_subnet(ip)
        if trap_alerts:
            audit_record("User trap: "
                         + "; ".join(f"{ip} ({','.join(u)})" for ip, u in trap_alerts))
            send_message(
                rtl(" <b>User trap!</b>") + "\n"
                + rtl("Try names: " + ", ".join(sorted({u for _ip, us in trap_alerts for u in us}))) + "\n"
                + "\n".join(rtl(f" Blocked {ip} Immediately and permanently") for ip, _u in trap_alerts))
    threshold = int(config.get("failed_login_block_threshold", 10))
    # During lock: Yes IP New Banned on first attempt - Against proxies that change IP Constantly
    if lockdown_active():
        threshold = 1
    window_min = int(config.get("failed_login_window", 15))
    window = window_min * 60
    now = time.time()
    lines = [" <b>Failed login attempts on the device!</b>",
             "Looks like someone is trying passwords on RDP:\n"]
    for ip, info in new_by_ip.items():
        e = _failed_logins.setdefault(ip, {"times": []})
        e["times"] = [t for t in e["times"] if now - t <= window] \
            + [now] * info["count"]
        total = len(e["times"])
        lines.append(f"• User: {', '.join(sorted(info['users']))} "
                     f"| IP: {ip}\n"
                     f"  Another attempts {window_min} Minute: {total}")
        already = ip in _blocked
        if already:
            # Banned from a previous session and new attempts are still being made (His appearance here means
            # 4625 New!) = A proxy that runs within the same network or base as affected
            lines.append("   Previously blocked and still trying"
                         " — Automatic escalation of network ban /24 Complete")
            sok, sst = block_subnet(ip)
            if sok and sst == "added":
                audit_record(f"Automatic escalation to ban /24 (Blocked and keep trying): {ip}")
        elif config.get("failed_login_block") and total >= threshold:
            bok, bstat = block_ip(ip)
            if bok:
                lines.append(f"   <b>has been blocked {ip} permanently in the firewall</b>")
                if config.get("subnetblock"):
                    block_subnet(ip)
            else:
                lines.append(f"   Blocking failed: {esc(bstat)}")
    audit_record("Failed login attempts: "
                 + "; ".join(f"{ip} x{len(_failed_logins[ip]['times'])}"
                             for ip in new_by_ip))
    # Drop IPs whose attempts have aged out of the window so the map cannot
    # grow without bound over a long-running process.
    for stale_ip in [k for k, v in _failed_logins.items()
                     if not any(now - t <= window for t in v["times"])]:
        _failed_logins.pop(stale_ip, None)
    # Auto lock: Total distributed to each IP It is a residential proxy fingerprint
    # - We scan all records for the current window first: They were old attempts from days gone by
    #   It accumulates forever and the lock works "After hours" It’s not okay 15 Minute
    if config.get("lockdown") and not lockdown_active():
        now3 = time.time()
        total_all = sum(len([t for t in e["times"] if now3 - t <= window])
                        for e in _failed_logins.values())
        if total_all >= int(config.get("lockdown_limit", 30)):
            audit_record(f"Auto lock: {total_all} Failed attempt distributed throughout the window")
            lockdown_start()
            return
    # Quick response buttons: Block without typing any command
    rows = []
    for atk_ip in list(new_by_ip.keys())[:3]:
        rows.append([(f"Block {atk_ip}", f"run:/block {atk_ip} confirm"),
                     ("Block /24", f"run:/blocksubnet {atk_ip} confirm")])
    rows.append([("Lockdown now", "run:/lockdown now confirm"),
                 ("Mute 3h", "run:/mute 3h"),
                 ("Whitelist", "run:/whitelist")])
    send_buttons("\n".join(lines), rows)


# ----------------------------- Whitelist and auto lock -----------------------------

PS_SUCCESS_LOGON = (
    "$st=(Get-Date).AddDays(-14); "
    "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$st} "
    "-MaxEvents 2000 -ErrorAction SilentlyContinue | ForEach-Object { "
    "try { $x=[xml]$_.ToXml(); $d=@{}; "
    "$x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }; "
    "$ip=$d['IpAddress']; "
    "if ($d['LogonType'] -eq '10' -and $ip -and $ip -ne '-' -and $ip -ne '::1' "
    "-and $ip -ne '127.0.0.1') "
    "{ Write-Output ($ip+'|'+$d['TargetUserName']+'|'+$_.TimeCreated.ToString('yyyy-MM-dd')) } "
    "} catch {} }"
)


def learn_successful_ips():
    """He learns IP Whoever succeeded in entering RDP Actually during 14 day (Of events 4624)
    - This is the safety net that prevents the lock from blocking you
    - It will alert you if it enters IP New, never seen before (Successful intrusion detection)"""
    global _learn_alerts_ready
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            PS_SUCCESS_LOGON],
                           capture_output=True, timeout=120, creationflags=NO_WINDOW)
    except Exception as e:
        print(f"[learn] error: {e}")
        return None
    learned = dict(config.get("learned_ips") or {})
    now = time.time()
    n_new = 0
    new_rows = []
    for ln in _decode_out(r.stdout).splitlines():
        parts = ln.strip().split("|")
        if len(parts) < 3:
            continue
        ip, user = parts[0].strip(), parts[1].strip()
        if not _valid_ip(ip):
            continue
        # Actual event time from the log — It’s not time for examination: His age happened 14 About a day
        # He was taking a new history and remaining almost reliable 28 One day
        try:
            ev_t = datetime.strptime(parts[2].strip(), "%Y-%m-%d").timestamp()
        except Exception:
            ev_t = now
        if ip not in learned:
            n_new += 1
            new_rows.append((ip, user))
        val = learned.get(ip)
        if not isinstance(val, dict):
            val = {"t": 0, "u": user}
        val["t"] = max(val.get("t", 0) or 0, ev_t)
        if user:
            val["u"] = user
        learned[ip] = val
    # Cleaning: We keep another 14 Just a day
    learned = {ip: v for ip, v in learned.items()
               if now - (v["t"] if isinstance(v, dict) else v) <= 14 * 86400}
    config["learned_ips"] = learned
    save_config()
    # Successful intrusion alarm: IP He entered successfully and the first time we saw him
    if new_rows and _learn_alerts_ready and config.get("new_ip_alerts", True):
        rows = "\n".join(rtl(f"• {esc(ip)} — {esc(u or '?')}")
                         for ip, u in new_rows[:10])
        kb = [[(f"It was me - trust {ip}", f"run:/whitelist add {ip}")
               for ip, _u in new_rows[:2]]]
        kb.append([("NOT me - PANIC", "run:/panic on confirm"),
                   ("/logins", "run:/logins")])
        send_buttons(
            rtl(" <b>Successful login from IP New!</b>") + "\n"
            + rtl("First time we see this IP Enters successfully:") + "\n" + rows + "\n"
            + rtl("Aren’t you? Press PANIC Immediately - Verify your entry with /logins"), kb)
    if not _learn_alerts_ready:
        _learn_alerts_ready = True
        # Baseline silently documents nothing: We announce what we have learned from another 14 One day
        base = sorted(learned.keys()) if config.get("baseline_alerts", False) else []
        if base:
            rows = "\n".join(rtl(f"• {esc(ip)} — {esc(learned[ip].get('u', '?') if isinstance(learned[ip], dict) else '?')}")
                             for ip in base[:10])
            send_buttons(
                rtl("<b>Baseline: IP Successfully entered during post 14 One day</b>") + "\n"
                + rtl("(From the Windows registry upon first startup — It was considered reliable for locking)") + "\n"
                + rows + (rtl(f"\nAnd {len(base) - 10} Other") if len(base) > 10 else ""),
                [[("Whitelist", "run:/whitelist")],
                 [("What is this?", "run:/noop")]])
    return n_new


def lockdown_active():
    """Is the auto lock working now?"""
    try:
        return time.time() < float(config.get("lockdown_until", 0) or 0)
    except Exception:
        return False


def lockdown_ips():
    """IP Allowed while locked: Manual approval, educated only when you choose it.
    Current contact does not mean trust: An attacker may be online the moment the lock is initiated."""
    ips = []
    sources = (
        [str(i) for i in (config.get("rdp_allowed_ips") or [])],
        [ip for ip, v in (config.get("learned_ips") or {}).items()
         if config.get("learn_for_lockdown", False)
         and time.time() - (v["t"] if isinstance(v, dict) else v) <= 14 * 86400],
    )
    for src in sources:
        for ip in src:
            if _valid_ip(ip) and ip not in ips:
                ips.append(ip)
    return ips


def lockdown_start(minutes=None, manual=False):
    """fall short RDP Whitelist immediately - Manual or automatic when a wave breaks"""
    global _pre_lockdown_allow_active
    minutes = int(minutes or config.get("lockdown_minutes", 60))
    learned_new = learn_successful_ips()
    ips = lockdown_ips()
    if not ips:
        send_message("[X] I couldn’t operate the lock: There is nothing in it IP Reliable, known\n"
                     "Add your device manually first: /whitelist add IP-Your device\n"
                     "(Also check administrator permissions for automatic learning to work)")
        return False
    _pre_lockdown_allow_active = bool(config.get("rdp_allow_active"))
    # We save the state before locking in the settings (It was only in memory — Restart
    # She was forgetting her, as release cancels your permanent confinement to him)
    config["rdp_allow_pre_active"] = _pre_lockdown_allow_active
    save_config()
    if not apply_rdp_allow(ips):
        send_message("[X] Failed to apply lock (Check administrator permissions)")
        return False
    config["lockdown_until"] = time.time() + minutes * 60
    config["rdp_allow_active"] = True
    save_config()
    audit_record("Safety lock: " + ("Manual" if manual else "Auto")
                 + f" - {len(ips)} IP Allowed for a period of time {minutes} Minute")
    send_buttons(
        rtl(f"<b>The lock worked {'(Manual)' if manual else '(Automatically - Breakthrough wave)'}</b>") + "\n"
        + rtl(f"RDP Now limited to {len(ips)} IP Reliable for duration {format_duration(minutes * 60)}") + "\n"
        + rtl(f"Learn {learned_new or 0} IP New from successful logins") + "\n"
        + rtl("During lock: Yes IP A new person tries to enter and is banned on the first attempt"),
        [[("Whitelist", "run:/whitelist"),
          ("Release early", "run:/lockdown release")]])
    return True


def lockdown_release(auto=False):
    """End the lock and revert the pre-lock firewall rules
    - We return the actual state before locking: If the restriction was not activated, we will not activate it
      (It was applying permission rules even if they were not enabled before the lock)"""
    global _pre_lockdown_allow_active
    manual_ips = [str(i) for i in (config.get("rdp_allowed_ips") or [])]
    was_active = bool(config.get("rdp_allow_pre_active",
                                 _pre_lockdown_allow_active))
    if was_active and manual_ips:
        apply_rdp_allow(manual_ips)
        config["rdp_allow_active"] = True
    else:
        apply_rdp_allow([])
        config["rdp_allow_active"] = False
    config["lockdown_until"] = 0
    config["rdp_allow_pre_active"] = False
    _pre_lockdown_allow_active = None
    save_config()
    audit_record("Security lock expired" + (" (Auto)" if auto else " (Manual)"))
    send_message((" <b>The lock ended automatically</b> - " if auto else " <b>I lifted the lock</b> - ")
                 + "The firewall is back to before the lock")


def ps_ok(ps, timeout=90):
    """Executes an order PowerShell Whether it was successful or not"""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        return r.returncode == 0
    except Exception:
        return False


# ----------------------------- Monitor account management events -----------------------------

PS_ACCOUNT_EVENTS = (
    "$st=(Get-Date).AddMinutes(-3); "
    "$ids=4720,4722,4724,4725,4726,4732,4728; "
    "Get-WinEvent -FilterHashtable @{LogName='Security';Id=$ids;StartTime=$st} "
    "-ErrorAction SilentlyContinue | ForEach-Object { "
    "try { $x=[xml]$_.ToXml(); $d=@{}; "
    "$x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }; "
    "$m = if ($d['MemberName']) { $d['MemberName'].Split('\\')[-1] } else { $d['TargetUserName'] }; "
    "$t = if ($d['MemberName']) { $d['TargetUserName'] } else { '-' }; "
    "Write-Output ($_.Id.ToString()+'|'+$m+'|'+$t+'|'+$d['SubjectUserName']+'|' "
    "+$_.TimeCreated.ToString('MM-dd HH:mm')) } catch {} }"
)

ACCT_EVENT_INFO = {
    "4720": ("", "A new account has been created", "Account created"),
    "4722": ("", "A disabled account has been activated", "Account enabled"),
    "4724": ("", "Account password has been zeroed", "Password reset"),
    "4725": ("", "Account has been disabled", "Account disabled"),
    "4726": ("", "Account deleted", "Account deleted"),
    "4728": ("", "Added a member to a security group", "Member added to global group"),
    "4732": ("", "A member has been added to a local group", "Member added to local group"),
}


def check_account_events():
    """Monitors account changes outside the tool (From Windows itself): Create/Delete/Disable/
    Traffic whistle/Add to supervisors — The malicious back account is exposed immediately"""
    if not _check_start("account_events"):
        return
    try:
        _check_account_events_impl()
    finally:
        _check_end("account_events")


def _check_account_events_impl():
    global _seen_acct, _acct_baseline
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            PS_ACCOUNT_EVENTS],
                           capture_output=True, timeout=90, creationflags=NO_WINDOW)
    except Exception as e:
        print(f"[acct-events] error: {e}")
        return
    rows = []
    for ln in _decode_out(r.stdout).splitlines():
        parts = ln.strip().split("|")
        if len(parts) != 5:
            continue
        rows.append(parts)
    if not _acct_baseline:
        _acct_baseline = True
        _seen_acct = {f"{a}|{b}|{c}|{d}|{e}": True
                      for a, b, c, d, e in rows}
        return
    new = []
    for eid, member, group, subj, ts in rows:
        key = f"{eid}|{member}|{group}|{subj}|{ts}"
        if key not in _seen_acct:
            _seen_acct[key] = True
            new.append((eid, member, group, subj, ts))
    if len(_seen_acct) > 2000:
        _seen_acct = dict(list(_seen_acct.items())[-1000:])
    if not new:
        return
    # Sensitive: any new account, or adding a member to an administrator group.
    # 4720 carries no group field, so creation is always treated as sensitive.
    sensitive = [n for n in new
                 if n[0] == "4720"
                 or (n[0] in ("4728", "4732")
                     and "admin" in (n[2] or "").lower())]
    prefix = " <b>Change to device accounts!</b>" if sensitive \
        else " <b>Activity on accounts</b>"
    lines = [rtl(prefix)]
    for eid, member, group, subj, ts in new:
        icon, ar, en = ACCT_EVENT_INFO.get(eid, ("•", "Account event", "Account event"))
        detail = f"{member}" + (f" → {group}" if group != "-" else "")
        lines.append(rtl(f"{icon} {ar} / {en}\n"
                         f"    <b>{esc(detail)}</b> — By {esc(subj)} — {ts}"))
    if sensitive:
        lines.append(rtl("[WARN] If you weren’t the one who did it — Review the list of buttons or think of PANIC"))
    audit_record("Accounts events: "
                 + "; ".join(f"#{e}:{m}" for e, m, _g, _s, _t in new[:5]))
    if sensitive:
        send_buttons("\n".join(lines),
                     [[("List users", "run:/listusers"),
                       ("Logins", "run:/logins")],
                      [("PANIC - close RDP", "run:/panic on confirm")]])
    else:
        send_buttons("\n".join(lines),
                     [[("List users", "run:/listusers")]])


def account_events_loop():
    """Periodic check of account management events (Every minute)"""
    while not _engine_stop.is_set():
        if config.get("account_watch", True):
            check_account_events()
        _engine_stop.wait(60)


def change_rdp_port(new_port):
    """Change port RDP Safely — Each step is conditional on the success of the one before it:
    registry ← Firewall ← Reset service ← Confirm listening on new
    - The old port is closed only after ensuring that the new port is actually listening
    - That is, failure = Automatic rollback of old port (He could have blocked all the outlets for you)"""
    old_port = int(config.get("rdp_port", 3389))
    res = {"reg": False, "fw": False, "old": None, "svc": None,
           "listen": False, "allow": None, "busy": False}

    reg_path = ("'HKLM:\\System\\CurrentControlSet\\Control\\Terminal "
                "Server\\WinStations\\RDP-Tcp'")

    # 0) The new port must be empty before anything else — Another program he listens to was
    #    It is read later as a listener RDP The change is considered successful and then the old one is closed to you!
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.status == psutil.CONN_LISTEN and c.laddr \
                    and c.laddr.port == new_port:
                res["busy"] = True
                return res
    except Exception:
        pass

    # 1) Registry first — If we fail, we don’t touch anything at all
    if not ps_ok(f"Set-ItemProperty -Path {reg_path} "
                 f"-Name PortNumber -Value {new_port} -Type DWord -ErrorAction Stop"):
        return res
    res["reg"] = True

    # 2) Open the new port in the firewall — If it fails, return the registry
    if not ps_ok(f"New-NetFirewallRule -DisplayName 'RDPMonitor RDP {new_port}' "
                 f"-Direction Inbound -LocalPort {new_port} -Protocol TCP "
                 "-Action Allow -ErrorAction Stop", timeout=60):
        ps_ok(f"Set-ItemProperty -Path {reg_path} "
              f"-Name PortNumber -Value {old_port} -Type DWord -ErrorAction Stop")
        return res
    res["fw"] = True

    # 3) Restart the service to listen on the new one
    res["svc"] = ps_ok("Restart-Service TermService -Force -ErrorAction Stop",
                       timeout=90)

    # 4) Wait for a listener on the new port — And it must be him PID Service RDP Herself
    #    (A listener of a strange program on the outlet does not consider it a success)
    rsvc = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "(Get-CimInstance Win32_Service -Filter \"Name='TermService'\").ProcessId"],
        capture_output=True, timeout=60, creationflags=NO_WINDOW)
    try:
        term_pid = int(_decode_out(rsvc.stdout).strip() or 0)
    except ValueError:
        term_pid = 0
    listen_pid = None
    for _ in range(15):
        time.sleep(2)
        try:
            for c in psutil.net_connections(kind="tcp"):
                if c.status == psutil.CONN_LISTEN and c.laddr \
                        and c.laddr.port == new_port:
                    listen_pid = c.pid
                    break
        except Exception:
            pass
        if listen_pid is not None:
            break
    if term_pid and listen_pid == term_pid:
        res["listen"] = True
    elif listen_pid and not term_pid:
        # We couldn’t read PID Service — We accept svchost As a regression indicator only
        try:
            res["listen"] = \
                psutil.Process(listen_pid).name().lower() == "svchost.exe"
        except Exception:
            res["listen"] = False

    if not res["listen"]:
        print(f"[rdpport] listener check failed "
              f"(listen_pid={listen_pid}, termsvc_pid={term_pid}) - rolling back")
        ps_ok(f"Set-ItemProperty -Path {reg_path} "
              f"-Name PortNumber -Value {old_port} -Type DWord -ErrorAction Stop")
        ps_ok("Restart-Service TermService -Force -ErrorAction Stop", timeout=90)
        # Remove the allow rule for the port we just tried, otherwise it stays
        # open to the world even though the change was rolled back.
        _netsh(["advfirewall", "firewall", "delete", "rule",
                f"name=RDPMonitor RDP {new_port}"])
        res["fw"] = False
        return res

    # 5) Only now — After confirming the new — Close the old port
    if old_port != new_port:
        ps_ok("Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' "
              "-ErrorAction SilentlyContinue", timeout=60)
        ps_ok("Disable-NetFirewallRule -DisplayGroup 'Remote desktop' "
              "-ErrorAction SilentlyContinue", timeout=60)
        _netsh(["advfirewall", "firewall", "delete", "rule",
                "name=RDPMonitor Old RDP Port Block"])
        ok, _err = _netsh(["advfirewall", "firewall", "add", "rule",
                           "name=RDPMonitor Old RDP Port Block", "dir=in",
                           "action=block", "protocol=TCP",
                           f"localport={old_port}"])
        res["old"] = ok

    # 6) Save the setting + Reapply the restriction IP On the new port
    #    (The restriction rules remained on the old port, so the new one remained open to the world)
    config["rdp_port"] = new_port
    save_config()
    if config.get("rdp_allow_active") or lockdown_active():
        # During lock: Manual, learned only when activated learn_for_lockdown
        # (The application reset was manual read only — If the lock depends on the learners
        #  The new port remains open to the world and the settings say "Forbidden"!)
        ips = lockdown_ips() if lockdown_active() \
            else [str(i) for i in (config.get("rdp_allowed_ips") or [])]
        if ips:
            res["allow"] = apply_rdp_allow(ips)
    return res


RDP_ALLOW_RULE = "RDPMonitor RDP Allow List"      # legacy v4.3 name
RDP_ALLOW_TCP_RULE = "RDPMonitor RDP Allow List TCP"
RDP_ALLOW_UDP_RULE = "RDPMonitor RDP Allow List UDP"
RDP_STAGE_TCP_RULE = "RDPMonitor RDP Allow Staging TCP"
RDP_STAGE_UDP_RULE = "RDPMonitor RDP Allow Staging UDP"
RDP_BLOCK_RULE = "RDPMonitor RDP Block Others"   # Old name - Cleans up upon reapplication
_allow_fail_info = ""                            # Another reason for the failure of the inventory (For messages)


def _ps_quote(value):
    """PowerShell single-quoted literal content."""
    return str(value).replace("'", "''")


def _scan_broad_rules(port, trusted):
    """He comes back IDs Rules that may allow movement RDP Off the list, without modifying the system.

    Rules TermService Andsvchost Prepare rules RDP Actual and not excluded. Restrictive rules
    With service/Other program do not apply to TermService, so it is left and its name appears for review.
    Editing is done later rule by rule in order to keep a record rollback Before moving on to the next.
    """
    ps = (
        "$port='" + str(port) + "'; "
        "$mine=@('" + RDP_ALLOW_RULE + "','" + RDP_ALLOW_TCP_RULE +
        "','" + RDP_ALLOW_UDP_RULE + "','" + RDP_STAGE_TCP_RULE +
        "','" + RDP_STAGE_UDP_RULE + "'); "
        "$trust=@(" + ",".join(f"'{i}'" for i in trusted) + "); "
        "$out=@(); $warn=@(); "
        "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $mine -notcontains $_.DisplayName } | ForEach-Object { "
        "$pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; "
        "if ($pf) { $hit = $false; $protOk = $false; "
        "if (-not $pf.Protocol -or $pf.Protocol -eq 'Any') { $protOk = $true } "
        "elseif ($pf.Protocol -eq 'TCP') { $protOk = $true } "
        "elseif ($pf.Protocol -eq 'UDP' -and (@($pf.LocalPort) -contains $port)) { $protOk = $true }; "
        "if ($protOk) { "
        "if (@($pf.LocalPort) -contains $port) { $hit = $true } "
        "elseif (@($pf.LocalPort) -contains 'Any' -and (-not $pf.Protocol "
        "-or $pf.Protocol -eq 'Any' -or $pf.Protocol -eq 'TCP')) { $hit = $true } "
        "else { foreach ($lp in @($pf.LocalPort)) { "
        "if ($lp -match '^(\\d+)-(\\d+)$') { "
        "if ($port -ge [int]$Matches[1] -and $port -le [int]$Matches[2]) "
        "{ $hit = $true } } } } }; "
        "if ($hit) { "
        "$scoped = $false; $rdpScoped = $false; "
        "$apf = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue; "
        "if ($apf -and $apf.Program -and $apf.Program -ne 'Any') { "
        "$scoped = $true; if ($apf.Program -match '(?i)(\\\\svchost\\.exe$|^System$)') "
        "{ $rdpScoped = $true } }; "
        "$svf = $_ | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue; "
        "if ($svf -and $svf.Service -and $svf.Service -ne 'Any') { "
        "$scoped = $true; if ($svf.Service -eq 'TermService') { $rdpScoped = $true } }; "
        "if ($scoped -and -not $rdpScoped) { $warn += $_.DisplayName } else { "
        "$af = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue; "
        "$broad = $false; "
        "if (-not $af) { $broad = $true } else { "
        "foreach ($ra in @($af.RemoteAddress)) { "
        "if ($ra -and ($trust -notcontains $ra)) { $broad = $true } } }; "
        "if ($broad) { $out += $_.Name } } } } }; "
        "[ordered]@{disable=@($out);warnings=@($warn)} | ConvertTo-Json -Compress"
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=240, creationflags=NO_WINDOW)
        if r.returncode != 0:
            raise RuntimeError(_decode_out(r.stderr).strip() or "PowerShell failed")
        data = json.loads(_decode_out(r.stdout).strip())
        ids = data.get("disable") or []
        warns = data.get("warnings") or []
        if isinstance(ids, str):
            ids = [ids]
        if isinstance(warns, str):
            warns = [warns]
        return [str(x) for x in ids], [str(x) for x in warns]
    except Exception as e:
        print(f"[rdpallow] scan error: {e}")
        return None, None


def _set_rule_enabled(rule_id, enabled):
    rid = _ps_quote(rule_id)
    verb = "Enable" if enabled else "Disable"
    expected = "True" if enabled else "False"
    return ps_ok(
        f"${{ErrorActionPreference}}='Stop'; {verb}-NetFirewallRule -Name '{rid}'; "
        f"$r=Get-NetFirewallRule -Name '{rid}'; "
        f"if ($r.Enabled.ToString() -ne '{expected}') {{ exit 1 }}", timeout=60)


def _enable_saved_rule(rule_id):
    """Repeats rule ID New, supported DisplayName Store from older versions."""
    rid = _ps_quote(rule_id)
    return ps_ok(
        "$ErrorActionPreference='Stop'; "
        f"$r=Get-NetFirewallRule -Name '{rid}' -ErrorAction SilentlyContinue; "
        f"if (-not $r) {{$r=Get-NetFirewallRule -DisplayName '{rid}' "
        "-ErrorAction SilentlyContinue}; if (-not $r) {exit 1}; "
        "$r | Enable-NetFirewallRule -ErrorAction Stop", timeout=60)


def _delete_allow_rules(port):
    names = (RDP_ALLOW_RULE, RDP_ALLOW_TCP_RULE, RDP_ALLOW_UDP_RULE,
             RDP_STAGE_TCP_RULE, RDP_STAGE_UDP_RULE, RDP_BLOCK_RULE,
             f"RDPMonitor RDP {port}")
    for name in names:
        _netsh(["advfirewall", "firewall", "delete", "rule", f"name={name}"])


def _delete_trusted_rules():
    for name in (RDP_ALLOW_RULE, RDP_ALLOW_TCP_RULE, RDP_ALLOW_UDP_RULE,
                 RDP_STAGE_TCP_RULE, RDP_STAGE_UDP_RULE, RDP_BLOCK_RULE):
        _netsh(["advfirewall", "firewall", "delete", "rule", f"name={name}"])


def _create_general_rdp_rule(port):
    _netsh(["advfirewall", "firewall", "delete", "rule",
            f"name=RDPMonitor RDP {port}"])
    ok, err = _netsh(["advfirewall", "firewall", "add", "rule",
                      f"name=RDPMonitor RDP {port}", "dir=in", "action=allow",
                      "protocol=TCP", f"localport={port}"])
    return ok, err


def _create_trusted_rules(port, ips):
    # Create staging Firstly, while the old rules are still effective: There is no access gap.
    for stale in (RDP_STAGE_TCP_RULE, RDP_STAGE_UDP_RULE):
        _netsh(["advfirewall", "firewall", "delete", "rule", f"name={stale}"])
    created = []
    for name, protocol in ((RDP_STAGE_TCP_RULE, "TCP"),
                           (RDP_STAGE_UDP_RULE, "UDP")):
        ok, err = _netsh(["advfirewall", "firewall", "add", "rule",
                          f"name={name}", "dir=in", "action=allow",
                          f"protocol={protocol}", f"localport={port}",
                          "remoteip=" + ",".join(ips)])
        if not ok:
            for made in created:
                _netsh(["advfirewall", "firewall", "delete", "rule",
                        f"name={made}"])
            return False, err
        created.append(name)
    for old in (RDP_ALLOW_RULE, RDP_ALLOW_TCP_RULE, RDP_ALLOW_UDP_RULE,
                RDP_BLOCK_RULE):
        _netsh(["advfirewall", "firewall", "delete", "rule", f"name={old}"])
    for staging, final in ((RDP_STAGE_TCP_RULE, RDP_ALLOW_TCP_RULE),
                           (RDP_STAGE_UDP_RULE, RDP_ALLOW_UDP_RULE)):
        if not ps_ok(f"Set-NetFirewallRule -DisplayName '{staging}' "
                     f"-NewDisplayName '{final}' -ErrorAction Stop", timeout=60):
            for name in (RDP_STAGE_TCP_RULE, RDP_STAGE_UDP_RULE,
                         RDP_ALLOW_TCP_RULE, RDP_ALLOW_UDP_RULE):
                _netsh(["advfirewall", "firewall", "delete", "rule",
                        f"name={name}"])
            return False, "The trusted allow rule name could not be installed"
    return True, ""


def _rollback_rdp_allow(port, disabled_now, changed_profiles):
    saved = list(config.get("rdpallow_disabled_rules") or [])
    for rid in disabled_now:
        if _enable_saved_rule(rid) and rid in saved:
            saved.remove(rid)
    config["rdpallow_disabled_rules"] = saved
    pre = dict(config.get("pre_default_inbound") or {})
    for prof in changed_profiles:
        original = pre.get(prof, "Allow")
        if ps_ok(f"Set-NetFirewallProfile -Profile '{_ps_quote(prof)}' "
                 f"-DefaultInboundAction {original} -ErrorAction Stop", timeout=60):
            pre.pop(prof, None)
    config["pre_default_inbound"] = pre
    _delete_allow_rules(port)
    fallback_ok, _ = _create_general_rdp_rule(port)
    save_config()
    return fallback_ok


def apply_rdp_allow(ips):
    """Application transactional To limit RDP With TCP AndUDP And he scored rollback Permanent."""
    global _allow_fail_info
    _allow_fail_info = ""
    port = int(config.get("rdp_port", 3389))
    if not ips:
        _delete_allow_rules(port)
        ok, _ = _create_general_rdp_rule(port)
        all_ok = ok
        remaining = []
        for rname in (config.get("rdpallow_disabled_rules") or []):
            if not _enable_saved_rule(rname):
                remaining.append(rname)
                all_ok = False
        config["rdpallow_disabled_rules"] = remaining
        pre_remaining = {}
        for prof, act in (config.get("pre_default_inbound") or {}).items():
            if not ps_ok(f"Set-NetFirewallProfile -Profile '{_ps_quote(prof)}' "
                         f"-DefaultInboundAction {act} -ErrorAction Stop", timeout=60):
                pre_remaining[prof] = act
                all_ok = False
        config["pre_default_inbound"] = pre_remaining
        save_config()
        return all_ok

    # staging Created before old rules are deleted; We do not create an access gap during the update.
    ok, err = _create_trusted_rules(port, ips)
    if not ok:
        print(f"[rdpallow] allow rule error: {err}")
        _allow_fail_info = err
        # Staging failed before the old rules were removed, so the previous
        # state is intact. Never open RDP to the world as a fallback here.
        return False
    _netsh(["advfirewall", "firewall", "delete", "rule",
            f"name=RDPMonitor RDP {port}"])

    candidates, scoped_warns = _scan_broad_rules(port, trusted=ips)
    if candidates is None:
        _allow_fail_info = "Broad bases scanning failed (PowerShell)"
        _rollback_rdp_allow(port, [], [])
        return False

    disabled_now = []
    saved = list(config.get("rdpallow_disabled_rules") or [])
    for rid in candidates:
        if not _set_rule_enabled(rid, False):
            _allow_fail_info = "Unable to disable broad permission rule: " + rid
            _rollback_rdp_allow(port, disabled_now, [])
            return False
        disabled_now.append(rid)
        if rid not in saved:
            saved.append(rid)
        config["rdpallow_disabled_rules"] = saved
        save_config()  # Register rollback After each change, not after the payment has finished

    leftover, _w = _scan_broad_rules(port, trusted=ips)
    if leftover is None:
        leftover = ["<verification failed>"]
    if leftover:
        print(f"[rdpallow] verification failed, leftovers: {leftover}")
        _allow_fail_info = "Broad rules of tolerance have not been broken: " + ", ".join(leftover[:5])
        _rollback_rdp_allow(port, disabled_now, [])
        return False

    if scoped_warns:
        send_message(rtl("<b>Accuracy alert:</b> Allow rules are restricted to a specific program "
                         "Or another service on the same port has not changed: "
                         + esc(", ".join(scoped_warns[:5]))
                         + " — Review it manually: /firewall"))

    ps_pol = ("$o=@(); Get-NetFirewallProfile | ForEach-Object { "
              "if ($_.DefaultInboundAction -eq 'Allow') { "
              "$o += ($_.Name) } }; Write-Output ($o -join '|')")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps_pol],
                           capture_output=True, timeout=60, creationflags=NO_WINDOW)
        if r.returncode != 0:
            raise RuntimeError(_decode_out(r.stderr).strip())
        allow_profiles = [x for x in _decode_out(r.stdout).strip().split("|") if x]
    except Exception as e:
        _allow_fail_info = "Unable to read firewall policy: " + str(e)[:120]
        _rollback_rdp_allow(port, disabled_now, [])
        return False
    changed_profiles = []
    if allow_profiles:
        pre = dict(config.get("pre_default_inbound") or {})
        for prof in allow_profiles:
            pre[prof] = "Allow"
            config["pre_default_inbound"] = pre
            save_config()
            if not ps_ok(f"Set-NetFirewallProfile -Profile '{_ps_quote(prof)}' "
                         "-DefaultInboundAction Block -ErrorAction Stop", timeout=60):
                _allow_fail_info = "Unable to convert inbound policy to Block: " + prof
                _rollback_rdp_allow(port, disabled_now, changed_profiles)
                return False
            changed_profiles.append(prof)
        send_message(rtl("<b>Important note:</b> The default inbound policy was "
                         "Allow On: " + ", ".join(allow_profiles) + " — I turned it over "
                         "Block Otherwise, the limitation has no meaning. At /rdpallow clear You come back "
                         "As it was. Check your ports: /firewall"))
    save_config()
    return True





LOG_LEVELS = {"error": (1, 2), "warning": (3,), "all": (1, 2, 3)}


def fetch_system_logs(hours, levels, limit=30):
    """Reads a log System Who Event Viewer: He comes back (Total number or None, lines of events)"""
    lvl = ",".join(str(x) for x in levels)
    ps = (
        "$st=(Get-Date).AddHours(-" + str(hours) + "); "
        "$e=@(Get-WinEvent -FilterHashtable @{LogName='System'; "
        "Level=@(" + lvl + "); StartTime=$st} -MaxEvents 1000 "
        "-ErrorAction SilentlyContinue); "
        "Write-Output ('TOTAL:' + $e.Count); "
        "$e | Select-Object -First " + str(limit) + " | ForEach-Object { "
        "$msg = $_.Message; if (-not $msg) { $msg = '(no message)' }; "
        "$msg = $msg -replace '\\r?\\n', ' '; "
        "if ($msg.Length -gt 90) { $msg = $msg.Substring(0, 90) }; "
        "Write-Output ($_.TimeCreated.ToString('MM-dd HH:mm') + ' | L' "
        "+ $_.Level + ' | ' + $_.ProviderName + ' | #' + $_.Id + ' | ' + $msg) }"
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=120, creationflags=NO_WINDOW)
    except Exception:
        return None, []
    total = None
    lines = []
    for ln in _decode_out(r.stdout).splitlines():
        ln = ln.strip()
        if ln.startswith("TOTAL:"):
            try:
                total = int(ln.split(":", 1)[1])
            except ValueError:
                total = 0
        elif ln:
            lines.append(ln)
    return total, lines


def get_firewall_report():
    """Status of firewall files + Open entry ports: (profiles, ports)"""
    ps = (
        "Write-Output '---P---'; "
        "Get-NetFirewallProfile -ErrorAction SilentlyContinue | "
        "ForEach-Object { Write-Output ($_.Name + '|' + $_.Enabled) }; "
        "Write-Output '---R---'; "
        "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow "
        "-ErrorAction SilentlyContinue | "
        "Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | "
        "Where-Object { $_.LocalPort -and (($_.LocalPort -ne 'Any') -or "
        "-not $_.Protocol -or $_.Protocol -eq 'Any' -or $_.Protocol -eq 'TCP') } | "
        "ForEach-Object { $_.LocalPort } | Sort-Object -Unique"
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=120, creationflags=NO_WINDOW)
    except Exception:
        return None, []
    section = ""
    profiles, ports = [], []
    for ln in _decode_out(r.stdout).splitlines():
        ln = ln.strip()
        if ln == "---P---":
            section = "P"
            continue
        if ln == "---R---":
            section = "R"
            continue
        if section == "P" and "|" in ln:
            name, en = ln.split("|", 1)
            profiles.append((name, en.lower() == "true"))
        elif section == "R" and ln:
            ports.append(ln)
    return profiles, ports


def format_netstat():
    """Active communications + Open ports with the name of the owner program"""
    try:
        conns = psutil.net_connections(kind="tcp")
    except Exception as e:
        return f"[X] I couldn’t read the communications: {e}"

    def pname(pid):
        if not pid:
            return "?"
        try:
            return psutil.Process(pid).name()
        except Exception:
            return "?"

    est = [c for c in conns if c.status == psutil.CONN_ESTABLISHED and c.raddr]
    lst = {}
    for c in conns:
        if c.status == psutil.CONN_LISTEN and c.laddr:
            key = (c.laddr.ip, c.laddr.port)
            known = lst.get(key, "?")
            cur = pname(c.pid)
            # We keep the known name - The unknown name does not match the one before it
            if known == "?" and cur != "?":
                lst[key] = cur
            elif key not in lst:
                lst[key] = cur

    lines = [" <b>Active communications (ESTABLISHED)</b>", "<pre>"]
    if est:
        for c in est[:25]:
            lines.append(esc(f"{c.laddr.ip}:{c.laddr.port} -> "
                             f"{c.raddr.ip}:{c.raddr.port} [{pname(c.pid)}]"))
        if len(est) > 25:
            lines.append(esc(f"... And {len(est) - 25} Another connection"))
    else:
        lines.append("There is no")
    lines.append("</pre>\n <b>Open ports (LISTEN)</b>\n<pre>")
    open_count = 0
    for (ip, port), name in sorted(lst.items(), key=lambda x: x[0][1]):
        if open_count >= 25:
            lines.append(esc(f"... And {len(lst) - open_count} Another port"))
            break
        scope = "Local only" if ip.startswith("127.") else "Open on the network [WARN]"
        lines.append(esc(f"{ip}:{port} [{name}] ") + scope)
        open_count += 1
    lines.append("</pre>")
    return "\n".join(lines)





# ----------------------------- Diagnostics of system logs -----------------------------

EVENT_EXPLANATIONS = {
    # (Source in small print, Event number): (Icon, The reason for the event and the proposed action)
    ("kernel-power", 41): ("", "Unexpected shutdown: The device turned off or froze without turning it off properly "
                                 "(Loss of power, complete freeze, or power outage)"),
    ("eventlog", 6008): ("", "The previous suspension was unexpected: The system subsequently records the extinguishing process"),
    ("bugcheck", 1001): ("", "Blue screen BSOD: The system has completely collapsed - See files Minidump With /dumps"),
    ("disk", 7): ("", "A read operation failed/Write to disk: Possibility of bad sectors"),
    ("disk", 11): ("", "The disk definition encountered an error: The disk may be failing - Take a backup"),
    ("disk", 153): ("", "Input error/Eject to disk: Possible bad sectors - chkdsk And a backup copy immediately"),
    ("ntfs", 55): ("", "File system corruption NTFS: Run chkdsk /f On the disk mentioned in the message"),
    ("whea-logger", 18): ("", "Strict hardware error (WHEA): Processor problem/Ram/Motherboard - Monitor the temperature and secure the parts"),
    ("whea-logger", 19): ("", "Corrected hardware error (WHEA): An early sign of a hardware problem - Watch for repetition"),
    ("whea-logger", 20): ("", "Hardware error (WHEA): Processor or memory related crash"),
    ("service control manager", 7031): ("", "Service collapsed: It ended suddenly and then tried again - Her name is in the letter"),
    ("service control manager", 7034): ("", "Service ended suddenly: If the same service is repeated, it is unstable"),
    ("application error", 1000): ("", "Program collapse: Unhandled exception Close the application - His name is in the message"),
    ("application error", 1002): ("", "The program freezes and stops responding (Hang) - Repeating the same program means a problem with it"),
    (".net runtime", 1026): ("", "Application crash .NET: Unhandled exception within the application"),
    ("application error", 1018): ("", "Application crash .NET"),
}

# Template PowerShell To withdraw critical events/Errors from my log System AndApplication
# {M} = time window in minutes, {LV} = Event levels (1 = Just embarrassed, 1,2 = Critical + Error)
PS_DIAG_EVENTS = (
    "$st=(Get-Date).AddMinutes(-{M}); "
    "foreach ($log in @('System','Application')) { "
    "$e=Get-WinEvent -FilterHashtable @{LogName=$log; Level=@({LV}); StartTime=$st} "
    "-MaxEvents 500 -ErrorAction SilentlyContinue; "
    "foreach ($x in $e) { "
    "$m=$x.Message; if (-not $m) { $m='(no message)' }; "
    "$m=($m -replace '\\r?\\n', ' ') -replace '\\|', '/'; "
    "if ($m.Length -gt 120) { $m=$m.Substring(0,120) }; "
    "Write-Output ($log+'|'+$x.ProviderName+'|'+$x.Id+'|'"
    "+$x.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')+'|'+$m) } }"
)


def fetch_diagnosis_events(minutes, levels="1,2"):
    """Collects system events: He comes back [(Record, source, number, time, message)] Or None When you fail"""
    ps = PS_DIAG_EVENTS.replace("{M}", str(minutes)).replace("{LV}", levels)
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=180, creationflags=NO_WINDOW)
    except Exception as e:
        print(f"[diagnosis] error: {e}")
        return None
    events = []
    for ln in _decode_out(r.stdout).splitlines():
        parts = ln.strip().split("|", 4)
        if len(parts) == 5 and parts[2].isdigit():
            events.append((parts[0], parts[1], int(parts[2]), parts[3], parts[4]))
    return events


def explain_event(provider, eid):
    """Explains the cause of an event from the dictionary: He comes back (Icon, explanation)"""
    p = (provider or "").lower().replace("microsoft-windows-", "")
    hit = EVENT_EXPLANATIONS.get((p, eid))
    if hit:
        return hit
    # Matched with family: Source names vary between versions of Windows, but the family is fixed
    if eid == 1001 or "bugcheck" in p:
        return ("", "Blue screen BSOD: The system collapsed - See files Minidump With /dumps")
    if "whea" in p:
        return ("", "Hardware error (WHEA): Indicator of a processor problem/Ram/Motherboard")
    if p in ("disk", "ntfs", "volmgr", "volsnap", "storahci", "stornvme") \
            or "disk" in p:
        return ("", "Disk problem/Storage: Review the text of the message and think about it chkdsk And a backup copy")
    if "kernel-power" in p:
        return ("", "Energy problem/Unexpected shutdown")
    if "service control" in p:
        return ("", "System service problem: The name of the service in the message")
    return ("", f"Error from source {provider} - See the text of the message")


def _crash_categories(group_keys):
    """Categorizes a group of events (Source, number) into categories of general problems arranged by priority"""
    cats = set()
    for prov, eid in group_keys:
        p = (prov or "").lower().replace("microsoft-windows-", "")
        if eid == 1001 or "bugcheck" in p:
            cats.add("bsod")
        elif eid == 41 or "kernel-power" in p or (p == "eventlog" and eid == 6008):
            cats.add("power")
        elif p in ("disk", "ntfs", "volmgr", "storahci", "stornvme") or "disk" in p:
            cats.add("disk")
        elif "whea" in p:
            cats.add("hw")
        elif "service control" in p:
            cats.add("svc")
        else:
            cats.add("app")
    ADVICE = {
        "bsod": ("", "Blue screen recorded - Top priority: Export files with /dumps And check the reason"),
        "power": ("", "Unexpected shutdown - Check power and freeze before anything"),
        "disk": ("", "Disk errors - Second priority: Back up immediately then chkdsk"),
        "hw": ("", "Hardware errors WHEA - Monitor temperature, install parts, and update drivers"),
        "svc": ("", "System services crash - Select the service from the event details above"),
        "app": ("", "Programs collapse - Annoying but usually does not threaten system stability"),
    }
    res = []
    for c in ("bsod", "power", "disk", "hw", "svc", "app"):
        if c in cats:
            res.append(ADVICE[c])
    return res


def diagnose_report(hours=24):
    """Diagnostic report: Collects errors, explains the reason for each one, and gives a summary of priorities"""
    events = fetch_diagnosis_events(hours * 60)
    if events is None:
        return "[X] Failed to read logs (Try from a manager account)"
    if not events:
        return (f"[OK] <b>Diagnosis</b> - Another {hours} hours\n"
                "There are no critical events or errors. The system is clean ")
    groups = {}
    for log, prov, eid, ts, msg in events:
        g = groups.setdefault((prov, eid),
                              {"n": 0, "last": ts, "msg": msg, "log": log})
        g["n"] += 1
        g["last"] = ts
    lines = [rtl(f"<b>Error diagnosis</b> — Another {hours} hours ({len(events)} It happened)"), ""]
    rows, reasons = [], []
    for (prov, eid), g in sorted(groups.items(),
                                 key=lambda kv: -kv[1]["n"])[:15]:
        icon, why = explain_event(prov, eid)
        rows.append(f"{prov[:30]} #{eid} x{g['n']}  {g['last']}")
        reasons.append((icon, why, prov, eid, g))
    lines.append("<pre>" + esc("\n".join(rows)) + "</pre>")
    for icon, why, prov, eid, g in reasons[:8]:
        lines.append(rtl(f"{icon} <b>{esc(prov)}</b> #{eid} — {esc(why)}"))
    verdicts = _crash_categories(groups.keys())
    if verdicts:
        lines.append("")
        lines.append(rtl("━━ <b>Conclusion and priorities</b> ━━"))
        for icon, advice in verdicts:
            lines.append(rtl(f"{icon} {advice}"))
    return "\n".join(lines)


def logstats_report(days=7):
    """The components of the system that produce the most errors over a period"""
    events = fetch_diagnosis_events(days * 24 * 60)
    if events is None:
        return "[X] Failed to read logs (Try from a manager account)"
    if not events:
        return f" Another {days} days: There are no errors at all "
    counts = {}
    for _log, prov, eid, _ts, _msg in events:
        counts[(prov, eid)] = counts.get((prov, eid), 0) + 1
    lines = [rtl(f" <b>Components of problems</b> — Another {days} days ({len(events)} Error)"),
             "",
             "<pre>"]
    for (prov, eid), n in sorted(counts.items(), key=lambda kv: -kv[1])[:10]:
        icon, _why = explain_event(prov, eid)
        lines.append(esc(f"{icon} {prov[:32]} #{eid} x{n}"))
    lines.append("</pre>")
    return "\n".join(lines)


def logstats_summary(days=7, top=3):
    """Short version for scheduled reports - Returns text or empty text"""
    events = fetch_diagnosis_events(days * 24 * 60)
    if not events:
        return ""
    counts = {}
    for _log, prov, eid, _ts, _msg in events:
        counts[(prov, eid)] = counts.get((prov, eid), 0) + 1
    parts = [f"{prov} #{eid} ×{n}" for (prov, eid), n
             in sorted(counts.items(), key=lambda kv: -kv[1])[:top]]
    return " Most sources of errors this week: " + " · ".join(parts)


def check_critical_events():
    """Immediate alert of any critical event (Level 1) New in System and Applications logs
    - Interference gate: The scan may take longer than the scheduling cycle"""
    if not _check_start("critical_events"):
        return
    try:
        _check_critical_events_impl()
    finally:
        _check_end("critical_events")


def _check_critical_events_impl():
    global _seen_critical, _critical_baseline
    events = fetch_diagnosis_events(3, levels="1")
    if events is None:
        return
    def _ev_key(ev):
        # Include the full timestamp and a message slice so events that share a
        # provider/id are not suppressed across years or repeated incidents.
        return f"{ev[0]}|{ev[1]}|{ev[2]}|{ev[3]}|{ev[4][:60]}"
    if not _critical_baseline:
        _critical_baseline = True
        _seen_critical = {_ev_key(ev): True for ev in events}
        return
    new = []
    for ev in events:
        key = _ev_key(ev)
        if key not in _seen_critical:
            _seen_critical[key] = True
            new.append(ev)
    if len(_seen_critical) > 1000:
        # dict Listed in order: We grab the newest and effectively throw away the oldest (It was set In no order)
        _seen_critical = dict(list(_seen_critical.items())[-500:])
    if not new:
        return
    if len(new) > 5:
        # A flood of events: We summarize instead of flooding the chat
        send_buttons(f" You register {len(new)} A critical event occurred during the last minutes!\n"
                     "Press the button to analyze the full reason:",
                     [[("Diagnose now", "run:/diagnose")]])
        return
    lines = [rtl("<b>CRITICAL SYSTEM EVENT</b>")]
    for log, prov, eid, ts, msg in new:
        icon, why = explain_event(prov, eid)
        lines.append(rtl(f"\n{icon} <b>{esc(prov)}</b> #{eid} at {ts} ({log} log)"))
        lines.append(rtl(f"Likely cause: {esc(why)}"))
        lines.append(esc(msg[:120]))
    audit_record("Critical event: "
                 + "; ".join(f"{p} #{e}" for _l, p, e, _t, _m in new))
    send_buttons("\n".join(lines),
                 [[("Diagnose", "run:/diagnose"),
                   ("Crash dumps", "run:/dumps")]])


PS_SHUTDOWN_HISTORY = (
    "$st=(Get-Date).AddHours(-24); "
    "$e=Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$st} "
    "-MaxEvents 400 -ErrorAction SilentlyContinue | "
    "Where-Object { $_.Id -in @(41,6008,1001,1074) }; "
    "foreach ($x in $e) { "
    "$m=$x.Message; if (-not $m) { $m='' }; "
    "$m=($m -replace '\\r?\\n', ' ') -replace '\\|', '/'; "
    "if ($m.Length -gt 100) { $m=$m.Substring(0,100) }; "
    "Write-Output ($x.Id+'|'+$x.TimeCreated.ToString('MM-dd HH:mm')+'|'+$m) }"
)


def _crash_dumps(max_age_days=30):
    """Recent crash dump files: [(Path, size, modification time)]"""
    dumps = []
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    locations = [os.path.join(sysroot, "Minidump"),
                 os.path.join(sysroot, "MEMORY.DMP"),
                 os.path.join(sysroot, "LiveKernelReports")]
    cutoff = time.time() - max_age_days * 86400
    for loc in locations:
        if os.path.isfile(loc):
            try:
                st = os.stat(loc)
                if st.st_mtime >= cutoff:
                    dumps.append((loc, st.st_size, st.st_mtime))
            except OSError:
                pass
        elif os.path.isdir(loc):
            for f in os.listdir(loc):
                if not f.lower().endswith(".dmp"):
                    continue
                fp = os.path.join(loc, f)
                try:
                    st = os.stat(fp)
                    if st.st_mtime >= cutoff:
                        dumps.append((fp, st.st_size, st.st_mtime))
                except OSError:
                    pass
    return sorted(dumps, key=lambda d: -d[2])


def boot_report():
    """Startup report: Is the last fire extinguished properly? Blue screen? Dump files?"""
    if not config.get("startup_report", False):
        return
    unexpected, bsod, clean = [], [], []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            PS_SHUTDOWN_HISTORY],
                           capture_output=True, timeout=120, creationflags=NO_WINDOW)
        for ln in _decode_out(r.stdout).splitlines():
            parts = ln.split("|", 2)
            if len(parts) < 2 or not parts[0].strip().isdigit():
                continue
            eid, ts = parts[0].strip(), parts[1].strip()
            if eid in ("41", "6008"):
                unexpected.append(ts)
            elif eid == "1001":
                bsod.append(ts)
            elif eid == "1074":
                clean.append(parts[2][:80] if len(parts) > 2 else "")
    except Exception as e:
        print(f"[boot-report] error: {e}")
        return

    lines = ["<b>Startup report</b>"]
    if bsod:
        lines.append(f" Blue screen recorded: {', '.join(bsod[:3])} "
                     "- See the dump files below")
    elif unexpected:
        lines.append(f" The latest shutdown was unexpected (Register {unexpected[0]}) - "
                     "Loss of power or freezing")
    elif clean:
        lines.append(f"[OK] The last extinguishing was fine ({clean[0][:60]})")
    else:
        lines.append("[OK] There are no indicators of a blue screen or an unexpected shutdown during 24 hours")

    dumps = _crash_dumps()
    if dumps:
        lines.append("\n Recent crash dump files:")
        for path, size, mtime in dumps[:3]:
            when = datetime.fromtimestamp(mtime).strftime("%m-%d %H:%M")
            lines.append(f"• {os.path.basename(path)} - {format_size(size)} - {when}")
        lines.append("Send /dumps To download and analyze the latest file")
    send_message("\n".join(lines))





# ----------------------------- Reliability: Pulse, revival, monitoring RDP And the Internet -----------------------------

def check_keepalive():
    """Plays back programs recorded in /keepalive If you close + Alert"""
    for w in (config.get("keepalive") or []):
        name = (w.get("name") or "").lower()
        if not name:
            continue
        found = False
        for p in psutil.process_iter(['name']):
            try:
                if (p.info.get('name') or '').lower() == name:
                    found = True
                    break
            except Exception:
                pass
        if found:
            continue
        # Deadline 5 Minutes between attempts at revival - We prevent a continuous failover loop
        now_ts = time.time()
        if now_ts - _keepalive_last.get(name, 0) < 300:
            continue
        _keepalive_last[name] = now_ts
        if len(_keepalive_last) > 200:
            for k in [k for k, t in _keepalive_last.items() if now_ts - t > 86400]:
                _keepalive_last.pop(k, None)
        # Custom order = shell With manager powers: Portal /exec It applies literally
        # (It was the only way left to execute orders with /exec And/run Disabled)
        if not config.get("exec_enabled"):
            send_message(rtl(f"Revival went beyond {w['name']}: Custom run command "
                             "Requires activation /set exec on"))
            continue
        run = w.get("run") or w["name"]
        try:
            if w.get("run"):
                # An operating command written by the owner himself in his settings (He may need shell) — Intentional and reliable
                subprocess.Popen(run, shell=True, creationflags=NO_WINDOW)
            else:
                try:
                    os.startfile(run)  # None shell — Which opens the door to orders
                except OSError:
                    subprocess.Popen([run], creationflags=NO_WINDOW)
            send_message(f"Program <b>{w['name']}</b> It was locked - It turned on automatically")
        except Exception as e:
            print(f"[keepalive] start error: {e}")
            send_message(f"[X] Program <b>{w['name']}</b> It’s locked and I can’t turn it on "
                         f"({e})\nSee the run command: /keepalive add Name path")


def _rdp_registry_port():
    """Reads port RDP Real from the registry (Trusted source) - None If reading fails"""
    try:
        import winreg
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server"
                r"\WinStations\RDP-Tcp") as k:
            val, _t = winreg.QueryValueEx(k, "PortNumber")
            return int(val)
    except Exception:
        return None


def check_rdp_service():
    """He makes sure that RDP He hears it on his real port (From the registry, not from settings):
    - If the settings differ from the registry, we will correct them automatically without warning
      (The old setting was causing false alarm every 15 minutes and restart the service properly!)
    - If the service really doesn’t listen: Alert after 2 minutes + Restart"""
    global _rdp_down_since, _last_rdp_restart
    reg_port = _rdp_registry_port()
    cfg_port = int(config.get("rdp_port", 3389))
    port = reg_port or cfg_port
    # Automatic sync: The settings were saying 3389 And reality 44389 = Permanent false alarm
    if reg_port and cfg_port != reg_port:
        config["rdp_port"] = reg_port
        save_config()
        send_message(rtl(
            f"outlet RDP In the registry it is <b>{reg_port}</b> It was in the settings "
            f"<b>{cfg_port}</b> — Settings fixed automatically (Without any actual error)"))
    listening = False
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port == port:
                listening = True
                break
    except Exception as e:
        print(f"[rdp-watch] error: {e}")
        return
    if listening:
        if _rdp_down_since:
            _rdp_down_since = None
            send_message(f"[OK] Service RDP You are back listening on the port {port}")
        return
    now_ts = time.time()
    if _rdp_down_since is None:
        _rdp_down_since = now_ts
    if now_ts - _rdp_down_since < 120:
        return  # Two consecutive minutes before any action - We avoid false alarms
    if now_ts - _last_rdp_restart < 900:
        return  # Try to restart all 15 1 minute max
    _last_rdp_restart = now_ts
    send_buttons(
        rtl("<b>RDP SERVICE DOWN</b>") + "\n"
        + rtl(f"Not listening on port ({port}) - if this continues you lose remote access") + "\n"
        + rtl("Attempting to restart the service automatically..."),
        [[("RDP status", "run:/rdp"),
          ("Restart service now", "run:/svc restart TermService")]])
    if ps_ok("Restart-Service TermService -Force -ErrorAction Stop", timeout=60):
        send_message(rtl("RDP service restarted - verify you can connect"))
    else:
        send_message(rtl("Failed to restart the RDP service (check admin rights) - "
                         "the machine may need manual intervention"))


_last_allow_sync = 0.0


def check_rdp_allow_sync():
    """Ensures that the rules are limited RDP In the firewall associated with the current port:
    - Changing the port was leaving the permission rules/Blocking on the old port
      The new port remains open to the world despite the activation of the restriction! (A vulnerability we actually discovered)"""
    if not config.get("rdp_allow_active") and not lockdown_active():
        return
    # During lock we only sync the actual approved list
    ips = lockdown_ips() if lockdown_active() \
        else [str(i) for i in (config.get("rdp_allowed_ips") or [])]
    if not ips:
        return
    port = _rdp_registry_port() or int(config.get("rdp_port", 3389))
    ps = ("$r = Get-NetFirewallRule -DisplayName "
          "'RDPMonitor RDP Allow List TCP' -ErrorAction SilentlyContinue; "
          "if ($r) { ($r | Get-NetFirewallPortFilter).LocalPort } "
          "else { Write-Output 'MISSING' }")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=60,
                           creationflags=NO_WINDOW)
        out = _decode_out(r.stdout).strip()
    except Exception:
        return
    if out == str(port):
        return  # Everything is in sync
    if apply_rdp_allow(ips):
        send_message(rtl(
            f" <b>Limitation rules RDP It was on the wrong port!</b>\n"
            f"It was: {out or 'Missing'} — Supposedly: {port}\n"
            f"I have now reapplied it to the correct port"))
        audit_record(f"Reapply inventory RDP On the port {port} (It was: {out})")


def _ping_ok(target):
    """try ping One - Returns whether it was successful or not"""
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", "3000", target],
                           capture_output=True, timeout=10, creationflags=NO_WINDOW)
        return r.returncode == 0
    except Exception:
        return False


def check_internet():
    """Internet monitoring: Alert after two minutes interruption + Warning when returning"""
    global _net_down_streak
    target = config.get("ping_target", "1.1.1.1")
    if _ping_ok(target):
        if _net_down_streak >= 2:
            send_message(f"[OK] <b>I got the internet back</b> (It was cut off "
                         f"{_net_down_streak} About a minute)")
        _net_down_streak = 0
    else:
        _net_down_streak += 1
        if _net_down_streak == 2:
            send_message(f" <b>The Internet is cut off on the device</b>\n"
                         f"ping {target} Failed 2 minutes ago\n"
                         "The device is working but without internet")


_last_fw_check = 0.0


def check_firewall_guard():
    """Firewall guarding - We discovered the actual incident: The wall was completely matted
    All the blocks, mats, and locks were 'On paper':
    - If the firewall file is turned off: Ensures that the port is RDP It has a permission rule, activates it, and informs you"""
    if not _check_start("fw_guard"):
        return
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-NetFirewallProfile | ForEach-Object { "
                            "Write-Output ($_.Name + '|' + [int][bool]$_.Enabled) }"],
                           capture_output=True, timeout=60, creationflags=NO_WINDOW)
        off = []
        for ln in _decode_out(r.stdout).splitlines():
            parts = ln.strip().split("|")
            if len(parts) == 2 and parts[1] == "0":
                off.append(parts[0])
        if not off:
            return
        # Safety first: Make sure that RDP It delivers — But there is no broad rule that breaks the restrictions!
        # (The guard was creating a general tolerance rule even if the restriction was enabled = It opens RDP To the world)
        port = _rdp_registry_port() or int(config.get("rdp_port", 3389))
        if config.get("rdp_allow_active"):
            # A restriction is configured. Never fall back to a general allow rule
            # (that would open RDP to the world). If we cannot reapply it, leave
            # the firewall exactly as it is and alert the operator.
            ips = lockdown_ips() if lockdown_active() \
                else [str(i) for i in (config.get("rdp_allowed_ips") or [])]
            if not ips:
                send_message(rtl("Firewall guard skipped: the IP allow-list is enabled but empty. "
                                 "Fix it first: /rdpallow add IP then /rdpallow apply confirm"))
                return
            if not apply_rdp_allow(ips):
                send_message(rtl("Firewall guard aborted: the IP allow-list could not be reapplied, "
                                 "so the firewall was left unchanged (RDP was NOT opened to the world). "
                                 "Fix it: /rdpallow apply confirm"))
                return
        else:
            access_ready, err = _create_general_rdp_rule(port)
            if not access_ready:
                send_message(rtl("[X] I did not activate the firewall because creating an access rule "
                                 "RDP Reliable failure. Fix the wall powers first.")
                             + (f"\n{esc(err)}" if err else ""))
                return
        ok, err = _netsh(["advfirewall", "set", "allprofiles", "state", "on"])
        if not ok:
            send_message(f"[X] Firewall activation failed: {esc(err)}")
            return
        audit_record("Firewall guarding: Activate dead files: " + ", ".join(off))
        send_buttons(
            rtl("<b>The firewall was off!</b>") + "\n"
            + rtl(f"Matte files: {esc(', '.join(off))}") + "\n"
            + rtl("All prohibition and restriction rules were not implemented — Activate them now automatically") + "\n"
            + rtl("Make sure your connection RDP It works, check the ports: /firewall"),
            [[("Firewall report", "run:/firewall"),
              ("Blocklist", "run:/blocklist")]])
    except Exception as e:
        print(f"[fw-guard] error: {e}")
    finally:
        _check_end("fw_guard")


def check_update_available():
    """Compares version on update_url In the current version - If you disagree, he will alert you (Without installation)
    - We compare the bytes of the file as is: Reading the text was unifying CRLF→LF
      The comparison always becomes different and the warning is repeated endlessly"""
    url = config.get("update_url", "")
    if not url:
        return
    try:
        r = requests.get(url, timeout=60)
        new_hash = hashlib.sha256(r.content).hexdigest()
    except Exception as e:
        print(f"[update-check] error: {e}")
        return
    try:
        with open(SCRIPT_PATH, "rb") as f:
            cur_hash = hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return
    if new_hash != cur_hash:
        send_message("UL  <b>There is a new update for the tool</b> on the specified link.\n"
                     "Review your changes first, then submit /update To install.\n"
                     "To stop the scan: /set updatecheck 0")


# ----------------------------- Account for transferred data -----------------------------

TRAFFIC_FILE = os.path.join(BASE_DIR, "traffic.json")


def load_traffic():
    """Holds daily count + Last sample counters — Turning the tool off and on doubles the count
    (It was the first sample after all restart It re-adds every byte of the device’s boot)"""
    global _traffic, _last_traffic_counters
    try:
        if os.path.exists(TRAFFIC_FILE):
            with open(TRAFFIC_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            return
        if isinstance(data, dict) and "days" in data:
            _traffic = data.get("days") or {}
            last = data.get("last")
            # Boot ID: Pre-reboot system counters are worthless with
            # New boot even if it is larger than the saved one (An account shortage was occurring)
            if data.get("boot") == psutil.boot_time() \
                    and isinstance(last, (list, tuple)) and len(last) == 2:
                _last_traffic_counters = (last[0], last[1])
        else:
            _traffic = data  # Old formula: Dictionary of days directly
    except Exception:
        _traffic = {}


def save_traffic():
    """Atomic conservation - A power outage does not waste the daily count nor the last sample counters"""
    try:
        tmp = TRAFFIC_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"days": _traffic, "boot": psutil.boot_time(),
                       "last": list(_last_traffic_counters or [])}, f)
        os.replace(tmp, TRAFFIC_FILE)
    except Exception as e:
        print(f"[traffic] save error: {e}")


def traffic_job():
    """Collects the bytes transferred since the last sample and adds them to the day’s count - Every cycle is monitored"""
    global _last_traffic_counters, _last_traffic_save, _last_traffic_check
    c = psutil.net_io_counters()
    if _last_traffic_counters:
        d_sent = c.bytes_sent - _last_traffic_counters[0]
        d_recv = c.bytes_recv - _last_traffic_counters[1]
        # If the meters decrease, the device will be restarted - We are counting from the start of take-off
        if d_sent < 0:
            d_sent = c.bytes_sent
        if d_recv < 0:
            d_recv = c.bytes_recv
    else:
        # First run of the tool on this installation only (After the first save, the counters are saved
        # In traffic.json Restarting the tool will continue without delay)
        d_sent = c.bytes_sent
        d_recv = c.bytes_recv
    day = datetime.now().strftime("%Y-%m-%d")
    with _traffic_lock:
        rec = _traffic.setdefault(day, {"down": 0.0, "up": 0.0})
        rec["down"] += d_recv / (1024 ** 2)   # MB
        rec["up"] += d_sent / (1024 ** 2)
        # Cleaning: We keep 95 day
        if len(_traffic) > 95:
            cutoff = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")
            for k in list(_traffic.keys()):
                if k < cutoff:
                    del _traffic[k]
    _last_traffic_counters = (c.bytes_sent, c.bytes_recv)
    now_ts = time.time()
    if now_ts - _last_traffic_save >= 300:
        _last_traffic_save = now_ts
        save_traffic()
        check_traffic_quota()
    _last_traffic_check = now_ts


def quota_window_start():
    """The beginning of the current billing cycle based on the day of the return (The default is the first of the month)"""
    day = min(max(int(config.get("traffic_reset_day", 1) or 1), 1), 28)
    now = datetime.now()
    if now.day >= day:
        return datetime(now.year, now.month, day)
    prev = datetime(now.year, now.month, 1) - timedelta(days=1)
    return datetime(prev.year, prev.month, day)


def traffic_since(start_dt):
    """Total (Download, upload) In megabytes since a certain date"""
    start_str = start_dt.strftime("%Y-%m-%d")
    down = up = 0.0
    with _traffic_lock:
        snapshot = dict(_traffic)
    for day, rec in snapshot.items():
        if day >= start_str:
            down += rec.get("down", 0)
            up += rec.get("up", 0)
    return down, up


def check_traffic_quota():
    """Monthly quota alerts: 50% / 80% / 95%"""
    quota = float(config.get("traffic_quota_gb", 0) or 0)
    if quota <= 0:
        return
    down, up = traffic_since(quota_window_start())
    used_gb = (down + up) / 1024
    pct = used_gb / quota * 100
    month_key = quota_window_start().strftime("%Y-%m")
    for level, mark in ((50, ""), (80, ""), (95, "")):
        key = f"{month_key}_{level}"
        if pct >= level and not _traffic_alerted.get(key):
            _traffic_alerted[key] = True
            if len(_traffic_alerted) > 36:
                # Keep only the most recent quota-alert markers.
                for k in sorted(_traffic_alerted)[:-24]:
                    _traffic_alerted.pop(k, None)
            send_message(
                f"{mark} <b>Data consumption alert</b>\n"
                f"Consumed {used_gb:.1f} GB of share {quota:.0f} GB "
                f"({pct:.0f}%) In the current billing cycle\n"
                "Detail: /traffic"
            )


def traffic_report(days=7):
    """Transferred data report: Today, current session, class, and days breakdown"""
    today = datetime.now().strftime("%Y-%m-%d")
    lines = [rtl("<b>Account for transferred data</b>"), ""]
    with _traffic_lock:
        snapshot = dict(_traffic)
    rec = snapshot.get(today)
    if rec:
        lines.append(rtl(f" Today: <b>{(rec['down'] + rec['up']) / 1024:.2f} GB</b> "
                         f"(Download {rec['down'] / 1024:.2f} | Raise {rec['up'] / 1024:.2f})"))
    else:
        lines.append(" Today: No data has been transferred yet (Or the tool has started now)")
    start = quota_window_start()
    down, up = traffic_since(start)
    lines.append(rtl(f" Billing cycle (since {start:%m-%d}): "
                     f"<b>{(down + up) / 1024:.2f} GB</b> "
                     f"(Download {down / 1024:.2f} | Raise {up / 1024:.2f})"))
    quota = float(config.get("traffic_quota_gb", 0) or 0)
    if quota > 0:
        used = (down + up) / 1024
        pct = min(100.0, used / quota * 100)
        bars = int(pct // 5)
        lines.append(rtl(f" The share: {used:.2f} Who {quota:.0f} GB"))
        lines.append("" * bars + "" * (20 - bars) + f" {pct:.0f}%")
    else:
        lines.append(rtl("There is no specific quota — Select it: /set traffic 500"))
    all_down = sum(r.get("down", 0) for r in snapshot.values())
    all_up = sum(r.get("up", 0) for r in snapshot.values())
    lines.append(rtl(f" Since installation: <b>{(all_down + all_up) / 1024:.2f} GB</b> "
                     f"(Download {all_down / 1024:.2f} | Raise {all_up / 1024:.2f})"))
    lines.append("")
    lines.append(rtl(f" Another {days} days:"))
    rows = []
    for i in range(days):
        day_dt = datetime.now() - timedelta(days=i)
        r = snapshot.get(day_dt.strftime("%Y-%m-%d"))
        if r:
            rows.append(f"{day_dt:%m-%d}   {(r['down'] + r['up']) / 1024:7.2f} GB"
                        f"   DL {r['down'] / 1024:6.2f}  UL {r['up'] / 1024:6.2f}")
        else:
            rows.append(f"{day_dt:%m-%d}      -")
    lines.append("<pre>" + esc("\n".join(rows)) + "</pre>")
    lines.append(rtl("Ranking: History | Total | Download | Raise"))
    return "\n".join(lines)


# ----------------------------- Complete control and advanced diagnostics -----------------------------

PANIC_RULE = "RDPMonitor PANIC"
SCHED_RULE = "RDPMonitor Schedule"


def block_subnet(ip):
    """Network blocked /24 Complete - Against corrupted proxies within the same domain
    - He comes back (succeeded?, status) Like block_ip"""
    if not _valid_ip(ip) or "." not in ip:
        return False, "requires IPv4"
    net = ".".join(ip.split(".")[:3]) + ".0/24"
    with _blocked_file_guard():
        load_blocked()
        if net in _blocked:
            return True, "exists"
        ok, err = _netsh(["advfirewall", "firewall", "add", "rule",
                          f"name=RDPMonitor Block {net}", "dir=in",
                          "action=block", f"remoteip={net}"])
        if ok:
            _blocked[net] = time.time()
            save_blocked()
            return True, "added"
    print(f"[block-subnet] netsh error ({net}): {err}")
    return False, (err or "Failed netsh Without a message")


def _panic_rule_exists():
    """Return True only when the panic block rule actually exists."""
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"(Get-NetFirewallRule -DisplayName '{PANIC_RULE}' "
         "-ErrorAction SilentlyContinue).Count"],
        capture_output=True, timeout=60, creationflags=NO_WINDOW)
    return _decode_out(r.stdout).strip() not in ("", "0")


def panic_on():
    """Panic mode: Close RDP Totally + Block all previous attempters"""
    if config.get("panic_active"):
        send_message(rtl("Panic mode is already on — /panic off To stop"))
        return
    blocked_now = []
    for ip in list(_failed_logins.keys()):
        bok, _st = block_ip(ip)
        if bok:
            blocked_now.append(ip)
    port = int(config.get("rdp_port", 3389))
    ok = ps_ok(f"New-NetFirewallRule -DisplayName '{PANIC_RULE}' -Direction Inbound "
               f"-Protocol TCP -LocalPort {port} -Action Block -ErrorAction Stop",
               timeout=60)
    if not ok:
        # Second check: Does the rule really exist? (You may encounter a format error in the output)
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-NetFirewallRule -DisplayName '{PANIC_RULE}' "
             "-ErrorAction SilentlyContinue).Count"],
            capture_output=True, timeout=60, creationflags=NO_WINDOW)
        ok = _decode_out(r.stdout).strip() not in ("", "0")
    if not ok:
        # The status is recorded and success is announced only if the rule actually exists
        audit_record("Failed to activate panic mode - The closing rule has not been established")
        send_message(rtl("[X] Failed to create shutdown rule — Panic mode <b>Not activated</b>. "
                         "Check administrator permissions"))
        return
    config["panic_active"] = True
    save_config()
    audit_record("Panic mode is activated")
    send_message(
        rtl("<b>Panic mode is activated!</b>") + "\n"
        + rtl(f"RDP Completely closed on the port ({port}) — Login via RDP Impossible now") + "\n"
        + rtl(f"Blocked {len(blocked_now)} IP From previous attempts") + "\n"
        + rtl("Return: /panic off"))


def panic_off():
    """End panic mode: Open RDP Again"""
    if not config.get("panic_active"):
        send_message(rtl("There is no panic mode activated"))
        return
    _netsh(["advfirewall", "firewall", "delete", "rule", f"name={PANIC_RULE}"])
    # Verify that the rule has actually been deleted — He was announcing "The panic is over" It remains busy
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"(Get-NetFirewallRule -DisplayName '{PANIC_RULE}' "
         "-ErrorAction SilentlyContinue).Count"],
        capture_output=True, timeout=60, creationflags=NO_WINDOW)
    if _decode_out(r.stdout).strip() not in ("", "0"):
        send_message(rtl("[X] The lockdown rule has not been removed — Panic mode "
                         "<b>It’s still activated</b>! Repeat /panic off Or see permissions"))
        return
    config["panic_active"] = False
    save_config()
    audit_record("Panic mode is over")
    send_message(rtl("<b>Panic mode is over</b> — RDP Back available "
                     "(Fortify it: /harden fix And /lockdown on)"))


def panic_rearm():
    """If the tool is restarted and panic is activated - Make sure the rule exists
    - We delete the old rule first: Repetition was accumulating rules with the same name"""
    port = int(config.get("rdp_port", 3389))
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={PANIC_RULE}"], capture_output=True, timeout=30, creationflags=NO_WINDOW)
    ps_ok(f"New-NetFirewallRule -DisplayName '{PANIC_RULE}' -Direction Inbound "
          f"-Protocol TCP -LocalPort {port} -Action Block "
          f"-ErrorAction SilentlyContinue")
    if not _panic_rule_exists():
        # The rule is missing, so RDP is NOT actually closed. Never report panic
        # as active while the port may be open.
        config["panic_active"] = False
        save_config()
        audit_record("Panic rule missing on restart - panic mode reported inactive")
        send_message(rtl("[WARN] Panic mode was active, but its firewall rule could not be "
                         "recreated. RDP is <b>not</b> closed. Panic mode has been reported "
                         "inactive — activate it again with /panic on"))
        return
    send_message(rtl(" Panic mode is still activated from before — RDP Closed. /panic off To return"))


def _parse_hours(spec):
    """Analyze "9-23" To (9, 23) - Supports night shifts 22-6"""
    m = re.fullmatch(r"(\d{1,2})\s*-\s*(\d{1,2})", (spec or "").strip())
    if not m:
        return None
    a, b = int(m.group(1)), int(m.group(2))
    if a > 23 or b > 23 or a == b:
        return None
    return a, b


def rdp_schedule_tick():
    """Opens and closes an outlet RDP According to specified working hours"""
    spec = config.get("rdphours", "")
    rng = _parse_hours(spec)
    port = int(config.get("rdp_port", 3389))
    blocked_flag = bool(config.get("rdpsched_blocked"))
    if rng:
        a, b = rng
        in_hours = (a <= datetime.now().hour < b) if a < b \
            else (datetime.now().hour >= a or datetime.now().hour < b)
    else:
        in_hours = True
    if not in_hours and not blocked_flag:
        try:
            r = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                f"name={SCHED_RULE}", "dir=in", "action=block",
                                "protocol=TCP", f"localport={port}"],
                               capture_output=True, timeout=30, creationflags=NO_WINDOW)
            if r.returncode == 0:
                config["rdpsched_blocked"] = True
                save_config()
                send_message(rtl(f" Outside hours RDP ({spec}) — I closed the port {port}"))
        except Exception as e:
            print(f"[schedule] error: {e}")
    elif in_hours and blocked_flag:
        _netsh(["advfirewall", "firewall", "delete", "rule", f"name={SCHED_RULE}"])
        # Verify that the rule has actually been deleted — He was recording "Open" The rule remains in use
        # And don’t try again (The sign is flipped to open)
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-NetFirewallRule -DisplayName '{SCHED_RULE}' "
             "-ErrorAction SilentlyContinue).Count"],
            capture_output=True, timeout=60, creationflags=NO_WINDOW)
        if _decode_out(r.stdout).strip() in ("", "0"):
            config["rdpsched_blocked"] = False
            save_config()
            send_message(rtl(f"Hours started RDP ({spec}) — I opened the port {port}"))
        else:
            print("[schedule] Failed to delete lockout rule - Try again next session")


def check_services():
    """Monitors registered Windows services - If I stopped, he would repeat it and warn me"""
    for w in (config.get("svcwatch") or []):
        name = (w.get("name") or "").strip()
        if not name:
            continue
        try:
            svc = psutil.win_service_get(name).as_dict()
        except Exception:
            continue
        if svc.get("status") == "running":
            continue
        now_ts = time.time()
        if now_ts - _svcwatch_last.get(name.lower(), 0) < 900:
            continue  # Try to reset all 15 1 minute max
        _svcwatch_last[name.lower()] = now_ts
        if len(_svcwatch_last) > 200:
            for k in [k for k, t in _svcwatch_last.items() if now_ts - t > 86400]:
                _svcwatch_last.pop(k, None)
        if ps_ok(f"Start-Service -Name '{_ps_quote(name)}' -ErrorAction Stop", timeout=60):
            send_message(rtl(f" Service <b>{esc(name)}</b> She was standing — "
                             "It restarted automatically"))
        else:
            send_message(rtl(f"[X] Service <b>{esc(name)}</b> Standing and failing "
                             "Restart it — Review it manually"))


def _selfheal_job():
    """Self-cleaning when the system disk is full"""
    try:
        freed = clean_temp_files()
        send_message(rtl("<b>Self cleaning worked</b> (Disk bypass 95%)") + "\n"
                     + rtl(f"Space freed up: {format_size(freed)}"))
    except Exception as e:
        send_message(rtl(f"[X] Self cleaning failed: {e}"))














def nettest_job(host):
    """Comprehensive testing: DNS + ping + outlets — Differentiate your problem from their problem"""
    lines = [rtl(f"<b>Connection test:</b> {esc(host)}"), ""]
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        lines.append(rtl(f"[OK] DNS: Resolves to {', '.join(ips[:4])}"))
        ip0 = ips[0]
    except Exception as e:
        lines.append(rtl(f"[X] DNS: Name resolution failed ({esc(e)})"))
        send_message("\n".join(lines))
        return
    if _ping_ok(ip0):
        lines.append(rtl("[OK] Ping: He responds"))
    else:
        lines.append(rtl("[WARN] Ping: What responds (Some servers block it — There is no evidence of a malfunction)"))
    for p in (80, 443):
        try:
            with socket.create_connection((host, p), timeout=5):
                lines.append(rtl(f"[OK] outlet {p}: Open"))
        except Exception:
            lines.append(rtl(f"[X] outlet {p}: Closed or blocked"))
    send_message("\n".join(lines))


def ps_detail(name):
    """Details of each version of the process: Full path and its owner — Detects fakes"""
    rows = []
    for p in psutil.process_iter(['pid', 'name', 'exe', 'username',
                                  'memory_info']):
        try:
            n = p.info.get('name') or ''
            if name.lower() in n.lower():
                mi = p.info.get('memory_info')
                rows.append({
                    "pid": p.info['pid'], "name": n,
                    "exe": p.info.get('exe') or '?',
                    "user": p.info.get('username') or '?',
                    "mem": mi.rss / 1024 ** 2 if mi else 0.0,
                })
        except Exception:
            pass
    if not rows:
        return rtl(f"I didn’t find any process named {esc(name)}")
    lines = [rtl(f" <b>Operations {esc(name)}</b> ({len(rows)} Process)"), "<pre>"]
    for r0 in rows[:12]:
        lines.append(esc(f"PID {r0['pid']:>7} {r0['mem']:7.0f}MB {r0['name'][:24]}"))
    lines.append("</pre>")
    for r0 in rows[:12]:
        lines.append(rtl(f"• [{r0['pid']}] {esc(r0['exe'])} — {esc(r0['user'])}"))
    return "\n".join(lines)


PS_LOGIN_LOG = (
    "$st=(Get-Date).AddDays(-3); "
    "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$st} "
    "-MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object { "
    "try { $x=[xml]$_.ToXml(); $d=@{}; "
    "$x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }; "
    "$ip=$d['IpAddress']; "
    "if ($d['LogonType'] -eq '10' -and $ip -and $ip -ne '-' -and $ip -ne '::1' "
    "-and $ip -ne '127.0.0.1') "
    "{ Write-Output ($_.TimeCreated.ToString('MM-dd HH:mm')+'|'"
    "+$d['TargetUserName']+'|'+$ip) } "
    "} catch {} }"
)


def _logins_job(n):
    """Latest successful logins via RDP"""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", PS_LOGIN_LOG],
                           capture_output=True, timeout=120, creationflags=NO_WINDOW)
        rows = [ln.strip() for ln in _decode_out(r.stdout).splitlines()
                if "|" in ln][:n]
    except Exception as e:
        send_message(rtl(f"[X] Reading failed: {e}"))
        return
    if not rows:
        send_message(rtl("There are no logins RDP registered during 3 days"))
        return
    send_message(rtl(f"<b>Latest successful logins</b> ({len(rows)})") + "\n<pre>"
                 + esc("\n".join(rows)) + "</pre>"
                 + rtl("Ranking: time | User | IP"))


PS_STARTUP = (
    "Write-Output '---RUN---'; "
    "foreach ($k in @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
    "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')) { "
    "try { $p=Get-ItemProperty -Path $k -ErrorAction Stop; "
    "$p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | "
    "ForEach-Object { Write-Output ($_.Name+' = '+$_.Value) } } catch {} }; "
    "Write-Output '---TASK---'; "
    "Get-ScheduledTask -ErrorAction SilentlyContinue | "
    "Where-Object { $_.TaskPath -notlike '\\Microsoft*' } | "
    "ForEach-Object { Write-Output ($_.State.ToString()+' | '+$_.TaskName) }"
)


def startup_job():
    """Inventory of automatic start programs: Keys Run and irregular scheduled tasks"""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", PS_STARTUP],
                           capture_output=True, timeout=120, creationflags=NO_WINDOW)
        section, run_rows, task_rows = "", [], []
        for ln in _decode_out(r.stdout).splitlines():
            ln = ln.strip()
            if ln == "---RUN---":
                section = "RUN"
            elif ln == "---TASK---":
                section = "TASK"
            elif ln and section == "RUN":
                run_rows.append(ln)
            elif ln and section == "TASK":
                task_rows.append(ln)
    except Exception as e:
        send_message(rtl(f"[X] Inventory failure: {e}"))
        return
    lines = [rtl("<b>Auto start programs</b>"), ""]
    lines.append(rtl(f" Keys Run ({len(run_rows)}):"))
    lines.append("<pre>" + esc("\n".join(run_rows[:15]) or "-") + "</pre>")
    lines.append(rtl(f" Irregular scheduled tasks ({len(task_rows)}):"))
    lines.append("<pre>" + esc("\n".join(task_rows[:15]) or "-") + "</pre>")
    lines.append(rtl("Strange entrance? This is a favorite place to hide malware"))
    send_message("\n".join(lines))


PS_SYSINFO = (
    "$os=Get-CimInstance Win32_OperatingSystem; "
    "Write-Output ('CAPTION|'+$os.Caption); "
    "Write-Output ('VERSION|'+$os.Version); "
    "$rb=(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
    "WindowsUpdate\\Auto Update\\RebootRequired') -or "
    "(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
    "Component Based Servicing\\RebootPending'); "
    "Write-Output ('REBOOT|'+$rb); "
    "$cs=Get-CimInstance Win32_ComputerSystem; "
    "Write-Output ('RAM|'+[math]::Round($cs.TotalPhysicalMemory/1GB,1)); "
    "$p=Get-CimInstance Win32_Processor | Select-Object -First 1; "
    "Write-Output ('CPU|'+$p.Name.Trim())"
)


def _sysinfo_job():
    """System card: Version, hardware, pending boot, memory pressure"""
    info = {}
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", PS_SYSINFO],
                           capture_output=True, timeout=90, creationflags=NO_WINDOW)
        for ln in _decode_out(r.stdout).splitlines():
            p0 = ln.split("|", 1)
            if len(p0) == 2:
                info[p0[0]] = p0[1].strip()
    except Exception as e:
        send_message(rtl(f"[X] Failed to collect information: {e}"))
        return
    mem = psutil.virtual_memory()
    sw = psutil.swap_memory()
    lines = [
        rtl("<b>System information</b>"), "",
        rtl(f" System: {esc(info.get('CAPTION', '?'))}"),
        rtl(f" Version: {esc(info.get('VERSION', '?'))}"),
        rtl(f" Processor: {esc(info.get('CPU', '?')[:50])}"),
        rtl(f" rams: {mem.percent:.0f}% User from {info.get('RAM', '?')} GB"),
        rtl(f" Migration file: {sw.percent:.0f}% User"),
        rtl(f" Duration of operation: {format_uptime()}"),
        rtl(" There is a pending restart (Updates)" if info.get("REBOOT") == "True"
            else "[OK] There is no pending restart"),
    ]
    send_message("\n".join(lines))


def when_report(metric="cpu", threshold=80, hours=24):
    """When consumption exceeds its limit during a period - Who registered? history Same"""
    cutoff = time.time() - hours * 3600
    pts = [h for h in _history if h.get("t", 0) >= cutoff]
    key = "c" if metric == "cpu" else "r"
    hits = [h for h in pts if h.get(key, 0) >= threshold]
    if not hits:
        return rtl(f"[OK] There are no moments of transcendence {metric.upper()} {threshold}% "
                   f"During another {hours} hours")
    ranges = []
    start = prev = None
    for h in pts:
        if h.get(key, 0) >= threshold:
            if start is None:
                start = h["t"]
            prev = h["t"]
        elif start is not None:
            ranges.append((start, prev))
            start = None
    if start is not None:
        ranges.append((start, prev))
    lines = [rtl(f" <b>Moments of transcendence {metric.upper()} {threshold}%</b> "
                 f"— Another {hours} hours ({len(hits)} Minute)"), "", "<pre>"]
    for s, e in ranges[:15]:
        lines.append(f"{datetime.fromtimestamp(s):%m-%d %H:%M} -> "
                     f"{datetime.fromtimestamp(e):%H:%M}")
    lines.append("</pre>")
    return "\n".join(lines)





PS_UPDATES = (
    "$rb=(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
    "WindowsUpdate\\Auto Update\\RebootRequired') -or "
    "(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
    "Component Based Servicing\\RebootPending'); "
    "Write-Output ('REBOOT|'+$rb); "
    "try { $s=New-Object -ComObject Microsoft.Update.Session; "
    "$se=$s.CreateUpdateSearcher(); "
    "$res=$se.Search('IsInstalled=0 and IsHidden=0'); "
    "Write-Output ('COUNT|'+$res.Updates.Count); "
    "$res.Updates | Select-Object -First 15 | "
    "ForEach-Object { Write-Output ('U|'+$_.Title) } } "
    "catch { Write-Output ('ERR|'+$_.Exception.Message) }"
)


def updates_job():
    """Pending Windows updates + Restart status"""
    info, titles = {}, []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", PS_UPDATES],
                           capture_output=True, timeout=300, creationflags=NO_WINDOW)
        for ln in _decode_out(r.stdout).splitlines():
            p0 = ln.split("|", 1)
            if len(p0) == 2:
                if p0[0] == "U":
                    titles.append(p0[1])
                else:
                    info[p0[0]] = p0[1].strip()
    except Exception as e:
        send_message(rtl(f"[X] Update check failed: {e}"))
        return
    lines = [rtl("<b>Windows updates</b>"), "",
             rtl(" There is a pending restart" if info.get("REBOOT") == "True"
                 else "[OK] There is no pending restart")]
    if info.get("COUNT") is not None:
        lines.append(rtl(f" Pending updates: {info['COUNT']}"))
        for t in titles:
            lines.append(rtl(f"• {esc(t[:70])}"))
    elif info.get("ERR"):
        lines.append(rtl(f"[WARN] I couldn’t get the list: {esc(info['ERR'][:120])}"))
    send_message("\n".join(lines))





# ----------------------------- Monitoring -----------------------------

def usage_level(cpu, ram):
    m = max(cpu, ram)
    if m >= config["critical_threshold"]:
        return "critical"
    if m >= config["danger_threshold"]:
        return "danger"
    if cpu >= config["cpu_alert_threshold"] or ram >= config["ram_alert_threshold"]:
        return "warning"
    return "ok"


LEVEL_INFO = {
    "warning": ("", "HIGH RESOURCE USAGE"),
    "danger": ("", "VERY HIGH RESOURCE USAGE"),
    "critical": ("", "CRITICAL RESOURCE USAGE"),
}


def format_duration(secs):
    """Duration in seconds to read Arabic text"""
    secs = int(secs)
    h, m = secs // 3600, (secs % 3600) // 60
    if h and m:
        return f"{h} hour and {m} Minute"
    if h:
        return f"{h} hours"
    return f"{m} Minute"





def alerts_muted():
    """Are regular alerts muted now? (Wish and Critical are never affected)"""
    try:
        return time.time() < float(config.get("muted_until", 0) or 0)
    except Exception:
        return False


def send_usage_alert(cpu, ram_pct, used_gb, total_gb, level):
    if level != "critical" and alerts_muted():
        return
    _icon, title = LEVEL_INFO[level]
    body = (f"CPU   {cpu:5.1f}%\n"
            f"RAM   {ram_pct:5.1f}%   ({used_gb:.1f}/{total_gb:.1f} GB)\n"
            f"limits  warn {config['cpu_alert_threshold']}  "
            f"danger {config['danger_threshold']}  "
            f"critical {config['critical_threshold']}")
    send_message(f"<b>{title}</b>\n<pre>{esc(body)}</pre>")


def check_watched_processes():
    """Check the programs under supervision (/watch)"""
    targets = config.get("watch") or []
    if not targets:
        return
    sums = {w["name"].lower(): 0 for w in targets}
    for p in psutil.process_iter(['name', 'memory_info']):
        try:
            pname = (p.info.get('name') or '').lower()
            mi = p.info.get('memory_info')
            if not mi:
                continue
            for key in sums:
                if key in pname:
                    sums[key] += mi.rss
        except Exception:
            pass
    for w in targets:
        mb = sums[w["name"].lower()] / (1024 ** 2)
        if mb >= w["ram_mb"] and \
                time.time() - _watch_cooldown.get(w["name"], 0) >= 600:
            _watch_cooldown[w["name"]] = time.time()
            if len(_watch_cooldown) > 200:
                cutoff = time.time() - 3600
                for k in [k for k, t in _watch_cooldown.items() if t < cutoff]:
                    _watch_cooldown.pop(k, None)
            if not alerts_muted():
                send_message(
                    f" <b>Program monitoring</b>\n"
                    f"Program <b>{w['name']}</b> Exceeding the limit:\n"
                    f" It is used now: {mb / 1024:.2f} GB "
                    f"(limit {w['ram_mb'] / 1024:.1f} GB)\n"
                    f"To close it send: /kill {w['name']}"
                )


def check_sessions():
    """Entry statement/Users log out of the device"""
    global _known_sessions
    try:
        users = {s["user"] for s in get_rdp_sessions() if s.get("user")}
        if _known_sessions is None:
            _known_sessions = users  # First reading = Reference point without alerts
            return
        new = users - _known_sessions
        gone = _known_sessions - users
        if new and not alerts_muted():
            send_buttons(rtl("<b>New user logged in:</b> ")
                         + esc(", ".join(new)),
                         [[("Recent logins", "run:/logins"),
                           ("Screenshot", "run:/screenshot")]])
        if gone and not alerts_muted():
            send_message(rtl("<b>User logged out:</b> ")
                         + esc(", ".join(gone)))
        _known_sessions = users
    except Exception as e:
        print(f"[sessions-check] error: {e}")


def speedtest_job(silent=False):
    try:
        ping_ms, down, up = run_speedtest()
        send_message(
            f" <b>Internet speed</b>\n"
            f"DL  Download: {down:.1f} Mbps\n"
            f"UL  Raise: {up:.1f} Mbps\n"
            f" Response: {ping_ms:.0f} ms"
        )
    except Exception as e:
        if not silent:
            send_message(f"[X] Speed measurement failed: {e}")


def read_only_monitor_loop():
    """Measure real host state without firewall/account/service/power remediation."""
    global _last_history_append, _last_history_save, _last_alert_level
    while not _engine_stop.is_set():
        try:
            cpu, ram, used, total = get_usage()
            update_net_speed()
            now = time.time()
            if now - _last_history_append >= 60:
                _last_history_append = now
                append_history(cpu, ram)
                traffic_job()
            if now - _last_history_save >= 300:
                _last_history_save = now
                save_history()
            level = usage_level(cpu, ram)
            if level != _last_alert_level:
                _last_alert_level = level
                if level != "ok":
                    send_usage_alert(cpu, ram, used, total, level)
            check_sessions()
        except Exception as exc:
            _emit_runtime("[X] Read-only monitoring failed: " + str(exc))
        _engine_stop.wait(5)


def monitor_loop():
    """Main episode: Graduated alerts + Anomaly + Tablets + Programs + Sessions + Reports"""
    global _was_over, _last_alert_time, _last_alert_level, _last_spike, _auto_streak, _last_auto_check
    global _last_auto_restart, _last_disk_check, _last_watch_check, _last_session_check
    global _last_history_append, _last_history_save, _last_speedtest, _last_daily, _last_weekly
    global _session_locked, _last_lock_time, _last_temp_check
    global _last_failed_check, _last_clean_day, _last_critical_check
    global _last_heartbeat, _last_keepalive_check, _last_rdp_check
    global _last_net_watch, _last_update_check, _last_learn
    global _last_svcwatch_check, _last_selfheal, _last_rdpsched_check
    global _last_allow_sync, _last_fw_check
    release_thread = None

    while not _engine_stop.is_set():
        try:
            now_ts = time.time()
            now = datetime.now()
            cpu, ram_pct, used_gb, total_gb = get_usage()

            # --- Network speed ---
            update_net_speed()

            # --- Consumption record (Every minute) ---
            if now_ts - _last_history_append >= 60:
                _last_history_append = now_ts
                append_history(cpu, ram_pct)
            if now_ts - _last_history_save >= 300:
                _last_history_save = now_ts
                save_history()

            # --- Sudden surge detection (Jump in a minute) ---
            _short.append((now_ts, cpu, ram_pct))
            # Compare against the oldest sample inside the last 60 seconds, not
            # against _short[0] which can be ~2 minutes old once the deque fills.
            old = next((s for s in _short if now_ts - s[0] <= 60), None)
            if old is not None and now_ts - old[0] >= 45 \
                    and now_ts - _last_spike >= config["spike_cooldown"]:
                d_cpu = cpu - old[1]
                d_ram = ram_pct - old[2]
                if d_cpu >= config["spike_threshold"] or d_ram >= config["spike_threshold"]:
                    _last_spike = now_ts
                    if not alerts_muted():
                        body = (f"CPU  {old[1]:.0f}% -> {cpu:.0f}%   (+{d_cpu:.0f})\n"
                                f"RAM  {old[2]:.0f}% -> {ram_pct:.0f}%   (+{d_ram:.0f})")
                        send_buttons("<b>SUDDEN SPIKE</b>\n<pre>" + esc(body) + "</pre>",
                                     [[("Top processes", "run:/top")]])

            # --- Tiered alerts + Back to normal ---
            # Escalations fire immediately; a repeat of the same level is limited
            # to at most once every 15 minutes to avoid noisy repeats.
            level = usage_level(cpu, ram_pct)
            if level != "ok":
                escalated = (level != _last_alert_level)
                due = (now_ts - _last_alert_time) >= max(config["alert_interval"], 900)
                if escalated or due:
                    _last_alert_time = now_ts
                    _last_alert_level = level
                    send_usage_alert(cpu, ram_pct, used_gb, total_gb, level)
                _was_over = True
            else:
                if _was_over:
                    _was_over = False
                    _last_alert_time = 0
                    _last_alert_level = "ok"
                    if not alerts_muted():
                        send_message("<b>Usage back to normal</b>\n<pre>"
                                     + esc(f"CPU  {cpu:.1f}%\nRAM  {ram_pct:.1f}%")
                                     + "</pre>")

            # --- Automatic restart (Check every minute) ---
            if now_ts - _last_auto_check >= 60:
                _last_auto_check = now_ts
                if config["auto_restart_enabled"] and (
                        cpu >= config["auto_restart_cpu"]
                        or ram_pct >= config["auto_restart_ram"]):
                    _auto_streak += 1
                    if _auto_streak >= config["auto_restart_consecutive"] and \
                            now_ts - _last_auto_restart > config["restart_cooldown"]:
                        _last_auto_restart = now_ts
                        _auto_streak = 0
                        do_restart(
                            f"Very high consumption (CPU {cpu:.0f}% / RAM {ram_pct:.0f}%) "
                            f"Continuous for several minutes", auto=True)
                else:
                    _auto_streak = 0

            # --- Discs (Every minute) ---
            if now_ts - _last_disk_check >= 60:
                _last_disk_check = now_ts
                for dev, pct, free, _total in get_disks():
                    if pct >= config["disk_threshold"] and not _disk_alerted.get(dev):
                        _disk_alerted[dev] = True
                        if not alerts_muted():
                            send_buttons(
                                rtl("<b>DISK SPACE ALERT</b>") + "\n"
                                + rtl(f"Disk {esc(dev)} is {pct:.0f}% full "
                                      f"(only {free:.1f} GB left)"),
                                [[("Clean now", "run:/clean"),
                                  ("Biggest files", "run:/bigfiles")]])
                    elif pct < config["disk_threshold"] - 5 and _disk_alerted.get(dev):
                        _disk_alerted[dev] = False
                        if not alerts_muted():
                            send_message(rtl(f"Disk {dev} is back under {config['disk_threshold']}%"))

            # --- Programs are under supervision (Every minute) ---
            if now_ts - _last_watch_check >= 60:
                _last_watch_check = now_ts
                check_watched_processes()

            # --- Sessions RDP (Eat 30 Again - With a separate thread: Deadline qwinsta 10 Seconds
            #     It was freezing the whole main loop) ---
            if config.get("session_alerts") and now_ts - _last_session_check >= 30:
                _last_session_check = now_ts
                threading.Thread(target=check_sessions, daemon=True).start()

            # --- Failed login attempts (Every minute) ---
            if (config.get("failed_login_alerts")
                    or config.get("failed_login_block")
                    or config.get("trap_users")) \
                    and now_ts - _last_failed_check >= 60:
                _last_failed_check = now_ts
                threading.Thread(target=check_failed_logons,
                                 daemon=True).start()

            # --- Critical events in the log (Every minute) ---
            if config.get("critical_alerts") and \
                    now_ts - _last_critical_check >= 60:
                _last_critical_check = now_ts
                threading.Thread(target=check_critical_events,
                                 daemon=True).start()

            # --- The pulse: Message "It still works" Eat N hours ---
            hb = float(config.get("heartbeat_hours", 0) or 0)
            if hb > 0:
                if _last_heartbeat == 0:
                    _last_heartbeat = now_ts
                elif now_ts - _last_heartbeat >= hb * 3600:
                    _last_heartbeat = now_ts
                    send_message(
                        rtl(f"<b>Still alive</b> - {hb:.0f} hours without issues") + "\n"
                        + rtl(f"CPU: {cpu:.1f}% | RAM: {ram_pct:.1f}%") + "\n"
                        + rtl(f"Machine uptime: {format_uptime()}")
                    )

            # --- Revitalize programs (Every minute) ---
            if config.get("keepalive") and \
                    now_ts - _last_keepalive_check >= 60:
                _last_keepalive_check = now_ts
                threading.Thread(target=check_keepalive, daemon=True).start()

            # --- Outlet monitoring RDP (Every minute) ---
            if config.get("rdp_watch", True) and \
                    now_ts - _last_rdp_check >= 60:
                _last_rdp_check = now_ts
                threading.Thread(target=check_rdp_service, daemon=True).start()

            # --- Internet monitoring (Every minute) ---
            if config.get("net_watch", True) and \
                    now_ts - _last_net_watch >= 60:
                _last_net_watch = now_ts
                threading.Thread(target=check_internet, daemon=True).start()

            # --- Firewall guarding (Eat 5 Minutes) ---
            if config.get("fw_guard", True) and \
                    now_ts - _last_fw_check >= 300:
                _last_fw_check = now_ts
                threading.Thread(target=check_firewall_guard, daemon=True).start()

            # --- Check for a newer version (Eat N hours) ---
            uch = float(config.get("update_check_hours", 0) or 0)
            if config.get("update_url") and uch > 0:
                if _last_update_check == 0:
                    _last_update_check = now_ts
                elif now_ts - _last_update_check >= uch * 3600:
                    _last_update_check = now_ts
                    threading.Thread(target=check_update_available,
                                     daemon=True).start()

            # --- Learn IP Success (Eat 10 Minutes) ---
            if config.get("auto_learn_ips", True) and \
                    now_ts - _last_learn >= 600:
                _last_learn = now_ts
                threading.Thread(target=learn_successful_ips,
                                 daemon=True).start()

            # --- Automatically terminate the lock when its duration expires ---
            # (The condition required the lock to be operational and timed out together = Impossible together,
            #  The lock remains activated forever, and the restriction rules are accumulated from an old session)
            _luntil = float(config.get("lockdown_until", 0) or 0)
            if _luntil and now_ts > _luntil \
                    and (release_thread is None or not release_thread.is_alive()):
                # The release worker clears the deadline only after success.
                # Keep failed releases eligible without overlapping workers.
                release_thread = threading.Thread(
                    target=lockdown_release, kwargs={"auto": True}, daemon=True)
                release_thread.start()

            # --- Account for transferred data (Eat 30 Again) ---
            if now_ts - _last_traffic_check >= 30:
                traffic_job()

            # --- Monitor services (Every minute) ---
            if config.get("svcwatch") and now_ts - _last_svcwatch_check >= 60:
                _last_svcwatch_check = now_ts
                threading.Thread(target=check_services, daemon=True).start()

            # --- Working hours RDP (Every minute - She was creating a new thread every 5 Seconds) ---
            if (config.get("rdphours") or config.get("rdpsched_blocked")) \
                    and now_ts - _last_rdpsched_check >= 60:
                _last_rdpsched_check = now_ts
                threading.Thread(target=rdp_schedule_tick, daemon=True).start()

            # --- Synchronization of inventory rules RDP With the current port (Eat 10 Minutes) ---
            if config.get("rdp_allow_active") \
                    and now_ts - _last_allow_sync >= 600:
                _last_allow_sync = now_ts
                threading.Thread(target=check_rdp_allow_sync,
                                 daemon=True).start()

            # --- Self-cleaning when the system disk is full ---
            if config.get("selfheal_disk") and now_ts - _last_selfheal >= 6 * 3600:
                for dev, pct, _f, _t in get_disks():
                    if dev.upper().startswith(
                            os.environ.get("SystemDrive", "C:").upper()) \
                            and pct >= 95:
                        _last_selfheal = now_ts
                        threading.Thread(target=_selfheal_job, daemon=True).start()
                        break

            # --- Heat (Every two minutes) ---
            if now_ts - _last_temp_check >= 120:
                _last_temp_check = now_ts

                def _temp_watch():
                    global _last_temp_alert
                    try:
                        temps = get_temps()
                        hot = {k: v for k, v in temps.items()
                               if v >= config.get("temp_threshold", 85)}
                        if hot and time.time() - _last_temp_alert >= 600:
                            _last_temp_alert = time.time()
                            parts = ", ".join(f"{k} {v:.0f}°C"
                                              for k, v in hot.items())
                            if not alerts_muted():
                                send_buttons(
                                    rtl("<b>HIGH TEMPERATURE</b>") + "\n"
                                    + rtl(f"{parts} - high temperature can throttle the machine, check cooling"),
                                    [[("Read temps", "run:/temp"),
                                      ("Top processes", "run:/top")]])
                    except Exception as e:
                        print(f"[temp] error: {e}")

                threading.Thread(target=_temp_watch, daemon=True).start()

            # --- Automatic session lock ---
            lock_min = int(config.get("auto_lock_minutes") or 0)
            if lock_min > 0:
                idle = idle_seconds()
                if idle >= lock_min * 60 and not _session_locked \
                        and now_ts - _last_lock_time > lock_min * 60:
                    _last_lock_time = now_ts
                    if lock_session():
                        _session_locked = True
                        send_message(
                            " <b>The session was automatically locked</b>\n"
                            f"The device was idle {lock_min} Minute\n"
                            "To disable: /set lock 0")
                elif idle < 60:
                    _session_locked = False

            # --- Automatic weekly cleaning ---
            if config.get("auto_clean_enabled") and \
                    now.weekday() == config.get("auto_clean_day", 5) and \
                    now.hour == config.get("auto_clean_hour", 3) and \
                    _last_clean_day != now.date():
                _last_clean_day = now.date()

                def _auto_clean():
                    try:
                        freed = clean_temp_files()
                        send_message("<b>Automatic weekly cleaning</b>\n"
                                     f"Edited: {format_size(freed)}")
                    except Exception as e:
                        print(f"[clean] error: {e}")

                threading.Thread(target=_auto_clean, daemon=True).start()

            # --- Periodic speed measurement ---
            hours = config.get("speedtest_interval_hours", 0)
            if hours and hours > 0 and now_ts - _last_speedtest >= hours * 3600:
                _last_speedtest = now_ts
                threading.Thread(target=speedtest_job, kwargs={"silent": True},
                                 daemon=True).start()

            # --- Daily report ---
            if config["daily_report_enabled"] and \
                    now.hour == config["daily_report_hour"] and _last_daily != now.date():
                _last_daily = now.date()
                threading.Thread(target=send_daily_report, daemon=True).start()

            # --- Weekly report ---
            if config["weekly_report_enabled"] and \
                    now.weekday() == config["weekly_report_day"] and \
                    now.hour == config["weekly_report_hour"] and \
                    _last_weekly != now.date():
                _last_weekly = now.date()
                threading.Thread(target=send_weekly_report, daemon=True).start()

        except Exception as e:
            print(f"[monitor] error: {e}")

        _engine_stop.wait(5)


# ----------------------------- Chat commands -----------------------------




SET_BOUNDS = {
    "cpu": (1, 100), "ram": (1, 100), "danger": (1, 100),
    "critical": (1, 100), "disk": (10, 99), "spike": (1, 100),
    "interval": (30, 86400), "dailyhour": (0, 23),
    "weeklyday": (0, 6), "speedtest": (0, 8760),
    "autolimit": (50, 100), "autocount": (1, 60),
    "lock": (0, 1440), "tempalert": (40, 120),
    "blocklimit": (1, 100), "cleanday": (0, 6),
    "heartbeat": (0, 168), "updatecheck": (0, 8760),
    "lockdownlimit": (1, 1000), "lockdownmins": (1, 1440),
    "traffic": (0, 1000000), "trafficday": (1, 28),
}










# --- Settings: one validated path shared by /set and the WebConsole panel ---

# key -> config field (used to read the current value for the panel)
SET_FIELDS = {
    "cpu": "cpu_alert_threshold", "ram": "ram_alert_threshold",
    "danger": "danger_threshold", "critical": "critical_threshold",
    "disk": "disk_threshold", "spike": "spike_threshold",
    "interval": "alert_interval", "daily": "daily_report_enabled",
    "dailyhour": "daily_report_hour", "weekly": "weekly_report_enabled",
    "weeklyday": "weekly_report_day", "speedtest": "speedtest_interval_hours",
    "exec": "exec_enabled", "users": "user_management",
    "uploads": "uploads_enabled", "sessions": "session_alerts",
    "accountwatch": "account_watch", "name": "instance_name",
    "lock": "auto_lock_minutes", "logins": "failed_login_alerts",
    "block": "failed_login_block", "blocklimit": "failed_login_block_threshold",
    "tempalert": "temp_threshold", "traffic": "traffic_quota_gb",
    "trafficday": "traffic_reset_day", "autorestart": "auto_restart_enabled",
    "autolimit": "auto_restart_cpu", "autocount": "auto_restart_consecutive",
    "autoclean": "auto_clean_enabled", "heartbeat": "heartbeat_hours",
    "rdpwatch": "rdp_watch", "netwatch": "net_watch", "fwguard": "fw_guard",
    "updatecheck": "update_check_hours", "image": "image_enabled",
    "imagedel": "image_delete_after", "rcloneremote": "rclone_remote",
    "subnetblock": "subnetblock", "selfheal": "selfheal_disk",
    "newipalert": "new_ip_alerts", "learn": "auto_learn_ips",
    "learnforlockdown": "learn_for_lockdown", "lockdown": "lockdown",
    "lockdownlimit": "lockdown_limit", "lockdownmins": "lockdown_minutes",
}

# (group, [(key, label, type, min, max, unit), ...]) for the panel settings tab

















                     # {user_id: [ts]} To specify the command rate
                  # Order execution queue (Prevents disabling reception)
               # Maximum number of commands per minute per user















# ----------------------------- Unpack system changes ( uninstall) -----------------------------




# ----------------------------- Operating -----------------------------





