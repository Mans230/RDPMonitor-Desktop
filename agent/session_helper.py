"""Explicit per-user Windows session actions, never a Session-0 UI fallback."""
from __future__ import annotations

import base64
import ctypes
import io
import os
import subprocess
import tempfile
import threading
from pathlib import Path

from .contracts import OperationError, succeeded
from .ipc import PipeServer, account_sid, current_identity, pipe_call, protect_path

HELPER_MAX_MESSAGE = 24 * 1024 * 1024
SCREENSHOT_MAX = 16 * 1024 * 1024
SESSION_STATES = {0: "active", 1: "connected", 2: "connect_query", 3: "shadow",
                  4: "disconnected", 5: "idle", 6: "listen", 7: "reset", 8: "down", 9: "init"}


def _windows():
    if os.name != "nt":
        raise OperationError("windows_required", "User-session operations require Windows.", 409)
    import win32ts
    return win32ts


def current_session_id():
    _windows()
    value = ctypes.c_ulong()
    if not ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(value)):
        raise OperationError("session_identity", "Unable to determine helper session.", 409)
    return value.value


def _pipe_name(session_id):
    return rf"\\.\pipe\RDPMonitor.Session.{session_id}.v1"


def _interactive_desktop():
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.OpenInputDesktop.argtypes = (ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong)
    user32.OpenInputDesktop.restype = ctypes.c_void_p
    user32.SwitchDesktop.argtypes = (ctypes.c_void_p,)
    user32.SwitchDesktop.restype = ctypes.c_bool
    user32.CloseDesktop.argtypes = (ctypes.c_void_p,)
    desktop = user32.OpenInputDesktop(0, False, 0x100)
    if not desktop:
        return False
    try:
        return bool(user32.SwitchDesktop(desktop))
    finally:
        user32.CloseDesktop(desktop)


def _idle_seconds():
    class LastInput(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

    value = LastInput()
    value.cbSize = ctypes.sizeof(value)
    if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(value)):
        return None
    # GetLastInputInfo timestamps are the current user's 32-bit tick count.
    ctypes.windll.kernel32.GetTickCount.restype = ctypes.c_uint
    return ((ctypes.windll.kernel32.GetTickCount() - value.dwTime) & 0xFFFFFFFF) / 1000.0


def _session_state(session_id):
    wts = _windows()
    try:
        state = wts.WTSQuerySessionInformation(wts.WTS_CURRENT_SERVER_HANDLE, session_id,
                                               wts.WTSConnectState)
        return int(state)
    except Exception:
        raise OperationError("session_unavailable", "The selected Windows session no longer exists.", 409)


class SessionHelper:
    """Worker-side broker. Screenshot data never goes through a public file route."""

    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)

    def sessions(self):
        wts = _windows()
        result = []
        try:
            sessions = wts.WTSEnumerateSessions(wts.WTS_CURRENT_SERVER_HANDLE, 1, 0)
        except Exception:
            raise OperationError("session_discovery", "Windows session discovery failed.", 503)
        for session in sessions:
            sid = int(session["SessionId"])
            state = int(session["State"])
            try:
                username = wts.WTSQuerySessionInformation(wts.WTS_CURRENT_SERVER_HANDLE, sid, wts.WTSUserName)
                domain = wts.WTSQuerySessionInformation(wts.WTS_CURRENT_SERVER_HANDLE, sid, wts.WTSDomainName)
            except Exception:
                username, domain = "", ""
            row = {"id": sid, "session_id": sid, "name": session.get("WinStationName", ""),
                   "username": username, "domain": domain, "state": SESSION_STATES.get(state, "unknown"),
                   "interactive": sid != 0 and bool(username), "helper_available": False,
                   "locked": None, "idle_seconds": None}
            if row["interactive"] and state == 0:
                try:
                    response = self._request(row, "status", {})
                    row["helper_available"] = True
                    row["locked"] = response["locked"]
                    row["idle_seconds"] = response.get("idle_seconds")
                except OperationError:
                    pass
            row["limitation"] = ("Session 0 cannot host interactive tasks." if sid == 0 else
                "Disconnected sessions cannot receive interactive actions." if state != 0 else
                "Start the RDPMonitor session helper as this signed-in user." if not row["helper_available"] else
                "Unlock the desktop for screenshots and launches." if row["locked"] else "")
            result.append(row)
        return result

    def _request(self, session, action, args):
        name = (session["domain"] + "\\" if session["domain"] else "") + session["username"]
        try:
            sid = account_sid(name)
        except Exception:
            raise OperationError("session_identity", "Cannot verify selected user's Windows identity.", 409)
        return pipe_call(_pipe_name(session["session_id"]), {"action": action, "args": args},
                         expected_sid=sid, maximum=HELPER_MAX_MESSAGE,
                         expected_session=session["session_id"])

    def execute(self, action, args, context):
        if action not in {"screenshot", "message", "launch", "lock", "logoff", "recycle_bin"}:
            raise OperationError("session_action", "Unknown user-session action.", 400)
        session_id = args.get("session_id")
        if isinstance(session_id, bool) or not isinstance(session_id, int) or session_id <= 0:
            raise OperationError("session_required", "Select an explicit nonzero Windows session ID.", 400)
        if context.cancel.is_set():
            return {"status": "cancelled", "message": "Session action cancelled before dispatch.", "data": None}
        matches = [row for row in self.sessions() if row["session_id"] == session_id]
        if not matches or not matches[0]["interactive"] or matches[0]["state"] != "active":
            raise OperationError("session_unavailable", "The selected session is not an active signed-in session.", 409)
        session = matches[0]
        if not session["helper_available"]:
            raise OperationError("helper_unavailable", "Start the session helper in the selected user's session; SYSTEM fallback is prohibited.", 409)
        result = self._request(session, action, {key: value for key, value in args.items() if key != "session_id"})
        if action != "screenshot":
            return succeeded(result.pop("message", "Session action completed."), result)
        try:
            image = base64.b64decode(result["data_base64"], validate=True)
        except (ValueError, KeyError):
            raise OperationError("screenshot_invalid", "The session helper returned invalid screenshot data.", 502)
        if not image or len(image) > SCREENSHOT_MAX or not image.startswith(b"\x89PNG\r\n\x1a\n"):
            raise OperationError("screenshot_limit", "Screenshot exceeds the 16 MiB limit or is not PNG.", 413)
        directory = self.data_dir / "session-artifacts"
        directory.mkdir(parents=True, exist_ok=True)
        protect_path(directory, directory=True)
        descriptor, filename = tempfile.mkstemp(prefix=f"session-{session_id}-", suffix=".png", dir=directory)
        path = Path(filename)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(image)
            protect_path(path)
            artifact = context.artifact(path, name=f"session-{session_id}.png", media_type="image/png")
            return succeeded("Screenshot captured in the selected user's session.",
                             {"session_id": session_id}, [artifact])
        finally:
            path.unlink(missing_ok=True)


def _handle_action(session_id, request, peer):
    if not peer["admin"]:
        raise OperationError("session_peer", "Only the privileged local worker may request session actions.", 403)
    if set(request) != {"action", "args"} or not isinstance(request["args"], dict):
        raise OperationError("session_request", "Invalid session-helper request.", 400)
    if current_session_id() != session_id or _session_state(session_id) != 0:
        raise OperationError("session_unavailable", "Helper session is not active.", 409)
    action, args = request["action"], request["args"]
    locked = not _interactive_desktop()
    if action == "status":
        return {"session_id": session_id, "locked": locked, "pid": os.getpid(),
                "idle_seconds": _idle_seconds()}
    if action in {"screenshot", "launch"} and locked:
        raise OperationError("desktop_locked", "Unlock the selected session before this operation.", 409)
    if action == "screenshot":
        if args:
            raise OperationError("session_arguments", "Screenshot takes no additional arguments.")
        from PIL import ImageGrab
        try:
            image = ImageGrab.grab(all_screens=True)
            stream = io.BytesIO()
            image.save(stream, format="PNG")
            data = stream.getvalue()
        except Exception:
            raise OperationError("capture_failed", "Windows could not capture this user's desktop.", 409)
        if len(data) > SCREENSHOT_MAX:
            raise OperationError("screenshot_limit", "Screenshot exceeds 16 MiB.", 413)
        return {"session_id": session_id, "data_base64": base64.b64encode(data).decode("ascii")}
    if action == "message":
        if set(args) - {"message", "title"}:
            raise OperationError("session_arguments", "Invalid message arguments.")
        message, title = args.get("message"), args.get("title", "RDPMonitor")
        if not isinstance(message, str) or not 1 <= len(message) <= 8192 or not isinstance(title, str) or len(title) > 128:
            raise OperationError("session_arguments", "Message/title length is invalid.")
        response = ctypes.c_ulong()
        wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
        wts.WTSSendMessageW.argtypes = (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p,
            ctypes.c_ulong, ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong), ctypes.c_bool)
        if not wts.WTSSendMessageW(None, session_id, title, len(title.encode("utf-16-le")),
                message, len(message.encode("utf-16-le")), 0x40, 60, ctypes.byref(response), False):
            raise OperationError("message_failed", "Windows could not deliver the session message.", 409)
        return {"message": "Windows accepted the session message (display expires after 60 seconds).",
                "session_id": session_id, "accepted": True}
    if action == "launch":
        if set(args) - {"executable", "arguments", "cwd"}:
            raise OperationError("session_arguments", "Invalid launch arguments.")
        executable = args.get("executable")
        arguments = args.get("arguments", [])
        cwd = args.get("cwd")
        if not isinstance(executable, str) or not Path(executable).is_absolute() or not Path(executable).is_file():
            raise OperationError("executable_required", "An existing absolute executable path is required.")
        if Path(executable).suffix.lower() not in {".exe", ".com"}:
            raise OperationError("executable_required", "Launch requires a native executable, not a shell script.")
        if not isinstance(arguments, list) or len(arguments) > 128 or any(not isinstance(v, str) or "\x00" in v for v in arguments):
            raise OperationError("session_arguments", "Launch arguments must be a bounded string list.")
        if len(subprocess.list2cmdline([executable, *arguments])) > 30000:
            raise OperationError("session_arguments", "Launch command line is too long.")
        if cwd is not None and (not isinstance(cwd, str) or not Path(cwd).is_absolute() or not Path(cwd).is_dir()):
            raise OperationError("session_arguments", "Working directory must be an existing absolute directory.")
        try:
            process = subprocess.Popen([executable, *arguments], cwd=cwd, shell=False,
                                       close_fds=True, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        except OSError:
            raise OperationError("launch_failed", "Windows could not launch the program as this user.", 409)
        return {"message": "Program launched as the selected signed-in user.", "pid": process.pid,
                "session_id": session_id, "execution_identity": current_identity()["sid"]}
    if action == "recycle_bin":
        if args:
            raise OperationError("session_arguments", "Recycle Bin cleanup takes no additional arguments.")
        class BinInfo(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_ulong), ("bytes", ctypes.c_longlong), ("items", ctypes.c_longlong)]
        shell = ctypes.WinDLL("shell32")
        shell.SHQueryRecycleBinW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(BinInfo)]
        shell.SHQueryRecycleBinW.restype = ctypes.c_long
        shell.SHEmptyRecycleBinW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
        shell.SHEmptyRecycleBinW.restype = ctypes.c_long
        before, after = BinInfo(), BinInfo()
        before.cbSize = after.cbSize = ctypes.sizeof(BinInfo)
        if shell.SHQueryRecycleBinW(None, ctypes.byref(before)) < 0:
            raise OperationError("recycle_bin_query", "Windows could not inspect this user's Recycle Bin.", 409)
        if shell.SHEmptyRecycleBinW(None, None, 7) < 0:
            raise OperationError("recycle_bin_cleanup", "Windows could not empty this user's Recycle Bin.", 409)
        if shell.SHQueryRecycleBinW(None, ctypes.byref(after)) < 0:
            raise OperationError("recycle_bin_verification", "Cleanup was requested but the remaining contents could not be verified.", 409)
        return {"message": "Selected user's Recycle Bin cleanup verified.", "session_id": session_id,
                "bytes_removed": max(0, before.bytes - after.bytes), "items_removed": max(0, before.items - after.items),
                "remaining_items": after.items}
    if action == "lock":
        if args:
            raise OperationError("session_arguments", "Lock takes no additional arguments.")
        if not ctypes.windll.user32.LockWorkStation():
            raise OperationError("lock_failed", "Windows refused the workstation lock.", 409)
        return {"message": "Windows accepted the selected session lock.", "session_id": session_id}
    if action == "logoff":
        if args:
            raise OperationError("session_arguments", "Logoff takes no additional arguments.")
        wts = _windows()
        wts.WTSLogoffSession(wts.WTS_CURRENT_SERVER_HANDLE, session_id, False)
        return {"message": "Windows accepted selected session logoff; unsaved work may be lost.", "session_id": session_id}
    raise OperationError("session_action", "Unknown user-session action.", 400)


def run_session_helper(stop_event: threading.Event, session_id=None):
    actual = current_session_id()
    identity = current_identity()
    if actual == 0 or identity["sid"] in {"S-1-5-18", "S-1-5-19", "S-1-5-20"}:
        raise OperationError("interactive_user_required", "Session helper must run as the signed-in user outside Session 0.", 403)
    if session_id is not None and session_id != actual:
        raise OperationError("session_identity", "A helper may serve only its own Windows session.", 403)
    server = PipeServer(_pipe_name(actual), lambda request, peer: _handle_action(actual, request, peer),
                        allowed_sids=[identity["sid"]], maximum=HELPER_MAX_MESSAGE)
    print(f"RDPMonitor session helper ready session={actual}", flush=True)
    server.serve(stop_event)
