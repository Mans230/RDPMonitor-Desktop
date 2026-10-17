"""Bounded, local-only Windows named-pipe RPC; no callable/pickle transport."""
from __future__ import annotations

import base64
import ctypes
import json
import os
import struct
import threading
import time
from pathlib import Path

from .contracts import OperationError

DEFAULT_PIPE = r"\\.\pipe\RDPMonitor.Worker.v1"
GATEWAY_ACCOUNT = r"NT SERVICE\RDPMonitorGateway"
MAX_MESSAGE = 1024 * 1024
RPC_METHODS = frozenset({"health", "catalog", "snapshot", "history", "pairing.enroll",
    "devices.list", "devices.revoke", "devices.renew", "confirmations.prepare", "jobs.submit", "jobs.list",
    "jobs.get", "jobs.cancel", "events.list", "events.ack", "audit.list", "artifacts.get",
    "artifacts.read", "config.get", "config.set", "uploads.begin", "uploads.write", "uploads.status",
    "uploads.complete", "notifications.register", "notifications.unregister", "notifications.status", "notifications.test"})


def windows_modules():
    if os.name != "nt":
        raise OperationError("windows_required", "Named-pipe services require Windows.", 503)
    import pywintypes
    import win32api
    import win32con
    import win32event
    import win32file
    import win32pipe
    import win32security
    return pywintypes, win32api, win32con, win32event, win32file, win32pipe, win32security


def account_sid(account):
    *_, security = windows_modules()
    return security.ConvertSidToStringSid(security.LookupAccountName(None, account)[0])


def _token_identity(token):
    *_, security = windows_modules()
    sid = security.ConvertSidToStringSid(security.GetTokenInformation(token, security.TokenUser)[0])
    groups = security.GetTokenInformation(token, security.TokenGroups)
    admin = sid == "S-1-5-18" or any(security.ConvertSidToStringSid(group) == "S-1-5-32-544"
              and flags & 4 and not flags & 16 for group, flags in groups)
    return {"sid": sid, "admin": bool(admin)}


def current_identity():
    _, api, con, _, _, _, security = windows_modules()
    token = security.OpenProcessToken(api.GetCurrentProcess(), con.TOKEN_QUERY)
    try:
        return _token_identity(token)
    finally:
        token.Close()


def client_identity(handle):
    _, api, con, _, _, _, security = windows_modules()
    security.ImpersonateNamedPipeClient(handle)
    try:
        token = security.OpenThreadToken(api.GetCurrentThread(), con.TOKEN_QUERY, True)
        try:
            return _token_identity(token)
        finally:
            token.Close()
    finally:
        security.RevertToSelf()


def validate_server(handle, expected_sid=None, expected_session=None):
    _, api, con, _, _, _, security = windows_modules()
    pid = ctypes.c_ulong()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetNamedPipeServerProcessId.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
    kernel.GetNamedPipeServerProcessId.restype = ctypes.c_bool
    if not kernel.GetNamedPipeServerProcessId(int(handle), ctypes.byref(pid)):
        raise OperationError("pipe_identity", "Cannot verify local pipe server.", 503)
    if expected_session is not None:
        session = ctypes.c_ulong()
        if not kernel.ProcessIdToSessionId(pid.value, ctypes.byref(session)) or session.value != expected_session:
            raise OperationError("pipe_session", "Helper is not in the selected Windows session.", 403)
    try:
        process = api.OpenProcess(0x1000, False, pid.value)
        try:
            token = security.OpenProcessToken(process, con.TOKEN_QUERY)
            try:
                identity = _token_identity(token)
            finally:
                token.Close()
        finally:
            process.Close()
    except Exception:
        # A constrained service account may query SCM but not a SYSTEM process token.
        # SCM binds this PID to the protected worker service and its configured identity.
        if expected_sid is not None or not _is_worker_service(pid.value):
            raise OperationError("pipe_identity", "Cannot verify local pipe server identity.", 403)
        identity = {"sid": "S-1-5-18", "admin": True}
    if (expected_sid and identity["sid"] != expected_sid) or (not expected_sid and not identity["admin"]):
        raise OperationError("pipe_identity", "Local pipe server identity is not trusted.", 403)


def _is_worker_service(pid):
    import win32service
    manager = service = None
    try:
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = win32service.OpenService(manager, "RDPMonitorWorker",
            win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_QUERY_STATUS)
        status = win32service.QueryServiceStatusEx(service)
        config = win32service.QueryServiceConfig(service)
        return (status["ProcessId"] == pid and config[7].lower() in {"localsystem", r"nt authority\system"})
    except Exception:
        return False
    finally:
        if service:
            win32service.CloseServiceHandle(service)
        if manager:
            win32service.CloseServiceHandle(manager)


def pipe_security(sids=()):
    py, _, _, _, _, _, security = windows_modules()
    attributes = py.SECURITY_ATTRIBUTES()
    sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)" + "".join(f"(A;;GRGW;;;{sid})" for sid in set(sids))
    attributes.SECURITY_DESCRIPTOR = security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
    return attributes


def protect_path(path: Path, read_sid=None, directory=False):
    """Replace inherited permissions, never grant gateway access to state/CA secrets."""
    *_, security = windows_modules()
    inherited = "OICI" if directory else ""
    sddl = f"O:BAD:P(A;{inherited};FA;;;SY)(A;{inherited};FA;;;BA)"
    if read_sid:
        sddl += f"(A;{inherited};GRGX;;;{read_sid})"
    descriptor = security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
    security.SetFileSecurity(str(path), security.OWNER_SECURITY_INFORMATION |
                             security.DACL_SECURITY_INFORMATION |
                             security.PROTECTED_DACL_SECURITY_INFORMATION, descriptor)


def _transfer(handle, data_or_length, writing=False, timeout=15000):
    py, _, _, event, file, _, _ = windows_modules()
    overlapped = py.OVERLAPPED()
    overlapped.hEvent = event.CreateEvent(None, True, False, None)
    buffer = data_or_length if writing else file.AllocateReadBuffer(data_or_length)
    try:
        try:
            status, _ = (file.WriteFile if writing else file.ReadFile)(handle, buffer, overlapped)
        except py.error as exc:
            if exc.winerror != 997:
                raise
            status = 997
        if status == 997 and event.WaitForSingleObject(overlapped.hEvent, timeout) != 0:
            # This thread owns the handle's only outstanding operation.
            file.CancelIo(handle)
            event.WaitForSingleObject(overlapped.hEvent, event.INFINITE)
            raise OperationError("pipe_timeout", "Local worker request timed out.", 504)
        count = file.GetOverlappedResult(handle, overlapped, True)
        if count == 0:
            raise OperationError("pipe_closed", "Local peer disconnected.", 503)
        return count if writing else bytes(buffer[:count])
    finally:
        overlapped.hEvent.Close()


def _read_exact(handle, size):
    result = bytearray()
    deadline = time.monotonic() + 15
    while len(result) < size:
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise OperationError("pipe_timeout", "Local message deadline exceeded.", 504)
        result.extend(_transfer(handle, size - len(result), timeout=remaining))
    return bytes(result)


def receive_message(handle, maximum=MAX_MESSAGE):
    size = struct.unpack("!I", _read_exact(handle, 4))[0]
    if size < 2 or size > maximum:
        raise OperationError("pipe_message_limit", "Local message size is outside limits.", 413)
    try:
        value = json.loads(_read_exact(handle, size))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise OperationError("pipe_message_invalid", "Invalid local JSON message.", 400)
    if not isinstance(value, dict):
        raise OperationError("pipe_message_invalid", "Local message must be an object.", 400)
    return value


def send_message(handle, value, maximum=MAX_MESSAGE):
    payload = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()
    if len(payload) > maximum:
        raise OperationError("pipe_message_limit", "Local response exceeds the message limit.", 413)
    payload = struct.pack("!I", len(payload)) + payload
    offset = 0
    while offset < len(payload):
        offset += _transfer(handle, payload[offset:], writing=True)


class PipeServer:
    def __init__(self, name, handler, allowed_sids=(), maximum=MAX_MESSAGE):
        if not name.startswith("\\\\.\\pipe\\") or len(name) > 240:
            raise ValueError("A local named-pipe path is required")
        self.name, self.handler, self.maximum = name, handler, maximum
        self.attributes = pipe_security(allowed_sids)
        self.slots = threading.BoundedSemaphore(16)
        self.threads = set()
        self.lock = threading.Lock()

    def serve(self, stop_event):
        py, _, _, event, file, pipe, _ = windows_modules()
        first = True
        try:
            while not stop_event.is_set():
                if not self.slots.acquire(timeout=0.25):
                    continue
                handle = None
                overlapped = py.OVERLAPPED()
                overlapped.hEvent = event.CreateEvent(None, True, False, None)
                try:
                    flags = pipe.PIPE_ACCESS_DUPLEX | file.FILE_FLAG_OVERLAPPED
                    if first:
                        flags |= 0x00080000  # FILE_FLAG_FIRST_PIPE_INSTANCE: refuse pipe squatting.
                    handle = pipe.CreateNamedPipe(self.name, flags,
                        pipe.PIPE_TYPE_BYTE | pipe.PIPE_READMODE_BYTE | 0x8, 16, 65536, 65536,
                        15000, self.attributes)  # PIPE_REJECT_REMOTE_CLIENTS
                    first = False
                    status = pipe.ConnectNamedPipe(handle, overlapped)
                    # pywin32 returns ERROR_PIPE_CONNECTED; it does not raise it.
                    if status in (0, 535):
                        event.SetEvent(overlapped.hEvent)
                    while event.WaitForSingleObject(overlapped.hEvent, 250) != 0:
                        if stop_event.is_set():
                            file.CancelIo(handle)
                            event.WaitForSingleObject(overlapped.hEvent, event.INFINITE)
                            break
                    if stop_event.is_set():
                        handle.Close()
                        handle = None
                        self.slots.release()
                        break
                    thread = threading.Thread(target=self._client, args=(handle,), daemon=True)
                    with self.lock:
                        self.threads.add(thread)
                    thread.start()
                    handle = None
                except Exception:
                    if handle:
                        handle.Close()
                    self.slots.release()
                    raise
                finally:
                    overlapped.hEvent.Close()
        finally:
            with self.lock:
                threads = list(self.threads)
            for thread in threads:
                thread.join(timeout=16)

    def _client(self, handle):
        try:
            request = receive_message(handle, self.maximum)
            peer = client_identity(handle)
            try:
                response = {"result": self.handler(request, peer)}
            except OperationError as exc:
                response = {"error": {"code": exc.code, "message": exc.message, "status": exc.status}}
            except Exception:
                response = {"error": {"code": "worker_error", "message": "Local operation failed.", "status": 500}}
            try:
                send_message(handle, response, self.maximum)
            except OperationError as exc:
                if exc.code != "pipe_message_limit":
                    raise
                send_message(handle, {"error": {"code": exc.code, "message": exc.message,
                                                "status": exc.status}}, self.maximum)
        except Exception:
            # Invalid/unresponsive clients cannot keep an instance or leak exception details.
            pass
        finally:
            handle.Close()
            self.slots.release()
            with self.lock:
                self.threads.discard(threading.current_thread())


def pipe_call(name, request, expected_sid=None, maximum=MAX_MESSAGE, expected_session=None):
    py, _, con, _, file, pipe, _ = windows_modules()
    deadline = time.monotonic() + 5
    observed_busy = False
    while True:
        try:
            handle = file.CreateFile(name, con.GENERIC_READ | con.GENERIC_WRITE, 0, None,
                                     con.OPEN_EXISTING, file.FILE_FLAG_OVERLAPPED | 0x00100000 | 0x00010000, None)
            break
        except py.error as exc:
            # WaitNamedPipe does not reserve an instance. Another client may win
            # CreateFile; retry only this handshake, never a submitted RPC.
            remaining = int((deadline - time.monotonic()) * 1000)
            # Once an instance was busy, ERROR_FILE_NOT_FOUND can mean the last
            # accepted instance closed before the server created its successor.
            # Preserve the existing handshake deadline; never retry a sent RPC.
            if (remaining <= 0 or exc.winerror not in (2, 231)
                    or (exc.winerror == 2 and not observed_busy)):
                raise OperationError("worker_unavailable", "The local agent worker is unavailable.", 503) from None
            observed_busy = True
            try:
                pipe.WaitNamedPipe(name, remaining)
            except py.error as wait_error:
                if wait_error.winerror != 2:
                    raise OperationError("worker_unavailable", "The local agent worker is unavailable.", 503) from None
                pause = min(0.01, deadline - time.monotonic())
                if pause <= 0:
                    raise OperationError("worker_unavailable", "The local agent worker is unavailable.", 503) from None
                time.sleep(pause)
    # SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION prevents privileged server impersonation.
    try:
        validate_server(handle, expected_sid, expected_session)
        send_message(handle, request, maximum)
        response = receive_message(handle, maximum)
        if "error" in response:
            error = response["error"]
            raise OperationError(error["code"], error["message"], error.get("status", 500))
        return response["result"]
    finally:
        handle.Close()


class WorkerProxy:
    def __init__(self, pipe_name=DEFAULT_PIPE):
        self.pipe_name = pipe_name

    def rpc(self, method, params=None, peer_der=None):
        return pipe_call(self.pipe_name, {"method": method, "params": params or {},
                         "peer_der": base64.b64encode(peer_der).decode() if peer_der else None})


class IntegratedProxy:
    def __init__(self, runtime):
        self.runtime = runtime

    def rpc(self, method, params=None, peer_der=None):
        if method not in RPC_METHODS:
            raise OperationError("rpc_method", "Unknown gateway method.", 404)
        actor = self.runtime.security.authenticate(peer_der) if peer_der else None
        if actor is None and method not in {"health", "pairing.enroll"}:
            raise OperationError("certificate_required", "Client certificate required.", 401)
        return self.runtime.rpc(method, params or {}, actor)


class WorkerDispatcher:
    def __init__(self, runtime, tls_paths, gateway_sid=None):
        self.runtime, self.tls_paths, self.gateway_sid = runtime, tls_paths, gateway_sid
        self.proxy = IntegratedProxy(runtime)

    def __call__(self, request, peer):
        if not peer["admin"] and peer["sid"] != self.gateway_sid:
            raise OperationError("pipe_peer", "Local peer is not authorized.", 403)
        if set(request) - {"method", "params", "peer_der"}:
            raise OperationError("rpc_context", "Untrusted authentication context rejected.", 400)
        method = request.get("method")
        params = request.get("params", {})
        if not isinstance(params, dict):
            raise OperationError("rpc_params", "Parameters must be an object.", 400)
        if method == "transport.tls":
            return self.tls_paths
        if method == "pairing.begin":
            if not peer["admin"] or request.get("peer_der"):
                raise OperationError("local_admin_required", "Pairing approval requires a local administrator.", 403)
            ttl, role = params.get("ttl_seconds", 300), params.get("role", "owner")
            if not isinstance(ttl, int) or not 30 <= ttl <= 900 or role not in {"owner", "operator", "viewer"}:
                raise OperationError("pairing_parameters", "Invalid pairing lifetime or role.", 400)
            return self.runtime.security.begin_pairing(ttl_seconds=ttl, role=role)
        if method == "local.status":
            if not peer["admin"]:
                raise OperationError("local_admin_required", "Local administrative status requires elevation.", 403)
            return self.runtime.health()
        raw = request.get("peer_der")
        try:
            der = base64.b64decode(raw, validate=True) if isinstance(raw, str) else None
        except ValueError:
            raise OperationError("certificate_invalid", "Invalid certificate encoding.", 401)
        if der and len(der) > 16384:
            raise OperationError("certificate_invalid", "Certificate exceeds limits.", 401)
        return self.proxy.rpc(method, params, peer_der=der)
