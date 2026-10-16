"""Administrator-approved relay registration and constrained outbound TLS tunnels.

The connector reads only its gateway configuration. It forwards opaque bytes to
one numeric loopback listener; neither broker messages nor settings select a dial
target. Relay credentials grant transport, never local worker authority.
"""
from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import logging
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from relay.protocol import (MAX_PAIRING_TTL, VERSION, ProtocolError, canonical_id,
                            create_pairing_envelope, decode_secret, normalize_origin,
                            parse_invitation, validate_pairing)

from .certificates import (agent_identity, atomic_private_write, identity_lock,
                           protect_secret, protected_data_directory, reject_links,
                           unprotect_secret)
from .contracts import OperationError
from .ipc import (DEFAULT_PIPE, GATEWAY_ACCOUNT, WorkerProxy, account_sid,
                  current_identity, protect_path)
from .service import verify_protected_tree

MAX_MESSAGE = 65536
MAX_STREAMS = 16
MAX_HTTP_BODY = 16384
CONNECT_TIMEOUT = 8
CLOSE_TIMEOUT = 2
_LOG = logging.getLogger(__name__)
# websockets DEBUG diagnostics include handshake Authorization headers. Never
# attach this wire logger to the application's configurable logging hierarchy.
_WIRE_LOG = logging.Logger("rdpmonitor.relay.wire", level=logging.CRITICAL + 1)
_WIRE_LOG.disabled = True
_WIRE_LOG.propagate = False


@dataclass(frozen=True)
class _Settings:
    relay_origin: str
    agent_id: str
    route_id: str
    name: str
    agent_token: str = field(repr=False)


def relay_settings_path(data_dir: Path) -> Path:
    return Path(data_dir) / "gateway" / "relay.json"


def _require_local_admin() -> None:
    if not current_identity()["admin"]:
        raise OperationError("local_admin_required", "Relay setup and pairing approval require a local administrator.", 403)


def _valid_name(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(char) < 32 for char in value):
        raise OperationError("relay_identity", "The persistent agent name is invalid.", 500)
    return value


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _settings_present(path: Path) -> bool:
    try:
        reject_links(path)
        path.lstat()
        return True
    except FileNotFoundError:
        return False
    except (OSError, OperationError):
        raise OperationError("relay_configuration", "Relay configuration cannot be accessed safely.", 500) from None


def _load_settings(data_dir: Path, *, allow_loopback: bool) -> _Settings | None:
    path = relay_settings_path(data_dir)
    if not _settings_present(path):
        return None
    try:
        # Read-only verification: the gateway never repairs ACLs or opens the
        # worker identity, database or CA while loading its transport credential.
        verify_protected_tree(path.parent, recursive=False)
        verify_protected_tree(path, recursive=False, ancestors=False)
        with path.open("rb") as stream:
            content = stream.read(MAX_HTTP_BODY + 1)
        if len(content) > MAX_HTTP_BODY:
            raise ValueError
        value = json.loads(content, object_pairs_hook=_json_object)
        if (not isinstance(value, dict) or set(value) !=
                {"v", "relay_origin", "agent_id", "route_id", "name", "agent_token_dpapi"}
                or type(value["v"]) is not int or value["v"] != VERSION):
            raise ValueError
        origin = normalize_origin(value["relay_origin"], allow_loopback=allow_loopback)
        if origin != value["relay_origin"]:
            raise ValueError
        token = unprotect_secret(value["agent_token_dpapi"]).decode("ascii")
        decode_secret(token)
        return _Settings(origin, canonical_id(value["agent_id"]), canonical_id(value["route_id"]),
                         _valid_name(value["name"]), token)
    except Exception:
        raise OperationError("relay_configuration", "Relay configuration is invalid, unprotected, or unavailable on this machine.", 500) from None


def _request(origin: str, path: str, payload: dict, *, token: str | None = None) -> dict:
    """One bounded request, with normal TLS verification and no redirect/retry."""
    parsed = urlsplit(origin)
    connection = None
    try:
        if parsed.scheme == "https":
            connection = http.client.HTTPSConnection(parsed.hostname, parsed.port,
                                                     timeout=15, context=ssl.create_default_context())
        else:
            # Every caller obtained origin from the strict shared normalizer.
            connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=15)
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        if len(body) > MAX_HTTP_BODY:
            raise OperationError("relay_request_limit", "Relay request exceeds the size limit.", 413)
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        content = response.read(MAX_HTTP_BODY + 1)
        if not 200 <= response.status < 300:
            # Never include response text: an untrusted endpoint may echo secrets.
            raise OperationError("relay_request_failed", f"Relay rejected the request (HTTP {response.status}).", 502)
        if len(content) > MAX_HTTP_BODY:
            raise ValueError
        result = json.loads(content, object_pairs_hook=_json_object)
        if not isinstance(result, dict):
            raise ValueError
        return result
    except OperationError:
        raise
    except (OSError, http.client.HTTPException):
        raise OperationError("relay_unavailable", "Cannot reach the relay with a certificate-validated connection.", 503) from None
    except (ValueError, TypeError, RecursionError):
        raise OperationError("relay_response", "Relay returned an invalid response.", 502) from None
    finally:
        if connection is not None:
            connection.close()


def register_installation(invitation: str, data_dir: Path, *, allow_loopback: bool = False) -> dict:
    _require_local_admin()
    parsed = parse_invitation(invitation, kind="install", allow_loopback=allow_loopback)
    data_dir = Path(data_dir)
    path = relay_settings_path(data_dir)
    if _settings_present(path):
        raise OperationError("relay_already_registered", "This installation already has relay settings; registration will not replace them.", 409)
    identity = agent_identity(data_dir)
    identifier = canonical_id(identity["id"])
    name = _valid_name(identity["name"])
    # Resolve/harden and exercise machine secret storage before consuming the
    # one-use invitation. The installer creates the gateway service first.
    gateway_sid = account_sid(GATEWAY_ACCOUNT)
    protected_data_directory(data_dir)
    reject_links(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    protect_path(path.parent, gateway_sid, directory=True)
    verify_protected_tree(path.parent, recursive=False)
    unprotect_secret(protect_secret(b"relay credential storage preflight"))
    # The existing cross-process administration lock also serializes competing
    # installers. agent_identity must be obtained before taking this lock.
    with identity_lock(data_dir):
        if _settings_present(path):
            raise OperationError("relay_already_registered", "This installation already has relay settings; registration will not replace them.", 409)
        result = _request(parsed.origin, "/api/v1/agents/register",
                          {"invitation_token": parsed.token, "agent_id": identifier, "name": name})
        try:
            if set(result) != {"route_id", "agent_token"}:
                raise ValueError
            route_id = canonical_id(result["route_id"])
            decode_secret(result["agent_token"])
        except (ProtocolError, ValueError, TypeError, KeyError):
            raise OperationError("relay_response", "Relay returned an invalid registration response.", 502) from None
        value = {"v": VERSION, "relay_origin": parsed.origin, "agent_id": identifier,
                 "route_id": route_id, "name": name,
                 "agent_token_dpapi": protect_secret(result["agent_token"].encode("ascii"))}
        try:
            atomic_private_write(path, json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
            protect_path(path, gateway_sid)
            verify_protected_tree(path, recursive=False, ancestors=False)
        except (OSError, RuntimeError, OperationError):
            raise OperationError("relay_configuration", "Relay registration succeeded but protected settings could not be saved; revoke the unused route in relay settings before retrying.", 500) from None
    return {"route_id": route_id, "agent_id": identifier, "relay_origin": parsed.origin}


def publish_connection_code(data_dir: Path, *, role: str = "owner", ttl: int = 300,
                            pipe_name: str = DEFAULT_PIPE, allow_loopback: bool = False) -> dict:
    _require_local_admin()
    if (type(ttl) is not int or not 30 <= ttl <= MAX_PAIRING_TTL
            or not isinstance(role, str) or role not in {"owner", "operator", "viewer"}):
        raise OperationError("pairing_parameters", "Choose owner, operator, or viewer and a lifetime between 30 and 600 seconds.", 400)
    settings = _load_settings(Path(data_dir), allow_loopback=allow_loopback)
    if settings is None:
        raise OperationError("relay_not_registered", "Register this installation with a relay first.", 409)
    approval = WorkerProxy(pipe_name).rpc("pairing.begin", {"ttl_seconds": ttl, "role": role})
    try:
        if not isinstance(approval, dict) or set(approval) != {"code", "expires", "agent_id", "fingerprint"}:
            raise ValueError
        if canonical_id(approval["agent_id"]) != settings.agent_id:
            raise ValueError
        approved_expiry = datetime.fromisoformat(approval["expires"].replace("Z", "+00:00"))
        if approved_expiry.tzinfo is None:
            raise ValueError
        expiry = min(int(approved_expiry.timestamp()), int(time.time()) + ttl)
        # Validate actual worker fingerprint/code before allocating a broker grant.
        payload = {"v": VERSION, "agent_id": settings.agent_id, "route_id": settings.route_id,
                   "fingerprint": approval["fingerprint"], "pairing_code": approval["code"],
                   "route_token": settings.agent_token, "expires": expiry, "name": settings.name}
        validate_pairing(payload)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise OperationError("relay_local_approval", "The local worker returned an invalid or mismatched pairing approval.", 500) from None
    grant = _request(settings.relay_origin, f"/api/v1/agents/{settings.route_id}/grants", {}, token=settings.agent_token)
    try:
        if set(grant) != {"grant_id", "route_token"}:
            raise ValueError
        canonical_id(grant["grant_id"])
        decode_secret(grant["route_token"])
        payload["route_token"] = grant["route_token"]
        envelope = create_pairing_envelope(settings.relay_origin, payload, allow_loopback=allow_loopback)
        result = _request(settings.relay_origin, f"/api/v1/agents/{settings.route_id}/pairings",
                          {key: envelope[key] for key in ("lookup_id", "ciphertext", "expires")},
                          token=settings.agent_token)
        if result != {"published": True} or type(result["published"]) is not bool:
            raise ValueError
    except OperationError:
        # The frozen API deliberately exposes revocation only to relay admins.
        # An unused transport grant expires at the broker after at most 600s.
        raise
    except (ValueError, TypeError, KeyError):
        raise OperationError("relay_response", "Connection code publication failed; any unused transport grant expires automatically within 600 seconds.", 502) from None
    return {"code": envelope["code"], "expires": envelope["expires"],
            "agent_id": settings.agent_id, "route_id": settings.route_id}


def _loopback_target(host: str, port: int) -> tuple[str, int]:
    try:
        if not isinstance(host, str) or "%" in host or not ipaddress.ip_address(host).is_loopback:
            raise ValueError
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, TypeError):
        raise OperationError("relay_gateway_target", "Relay forwarding requires a numeric loopback gateway and a valid port.", 500) from None
    return host, port


def _websocket_url(settings: _Settings, path: str) -> str:
    return ("wss" + settings.relay_origin[5:] if settings.relay_origin.startswith("https:")
            else "ws" + settings.relay_origin[4:]) + path


def _connect_websocket(connect, settings: _Settings, path: str):
    return connect(_websocket_url(settings, path),
                   additional_headers={"Authorization": "Bearer " + settings.agent_token},
                   proxy=None, compression=None, max_size=MAX_MESSAGE, max_queue=4,
                   write_limit=MAX_MESSAGE, open_timeout=CONNECT_TIMEOUT,
                   close_timeout=CLOSE_TIMEOUT, ping_interval=20, ping_timeout=20,
                   logger=_WIRE_LOG)


async def _close_websocket(websocket) -> None:
    if websocket is not None:
        try:
            await asyncio.wait_for(websocket.close(), CLOSE_TIMEOUT + 1)
        except Exception:
            transport = getattr(websocket, "transport", None)
            if transport is not None:
                transport.abort()


class _RelayStream:
    def __init__(self, connect, settings: _Settings, stream_id: str, host: str, port: int):
        self.connect, self.settings, self.stream_id = connect, settings, stream_id
        self.host, self.port = host, port
        self.websocket = self.reader = self.writer = None
        self.children: set[asyncio.Task] = set()
        self.closed = False
        self.task: asyncio.Task | None = None

    def start(self) -> None:
        self.task = asyncio.create_task(self.run())

    def abort(self) -> None:
        if not self.closed:
            self.closed = True
            if self.writer is not None:
                self.writer.close()
            if self.task is not None:
                self.task.cancel()

    def child(self, coroutine) -> asyncio.Task:
        task = asyncio.create_task(coroutine)
        self.children.add(task)
        return task

    async def _attach(self) -> None:
        path = f"/api/v1/agents/{self.settings.route_id}/streams/{self.stream_id}"
        self.websocket = await _connect_websocket(self.connect, self.settings, path)
        if self.closed:
            await _close_websocket(self.websocket)

    async def _dial(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port, limit=MAX_MESSAGE)
        if self.closed:
            self.writer.close()
            await self.writer.wait_closed()

    async def _from_gateway(self) -> None:
        while not self.closed:
            data = await self.reader.read(MAX_MESSAGE)
            if not data:
                return
            await self.websocket.send(data)

    async def _to_gateway(self) -> None:
        async for data in self.websocket:
            if not isinstance(data, bytes) or len(data) > MAX_MESSAGE:
                await self.websocket.close(code=1008, reason="Binary stream required")
                return
            self.writer.write(data)
            await self.writer.drain()

    async def run(self) -> None:
        try:
            # Child tasks publish acquired resources before returning, so even a
            # late completion during cancellation remains owned by this stream.
            await self.child(self._attach())
            if self.closed:
                return
            await asyncio.wait_for(self.child(self._dial()), CONNECT_TIMEOUT)
            if self.closed:
                return
            pumps = (self.child(self._from_gateway()), self.child(self._to_gateway()))
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for task in pumps:
                if task.done():
                    task.result()
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOG.warning("Relay data stream closed before completion; requests are not replayed.")
        finally:
            self.closed = True
            for task in self.children:
                if not task.done():
                    task.cancel()
            if self.writer is not None:
                self.writer.close()
            await asyncio.gather(*self.children, return_exceptions=True)
            # A cancelled attach/dial may have completed while children settled.
            if self.writer is not None:
                self.writer.close()
                try:
                    await asyncio.wait_for(self.writer.wait_closed(), CLOSE_TIMEOUT)
                except Exception:
                    self.writer.transport.abort()
            await _close_websocket(self.websocket)


async def _control_session(connect, settings: _Settings, host: str, port: int) -> bool:
    streams: dict[str, _RelayStream] = {}
    websocket = None
    connected_at = None

    def finished(stream_id: str, task: asyncio.Task) -> None:
        stream = streams.get(stream_id)
        if stream is not None and stream.task is task:
            streams.pop(stream_id)
        # run() handles data errors; consume cancellation without leaked futures.
        if not task.cancelled():
            task.exception()

    try:
        websocket = await _connect_websocket(connect, settings, f"/api/v1/agents/{settings.route_id}/control")
        connected_at = time.monotonic()
        _LOG.info("Relay control connection established.")
        async for message in websocket:
            try:
                if not isinstance(message, str):
                    raise ValueError
                command = json.loads(message, object_pairs_hook=_json_object)
                if not isinstance(command, dict) or set(command) != {"type", "stream_id"} or command["type"] != "open":
                    raise ValueError
                stream_id = canonical_id(command["stream_id"])
                if stream_id in streams or len(streams) >= MAX_STREAMS:
                    raise ValueError
            except (ValueError, TypeError, KeyError, RecursionError):
                await websocket.close(code=1008, reason="Invalid control message or stream limit")
                break
            stream = _RelayStream(connect, settings, stream_id, host, port)
            streams[stream_id] = stream
            stream.start()
            stream.task.add_done_callback(lambda task, identifier=stream_id: finished(identifier, task))
    except asyncio.CancelledError:
        raise
    except Exception:
        # Exception text/reprs from networking libraries can carry headers.
        pass
    finally:
        active = list(streams.values())
        for stream in active:
            stream.abort()
        await asyncio.gather(*(stream.task for stream in active), return_exceptions=True)
        await _close_websocket(websocket)
    return connected_at is not None and time.monotonic() - connected_at >= 10


async def _watch_stop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        await asyncio.sleep(0.2)


async def _run_connector(connect, settings: _Settings, host: str, port: int, stop_event: threading.Event) -> None:
    stopped = asyncio.create_task(_watch_stop(stop_event))
    session = None
    delay = 1
    try:
        while not stop_event.is_set():
            session = asyncio.create_task(_control_session(connect, settings, host, port))
            done, _ = await asyncio.wait((session, stopped), return_when=asyncio.FIRST_COMPLETED)
            if stopped in done:
                break
            if session.result():
                delay = 1
            _LOG.warning("Relay control unavailable; retrying in %d seconds. Existing streams are closed, not replayed.", delay)
            await asyncio.wait((stopped,), timeout=delay)
            delay = min(delay * 2, 30)
    finally:
        if session is not None and not session.done():
            session.cancel()
        stopped.cancel()
        await asyncio.gather(*(task for task in (session, stopped) if task is not None), return_exceptions=True)


def run_connector(data_dir: Path, host: str, port: int, stop_event: threading.Event, *, allow_loopback: bool = False) -> None:
    settings = _load_settings(Path(data_dir), allow_loopback=allow_loopback)
    if settings is None:
        return
    host, port = _loopback_target(host, port)
    try:
        from websockets.asyncio.client import connect
    except ImportError:
        raise OperationError("relay_dependency", "The packaged WebSocket relay client is unavailable.", 500) from None
    asyncio.run(_run_connector(connect, settings, host, port, stop_event))
