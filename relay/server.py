"""Bounded, single-process outbound rendezvous; inner TLS remains opaque."""
from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import json
import re
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from starlette.websockets import WebSocketDisconnect

from .protocol import (MAX_ENVELOPE_BYTES, ProtocolError, canonical_id, make_invitation,
                       normalize_origin, token_hash)
from .store import Limits, RelayError, Store
from .websocket import EXTENSION, close_connection

MAX_MESSAGE = 65536
MAX_BODY = 16384
ATTACH_TIMEOUT = 10
_LOOKUP = re.compile(r"[0-9a-f]{64}\Z")
_CIPHERTEXT = re.compile(r"[A-Za-z0-9_-]+\Z")


def bearer(connection) -> str:
    values = connection.headers.getlist("authorization")
    if len(values) != 1 or not values[0].startswith("Bearer "):
        raise RelayError("invalid_credential", 401)
    try:
        return token_hash(values[0][7:])
    except ProtocolError:
        raise RelayError("invalid_credential", 401) from None


def identifier(value: str) -> str:
    try:
        return canonical_id(value)
    except ProtocolError:
        raise RelayError("invalid_identifier", 422) from None


def lookup(value: str) -> str:
    if not _LOOKUP.fullmatch(value):
        raise RelayError("pairing_not_found", 404)
    return value


async def body(request: Request, required: set[str], optional: set[str] = frozenset()) -> dict:
    async def collect():
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > MAX_BODY:
                raise RelayError("body_too_large", 413)
            data.extend(chunk)
        return data

    try:
        raw = await asyncio.wait_for(collect(), 10)
        value = json.loads(raw)
    except asyncio.TimeoutError:
        raise RelayError("body_timeout", 408) from None
    except (ValueError, UnicodeError):
        raise RelayError("invalid_request", 422) from None
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise RelayError("invalid_request", 422)
    return value


async def deny(ws: WebSocket, error: RelayError):
    if "websocket.http.response" in ws.scope.get("extensions", {}):
        await ws.send_denial_response(JSONResponse({"error": error.code}, status_code=error.status))
    else:
        await ws.close(code=1008)


async def close_socket(ws: WebSocket | None, code: int = 1000):
    if ws is not None:
        await close_connection(ws, code)


class TransportPolicy:
    """Reject insecure/mismatched origins before consuming secrets or bodies."""

    def __init__(self, app, *, origin: str, allow_loopback_http: bool):
        self.app = app
        self.origin = origin
        self.development = allow_loopback_http and origin.startswith("http://")
        self.active_http = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        headers = scope.get("headers", [])
        hosts = [v.decode("latin1") for k, v in headers if k.lower() == b"host"]
        scheme = {"ws": "http", "wss": "https"}.get(scope["scheme"], scope["scheme"])
        allowed = False
        try:
            allowed = (len(hosts) == 1 and normalize_origin(
                f"{scheme}://{hosts[0]}", allow_loopback=self.development) == self.origin)
            if scheme == "http":
                peer = scope.get("client")
                allowed = allowed and self.development and bool(peer) and ipaddress.ip_address(peer[0]).is_loopback
        except (ProtocolError, ValueError):
            allowed = False
        error = None
        if not allowed:
            error = RelayError("https_origin_required", 400)
        elif scope.get("query_string"):
            error = RelayError("query_parameters_not_supported", 400)
        elif scope["type"] == "websocket" and EXTENSION not in scope.get("extensions", {}):
            error = RelayError("supported_relay_transport_required", 503)
        elif scope["type"] == "http":
            sizes = [v for k, v in headers if k.lower() == b"content-length"]
            try:
                if len(sizes) > 1 or (sizes and (not sizes[0].isdigit() or int(sizes[0]) > MAX_BODY)):
                    error = RelayError("body_too_large", 413)
            except ValueError:
                error = RelayError("body_too_large", 413)
            if self.active_http >= 128:
                error = RelayError("request_quota", 429)
        if error is not None:
            if scope["type"] == "http":
                await JSONResponse({"error": error.code}, status_code=error.status)(scope, receive, send)
            else:
                await deny(WebSocket(scope, receive, send), error)
            return
        if scope["type"] == "http":
            self.active_http += 1
            try:
                await self.app(scope, receive, send)
            finally:
                self.active_http -= 1
        else:
            await self.app(scope, receive, send)


@dataclass(eq=False)
class Control:
    socket: WebSocket
    queue: asyncio.Queue
    tasks: set[asyncio.Task] = field(default_factory=set)
    closing: asyncio.Task | None = None


@dataclass(eq=False)
class Stream:
    stream_id: str
    route_id: str
    grant_id: str
    client: WebSocket
    control: Control
    agent: WebSocket | None = None
    attached: asyncio.Event = field(default_factory=asyncio.Event)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    tasks: set[asyncio.Task] = field(default_factory=set)
    closing: asyncio.Task | None = None


class Runtime:
    def __init__(self, store: Store, limits: Limits):
        self.store = store
        self.limits = limits
        self.controls: dict[str, Control] = {}
        self.streams: dict[str, Stream] = {}
        self.stopping = False

    def add_control(self, route_id: str, ws: WebSocket) -> Control:
        if self.stopping:
            raise RelayError("relay_stopping", 503)
        if route_id in self.controls:
            raise RelayError("control_already_connected", 409)
        result = Control(ws, asyncio.Queue(maxsize=self.limits.pending_control))
        self.controls[route_id] = result
        return result

    def add_stream(self, route_id: str, credential_hash: str, ws: WebSocket) -> Stream:
        if self.stopping:
            raise RelayError("relay_stopping", 503)
        control = self.controls.get(route_id)
        if control is None or control.closing is not None:
            raise RelayError("agent_offline", 503)
        if (len(self.streams) >= self.limits.streams or
                sum(s.route_id == route_id for s in self.streams.values()) >= self.limits.streams_per_route):
            raise RelayError("stream_quota", 429)
        if control.queue.full():
            raise RelayError("control_queue_full", 429)
        # No await between admission/activation and registration: a revoke or
        # control disconnect cannot interleave with granting this stream.
        grant_id = self.store.activate_grant(route_id, credential_hash)
        stream = Stream(str(uuid4()), route_id, grant_id, ws, control)
        self.streams[stream.stream_id] = stream
        control.queue.put_nowait(stream.stream_id)
        return stream

    def attach(self, route_id: str, stream_id: str, ws: WebSocket) -> Stream:
        stream = self.streams.get(stream_id)
        if stream is None or stream.route_id != route_id or stream.done.is_set():
            raise RelayError("stream_not_found", 404)
        if stream.agent is not None:
            raise RelayError("stream_already_attached", 409)
        if self.controls.get(route_id) is not stream.control:
            raise RelayError("stream_not_found", 404)
        stream.agent = ws
        return stream

    async def close_stream(self, stream: Stream, code: int = 1000):
        if stream.closing is None:
            stream.done.set()
            stream.closing = asyncio.create_task(self._close_stream(stream, code))
        await asyncio.shield(stream.closing)

    async def _close_stream(self, stream: Stream, code: int):
        tasks = list(stream.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*(close_socket(ws, code) for ws in (stream.client, stream.agent)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        # Do not free quota when a close frame is merely queued: both native
        # transports must have delivered connection_lost first.
        self.streams.pop(stream.stream_id, None)

    async def drop_control(self, route_id: str, control: Control, code: int = 1001):
        if self.controls.get(route_id) is not control:
            return
        if control.closing is None:
            control.closing = asyncio.create_task(self._close_control(route_id, control, code))
        await asyncio.shield(control.closing)

    async def _close_control(self, route_id: str, control: Control, code: int):
        tasks = list(control.tasks)
        for task in tasks:
            task.cancel()
        streams = [stream for stream in self.streams.values() if stream.control is control]
        await asyncio.gather(close_socket(control.socket, code),
                             *(self.close_stream(stream, code) for stream in streams))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.controls.get(route_id) is control:
            self.controls.pop(route_id)

    async def revoke_grant(self, route_id: str, grant_id: str):
        await asyncio.gather(*(self.close_stream(stream, 1008) for stream in list(self.streams.values())
                               if stream.route_id == route_id and stream.grant_id == grant_id))

    async def shutdown(self):
        self.stopping = True
        await asyncio.gather(*(self.drop_control(route, control) for route, control in list(self.controls.items())))
        await asyncio.gather(*(self.close_stream(stream, 1001) for stream in list(self.streams.values())))

    async def serve_control(self, route_id: str, control: Control):
        async def outgoing():
            while True:
                stream_id = await control.queue.get()
                try:
                    stream = self.streams.get(stream_id)
                    if stream is not None and stream.control is control and not stream.done.is_set():
                        await asyncio.wait_for(control.socket.send_json({"type": "open", "stream_id": stream_id}), 5)
                finally:
                    control.queue.task_done()

        async def incoming():
            # Protocol-level ping/pong is handled by the WebSocket server. The
            # agent has no application-level command authority on this channel.
            message = await control.socket.receive()
            if message["type"] != "websocket.disconnect":
                raise RelayError("control_commands_not_supported", 400)

        try:
            await control.socket.accept()
            control.tasks = {asyncio.create_task(outgoing()), asyncio.create_task(incoming())}
            finished, _ = await asyncio.wait(control.tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in finished:
                if not task.cancelled():
                    task.result()
        except (WebSocketDisconnect, RelayError, OSError, RuntimeError, asyncio.TimeoutError):
            pass
        finally:
            await self.drop_control(route_id, control)

    async def serve_stream(self, stream: Stream):
        async def pump(source: WebSocket, *, from_client: bool):
            while not stream.done.is_set():
                message = await source.receive()
                if message["type"] == "websocket.disconnect":
                    return
                data = message.get("bytes")
                if not isinstance(data, bytes):
                    raise RelayError("binary_frames_required", 400)
                if len(data) > MAX_MESSAGE:
                    raise RelayError("message_too_large", 413)
                if from_client:
                    await stream.attached.wait()
                    target = stream.agent
                else:
                    target = stream.client
                if target is None or stream.done.is_set():
                    return
                # Exactly one awaited write per read provides backpressure;
                # only one message is held outside the bounded WS queue.
                await target.send_bytes(data)

        code = 1000
        try:
            await stream.client.accept()
            forward = asyncio.create_task(pump(stream.client, from_client=True))
            attached = asyncio.create_task(stream.attached.wait())
            stopped = asyncio.create_task(stream.done.wait())
            stream.tasks.update((forward, attached, stopped))
            finished, _ = await asyncio.wait((forward, attached, stopped), timeout=ATTACH_TIMEOUT,
                                              return_when=asyncio.FIRST_COMPLETED)
            if not finished:
                code = 1013
                return
            if forward in finished:
                if not forward.cancelled():
                    forward.result()
                return
            if stopped in finished or stream.done.is_set() or not stream.attached.is_set():
                return
            reverse = asyncio.create_task(pump(stream.agent, from_client=False))
            stream.tasks.add(reverse)
            finished, _ = await asyncio.wait((forward, reverse, stopped), return_when=asyncio.FIRST_COMPLETED)
            for task in finished:
                if not task.cancelled():
                    task.result()
        except RelayError as exc:
            code = 1009 if exc.status == 413 else 1008
        except (WebSocketDisconnect, OSError, RuntimeError):
            code = 1011
        finally:
            await self.close_stream(stream, code)


def create_app(database: str | Path, *, public_origin: str, admin_key: str,
               allow_loopback_http: bool = False, limits: Limits | None = None) -> FastAPI:
    """Create a broker; ownership of the exclusive DB lock follows ASGI lifespan."""
    origin = normalize_origin(public_origin, allow_loopback=allow_loopback_http)
    admin_hash = token_hash(admin_key)
    limits = limits or Limits()

    @asynccontextmanager
    async def lifespan(app):
        store = Store(database, limits=limits)
        runtime = Runtime(store, limits)
        app.state.relay = runtime

        async def cleanup():
            while True:
                await asyncio.sleep(30)
                store.cleanup()

        cleaner = asyncio.create_task(cleanup())
        try:
            yield
        finally:
            cleaner.cancel()
            with suppress(asyncio.CancelledError):
                await cleaner
            await runtime.shutdown()
            store.close()

    app = FastAPI(title="RDPMonitor relay", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.add_middleware(TransportPolicy, origin=origin, allow_loopback_http=allow_loopback_http)

    def runtime() -> Runtime:
        return app.state.relay

    def admin(connection):
        if not hmac.compare_digest(bearer(connection), admin_hash):
            raise RelayError("invalid_admin_credential", 401)

    def agent(connection, route_id: str) -> str:
        identifier(route_id)
        credential_hash = bearer(connection)
        runtime().store.authenticate_agent(route_id, credential_hash)
        return credential_hash

    @app.exception_handler(RelayError)
    async def relay_error(request, exc):
        return JSONResponse({"error": exc.code}, status_code=exc.status)

    @app.exception_handler(ProtocolError)
    async def protocol_error(request, exc):
        return JSONResponse({"error": "invalid_request"}, status_code=422)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # FastAPI validation can include submitted tokens; never serialize it.
        return JSONResponse({"error": "invalid_request"}, status_code=422)

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return JSONResponse({"error": "resource_unavailable"}, status_code=exc.status_code)

    @app.middleware("http")
    async def confidential_responses(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/health")
    async def health():
        return {"status": "ok", "protocol": 1}

    @app.post("/api/v1/installations")
    async def installations(request: Request):
        admin(request)
        value = await body(request, set(), {"ttl_seconds"})
        ttl = value.get("ttl_seconds", 900)
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise RelayError("invalid_invitation_lifetime", 422)
        token, expires = runtime().store.create_invitation(ttl)
        return {"invitation": make_invitation("install", origin, token, allow_loopback=allow_loopback_http),
                "expires": expires}

    @app.post("/api/v1/agents/register")
    async def register(request: Request):
        value = await body(request, {"invitation_token", "agent_id", "name"})
        name = value["name"]
        if not isinstance(name, str) or not 1 <= len(name) <= 128 or any(ord(c) < 32 for c in name):
            raise RelayError("invalid_agent_name", 422)
        return runtime().store.register(value["invitation_token"], value["agent_id"], name)

    @app.get("/api/v1/agents")
    async def agents(request: Request):
        admin(request)
        agents = runtime().store.agents()
        for value in agents:
            control = runtime().controls.get(value["route_id"])
            value["online"] = control is not None and control.closing is None
            value["revoked"] = bool(value["revoked"])
        return {"agents": agents}

    @app.delete("/api/v1/agents/{route_id}")
    async def revoke_agent(route_id: str, request: Request):
        admin(request)
        identifier(route_id)
        runtime().store.revoke_agent(route_id)
        control = runtime().controls.get(route_id)
        if control is not None:
            await runtime().drop_control(route_id, control, 1008)
        return {"revoked": True}

    @app.post("/api/v1/agents/{route_id}/grants")
    async def create_grant(route_id: str, request: Request):
        credential_hash = agent(request, route_id)
        await body(request, set())
        return runtime().store.create_grant(route_id, credential_hash)

    @app.get("/api/v1/agents/{route_id}/grants")
    async def grants(route_id: str, request: Request):
        admin(request)
        identifier(route_id)
        values = runtime().store.grants(route_id)
        for value in values:
            value["revoked"] = bool(value["revoked"])
        return {"grants": values}

    @app.delete("/api/v1/agents/{route_id}/grants/{grant_id}")
    async def revoke_grant(route_id: str, grant_id: str, request: Request):
        admin(request)
        identifier(route_id)
        identifier(grant_id)
        runtime().store.revoke_grant(route_id, grant_id)
        await runtime().revoke_grant(route_id, grant_id)
        return {"revoked": True}

    @app.post("/api/v1/agents/{route_id}/pairings")
    async def publish_pairing(route_id: str, request: Request):
        credential_hash = agent(request, route_id)
        value = await body(request, {"lookup_id", "ciphertext", "expires"})
        lookup_id = value["lookup_id"]
        ciphertext = value["ciphertext"]
        if not isinstance(lookup_id, str) or not _LOOKUP.fullmatch(lookup_id):
            raise RelayError("invalid_lookup_identifier", 422)
        if (not isinstance(ciphertext, str) or not 38 <= len(ciphertext) <= (MAX_ENVELOPE_BYTES * 4 + 2) // 3
                or not _CIPHERTEXT.fullmatch(ciphertext)):
            raise RelayError("invalid_ciphertext", 422)
        try:
            raw = base64.b64decode(ciphertext + "=" * (-len(ciphertext) % 4), altchars=b"-_", validate=True)
        except ValueError:
            raise RelayError("invalid_ciphertext", 422) from None
        if (not 28 <= len(raw) <= MAX_ENVELOPE_BYTES or
                base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != ciphertext):
            raise RelayError("invalid_ciphertext", 422)
        if type(value["expires"]) is not int:
            raise RelayError("invalid_pairing_expiry", 422)
        runtime().store.publish_pairing(route_id, credential_hash, lookup_id, ciphertext, value["expires"])
        return {"published": True}

    @app.get("/api/v1/pairings/{lookup_id}")
    async def pairing(lookup_id: str):
        return runtime().store.pairing(lookup(lookup_id))

    @app.websocket("/api/v1/agents/{route_id}/control")
    async def control(ws: WebSocket, route_id: str):
        try:
            agent(ws, route_id)
            state = runtime().add_control(route_id, ws)
        except RelayError as exc:
            await deny(ws, exc)
            return
        await runtime().serve_control(route_id, state)

    @app.websocket("/api/v1/agents/{route_id}/streams/{stream_id}")
    async def agent_stream(ws: WebSocket, route_id: str, stream_id: str):
        try:
            agent(ws, route_id)
            identifier(stream_id)
            stream = runtime().attach(route_id, stream_id, ws)
        except RelayError as exc:
            await deny(ws, exc)
            return
        try:
            await ws.accept()
            if stream.done.is_set():
                await close_socket(ws, 1008)
                return
            stream.attached.set()
            await stream.done.wait()
        except (WebSocketDisconnect, OSError, RuntimeError):
            pass
        finally:
            await runtime().close_stream(stream)

    @app.websocket("/api/v1/connect/{route_id}")
    async def connect(ws: WebSocket, route_id: str):
        try:
            identifier(route_id)
            state = runtime().add_stream(route_id, bearer(ws), ws)
        except RelayError as exc:
            await deny(ws, exc)
            return
        await runtime().serve_stream(state)

    return app
