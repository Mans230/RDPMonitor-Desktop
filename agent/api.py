"""Versioned HTTPS gateway. Authentication comes only from the TLS transport."""
from __future__ import annotations

import asyncio
import base64
import re
import time
import uuid
from collections import OrderedDict
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException
from uvicorn.protocols.http.h11_impl import H11Protocol

from .contracts import OperationError

MAX_BODY = 1024 * 1024
MAX_TRANSFER = 8 * 1024 * 1024 * 1024


class CertificateH11Protocol(H11Protocol):
    """Capture the negotiated certificate, never a forwarded identity header."""

    def connection_made(self, transport):
        super().connection_made(transport)
        if len(self.connections) > 64:
            transport.close()
            return
        application = self.app
        tls = transport.get_extra_info("ssl_object")
        peer = tls.getpeercert(binary_form=True) if tls else None

        async def authenticated_scope(scope, receive, send):
            scope["rdpmonitor.peer_der"] = peer
            scope["rdpmonitor.tls"] = tls is not None
            await application(scope, receive, send)

        self.app = authenticated_scope


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Enrollment(StrictModel):
    code: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    csr: str = Field(min_length=64, max_length=16384)


class Confirmation(StrictModel):
    operation: str = Field(min_length=1, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)


class Job(Confirmation):
    request_id: str = Field(min_length=1, max_length=128)
    nonce: str | None = Field(default=None, max_length=512)


class Configuration(StrictModel):
    revision: int = Field(ge=0)
    value: dict[str, Any]
    nonce: str = Field(min_length=1, max_length=512)


class Upload(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    size: int = Field(ge=0, le=MAX_TRANSFER)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")


class UploadComplete(StrictModel):
    request_id: str = Field(min_length=1, max_length=128)


class Renewal(StrictModel):
    csr: str = Field(min_length=64, max_length=16384)


class NotificationToken(StrictModel):
    provider: str = Field(pattern=r"^(fcm|apns)$")
    token: str = Field(min_length=1, max_length=8192)


class NotificationRegistration(NotificationToken):
    min_severity: str = Field(default="warning", max_length=16)


def error_response(code, message, status, correlation_id=None):
    return JSONResponse({"error": {"code": code, "message": message,
                         "correlation_id": correlation_id or uuid.uuid4().hex,
                         "retryable": status in (429, 502, 503, 504)}}, status_code=status)


class Admission:
    """Bounds requests before parsing bodies; counters cannot grow unbounded."""

    def __init__(self, app, concurrency=32, requests_per_minute=180):
        self.app = app
        self.concurrency = concurrency
        self.active = 0
        self.rate = requests_per_minute
        self.clients = OrderedDict()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        correlation = uuid.uuid4().hex
        scope["rdpmonitor.correlation_id"] = correlation
        status, code, message = 0, "", ""
        if not scope.get("rdpmonitor.tls"):
            status, code, message = 400, "tls_required", "HTTPS is required."
        headers = dict(scope.get("headers", []))
        length = headers.get(b"content-length", b"0")
        try:
            if int(length) < 0 or int(length) > MAX_BODY:
                status, code, message = 413, "body_too_large", "Request body exceeds 1 MiB."
        except ValueError:
            status, code, message = 400, "invalid_length", "Invalid request length."
        if self.active >= self.concurrency:
            status, code, message = 503, "busy", "Gateway request capacity reached."
        peer = scope.get("rdpmonitor.peer_der")
        key = peer if peer else (scope.get("client") or ("unknown",))[0]
        transfer = scope.get("method") == "PUT" and scope.get("path", "").startswith("/api/v1/uploads/")
        key = (key, "transfer" if transfer else "api")
        now = time.monotonic()
        start, count = self.clients.pop(key, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        self.clients[key] = (start, count + 1)
        if len(self.clients) > 4096:
            self.clients.popitem(last=False)
        if count >= (1800 if transfer else self.rate):
            status, code, message = 429, "rate_limited", "Request rate limit reached; retry later."
        if status:
            return await error_response(code, message, status, correlation)(scope, receive, send)
        received = 0
        body_complete = False
        body_deadline = time.monotonic() + 15

        async def bounded_receive():
            nonlocal received, body_complete
            if body_complete:
                return await receive()
            remaining = body_deadline - time.monotonic()
            if remaining <= 0:
                raise HTTPException(408, detail="request_timeout")
            try:
                event = await asyncio.wait_for(receive(), timeout=remaining)
            except asyncio.TimeoutError:
                raise HTTPException(408, detail="request_timeout") from None
            if event["type"] == "http.request" and not event.get("more_body", False):
                body_complete = True
            received += len(event.get("body", b""))
            if received > MAX_BODY:
                raise HTTPException(413, detail="body_too_large")
            return event

        self.active += 1
        try:
            await self.app(scope, bounded_receive, send)
        finally:
            self.active -= 1


def create_app(proxy) -> FastAPI:
    app = FastAPI(title="RDPMonitor Agent", version="1.0.0", docs_url=None,
                  redoc_url=None, openapi_url=None)
    app.add_middleware(Admission)

    @app.exception_handler(OperationError)
    async def operation_error(request, exc):
        return error_response(exc.code, exc.message, exc.status,
                              request.scope.get("rdpmonitor.correlation_id"))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic errors may contain submitted secrets; never serialize them.
        return error_response("invalid_request", "Request fields are invalid.", 422,
                              request.scope.get("rdpmonitor.correlation_id"))

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        messages = {"request_timeout": "Request body deadline exceeded.",
                    "body_too_large": "Request body exceeds 1 MiB."}
        code = exc.detail if isinstance(exc.detail, str) and exc.detail in messages else "http_error"
        return error_response(code, messages.get(code, "Resource or HTTP method unavailable."), exc.status_code,
                              request.scope.get("rdpmonitor.correlation_id"))

    @app.exception_handler(Exception)
    async def internal_error(request, exc):
        return error_response("internal_error", "The agent could not complete the request.", 500,
                              request.scope.get("rdpmonitor.correlation_id"))

    async def call(request, method, params=None, public=False):
        peer = request.scope.get("rdpmonitor.peer_der")
        if not peer and not public:
            raise OperationError("certificate_required", "An enrolled client certificate is required.", 401)
        try:
            return await asyncio.to_thread(proxy.rpc, method, params or {}, peer_der=peer)
        except OperationError:
            raise
        except Exception:
            raise OperationError("worker_error", "The local worker could not complete this request.", 503) from None

    prefix = "/api/v1"

    @app.get(prefix + "/health")
    async def health(request: Request):
        return await call(request, "health", public=True)

    @app.post(prefix + "/enroll")
    async def enroll(request: Request, body: Enrollment):
        return await call(request, "pairing.enroll", {"code": body.code, "name": body.name,
                                                    "csr": body.csr}, public=True)

    @app.get(prefix + "/catalog")
    async def catalog(request: Request):
        return await call(request, "catalog")

    @app.get(prefix + "/snapshot")
    async def snapshot(request: Request):
        return await call(request, "snapshot")

    @app.get(prefix + "/history")
    async def history(request: Request, limit: int = 1000):
        return await call(request, "history", {"limit": max(1, min(limit, 10000))})

    @app.post(prefix + "/confirmations")
    async def confirmations(request: Request, body: Confirmation):
        return await call(request, "confirmations.prepare", body.model_dump())

    @app.post(prefix + "/jobs", status_code=202)
    async def submit(request: Request, body: Job):
        return await call(request, "jobs.submit", body.model_dump())

    @app.get(prefix + "/jobs")
    async def jobs(request: Request, limit: int = 100):
        return await call(request, "jobs.list", {"limit": max(1, min(limit, 500))})

    @app.get(prefix + "/jobs/{job_id}")
    async def job(request: Request, job_id: str):
        return await call(request, "jobs.get", {"id": job_id})

    @app.post(prefix + "/jobs/{job_id}/cancel")
    async def cancel(request: Request, job_id: str):
        return await call(request, "jobs.cancel", {"id": job_id})

    @app.get(prefix + "/events")
    async def events(request: Request, after: int = 0, limit: int = 100):
        return await call(request, "events.list", {"after": max(0, after), "limit": max(1, min(limit, 500))})

    @app.post(prefix + "/events/{event_id}/ack")
    async def acknowledge(request: Request, event_id: int):
        return await call(request, "events.ack", {"id": event_id})

    @app.get(prefix + "/audit")
    async def audit(request: Request, after: int = 0, limit: int = 100):
        return await call(request, "audit.list", {"after": max(0, after), "limit": max(1, min(limit, 500))})

    @app.get(prefix + "/devices")
    async def devices(request: Request):
        return await call(request, "devices.list")

    @app.delete(prefix + "/devices/{device_id}")
    async def revoke(request: Request, device_id: str):
        return await call(request, "devices.revoke", {"id": device_id})

    @app.get(prefix + "/config/{domain}")
    async def configuration(request: Request, domain: str):
        return await call(request, "config.get", {"domain": domain})

    @app.put(prefix + "/config/{domain}")
    async def put_configuration(request: Request, domain: str, body: Configuration):
        return await call(request, "config.set", {"domain": domain, **body.model_dump()})

    @app.post(prefix + "/uploads", status_code=201)
    async def begin_upload(request: Request, body: Upload):
        return await call(request, "uploads.begin", body.model_dump(exclude_none=True))

    @app.get(prefix + "/uploads/{upload_id}")
    async def upload_status(request: Request, upload_id: str):
        return await call(request, "uploads.status", {"id": upload_id})

    @app.put(prefix + "/uploads/{upload_id}")
    async def write_upload(request: Request, upload_id: str, offset: int = 0):
        if offset < 0:
            raise OperationError("upload_offset", "Offset must be nonnegative.")
        if not request.scope.get("rdpmonitor.peer_der"):
            raise OperationError("certificate_required", "Client certificate required.", 401)
        body = await request.body()
        if not body or len(body) > 262144:
            raise OperationError("chunk_limit", "Upload chunks must contain 1 to 262144 bytes.", 413)
        return await call(request, "uploads.write", {"id": upload_id, "offset": offset,
                          "data": base64.b64encode(body).decode("ascii")})

    @app.post(prefix + "/uploads/{upload_id}/complete", status_code=202)
    async def complete_upload(request: Request, upload_id: str, body: UploadComplete):
        return await call(request, "uploads.complete", {"id": upload_id, "request_id": body.request_id})

    @app.post(prefix + "/devices/renew")
    async def renew_certificate(request: Request, body: Renewal):
        return await call(request, "devices.renew", {"csr": body.csr})

    @app.post(prefix + "/notifications/register")
    async def register_notifications(request: Request, body: NotificationRegistration):
        return await call(request, "notifications.register", body.model_dump())

    @app.delete(prefix + "/notifications/registration")
    async def unregister_notifications(request: Request, body: NotificationToken):
        return await call(request, "notifications.unregister", body.model_dump())

    @app.get(prefix + "/notifications/status")
    async def notification_status(request: Request):
        return await call(request, "notifications.status")

    @app.post(prefix + "/notifications/test")
    async def test_notifications(request: Request):
        return await call(request, "notifications.test")

    @app.get(prefix + "/artifacts/{artifact_id}")
    async def artifact(request: Request, artifact_id: str):
        metadata = await call(request, "artifacts.get", {"id": artifact_id})
        size = int(metadata["size"])
        if size < 0 or size > MAX_TRANSFER:
            raise OperationError("transfer_limit", "Artifact exceeds the 8 GiB transfer limit.", 413)
        start, end, partial = 0, size - 1, False
        requested_range = request.headers.get("range")
        if requested_range:
            match = re.fullmatch(r"bytes=(\d+)-(\d*)", requested_range)
            if not match:
                raise OperationError("invalid_range", "One explicit byte range is supported.", 416)
            start = int(match[1])
            end = min(int(match[2]) if match[2] else size - 1, size - 1)
            if start > end or start >= size:
                raise OperationError("invalid_range", "Requested range is outside the artifact.", 416)
            partial = True

        async def chunks():
            offset = start
            while offset <= end:
                # Worker rechecks certificate revocation and artifact policy on EVERY chunk.
                result = await call(request, "artifacts.read", {"id": artifact_id, "offset": offset,
                                    "length": min(262144, end - offset + 1)})
                chunk = base64.b64decode(result["data"], validate=True)
                if not chunk or len(chunk) > min(262144, end - offset + 1):
                    raise OperationError("artifact_changed", "Artifact transfer was interrupted.", 409)
                offset += len(chunk)
                yield chunk

        headers = {"Content-Length": str(max(0, end - start + 1)), "Accept-Ranges": "bytes",
                   "Content-Disposition": "attachment; filename*=UTF-8''" + quote(metadata.get("name", "artifact"), safe=""),
                   "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
        if metadata.get("sha256"):
            headers["ETag"] = '"' + metadata["sha256"] + '"'
        if partial:
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"
        return StreamingResponse(chunks(), status_code=206 if partial else 200,
                                 media_type=metadata.get("media_type", "application/octet-stream"), headers=headers)

    return app
