"""Agent lifecycle, durable operation execution and transport-independent RPC.

The worker is the execution owner. Network code authenticates a certificate and
passes an enrolled actor; the runtime reloads authorization before admission and
again before execution. Only the private scheduler callback uses system identity.
"""
from __future__ import annotations

import base64
import copy
import json
import logging
import math
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .contracts import (API_VERSION, TERMINAL_STATES, VERSION, ExecutionContext, OperationError,
                        field, operation, public_artifact, secret_named)
from .network import NetworkWatch, tcp_reachable

log = logging.getLogger(__name__)
CONFIG_DOMAINS = ("monitor", "backup", "files", "notifications")
NETWORK_CHECK_SECONDS = 60.0
NETWORK_PROBE_TIMEOUT = 3.0


def _redact(value: Any, names: set[str] | None = None) -> Any:
    names = names or set()
    if isinstance(value, dict):
        return {key: ("***" if str(key) in names or secret_named(key)
                      else _redact(item, names)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, names) for item in value]
    return value


class AgentRuntime:
    def __init__(self, root: Path, data_dir: Path, read_only: bool = False):
        from .store import Store
        from .certificates import CertificateAuthority
        from .security import Security
        from .backend import WindowsBackend
        from .transfers import TransferManager
        from .notifications import NotificationManager

        self.root = Path(root).resolve()
        self.data_dir = Path(data_dir).resolve()
        # A direct installation stays monitoring-only, including signed builds
        # and after bootstrap publication has been retired.
        self.read_only = bool(read_only) or (self.data_dir / "direct-bootstrap.json").exists()
        self.store = Store(self.data_dir)
        self.ca = CertificateAuthority(self.data_dir)
        self.security = Security(self.store, self.ca)
        self.backend = WindowsBackend(self.root, self.data_dir, self.store)
        self.transfers = TransferManager(self.data_dir, lambda: self.backend.get_config("monitor")["value"],
                                         lambda path: self.backend.approve_file(path, write=True))
        self.notifications = NotificationManager(self.store, self.security)
        self._internal_actor = {"id": "agent", "name": "Agent scheduler", "role": "internal"}
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lifecycle = threading.Lock()
        self._running_lock = threading.Lock()
        self._admission_lock = threading.RLock()
        self._running: dict[str, threading.Event] = {}
        self._threads: list[threading.Thread] = []
        self._started = False
        self._worker_lock = None
        self._last_sample = 0.0
        self._sampling_error: str | None = None
        # Network reachability is owned here: the telemetry thread probes the
        # configured target and records transitions. The probe is injectable so
        # the watch can be exercised without real sockets.
        self.network = NetworkWatch()
        self.network_probe = tcp_reachable
        self.network_interval = NETWORK_CHECK_SECONDS
        self.network_timeout = NETWORK_PROBE_TIMEOUT
        self._network_last = 0.0
        self._definitions: dict[str, dict] = {}
        for descriptor in self.backend.catalog():
            identifier = descriptor["id"]
            if identifier in self._definitions:
                raise ValueError("duplicate operation: " + identifier)
            self._definitions[identifier] = copy.deepcopy(descriptor)
        upload = operation("files.upload", "Receive uploaded file", "files",
                           "Commit a verified staged upload into the configured upload directory.",
                           "files", fields=[field("upload_id", "Upload ID", required=True)])
        upload["hidden"] = True
        self._definitions[upload["id"]] = upload
        self._definitions["monitoring.network_health"] = operation(
            "monitoring.network_health", "Network reachability", "monitoring",
            "Current up/down state of the configured reachability target (ping_target), "
            "including the last transition and outage duration.", "view")
        self.backend.set_submitter(self._submit_scheduled)

    def start(self) -> None:
        with self._lifecycle:
            if self._started:
                return
            self._acquire_worker_lock()
            try:
                self.store.recover_jobs()
                self._stop.clear()
                self.backend.start(read_only=self.read_only)
                if not self.read_only:
                    self.notifications.start()
                self._threads = [threading.Thread(target=self._run_jobs, name="agent-jobs", daemon=True),
                                 threading.Thread(target=self._sample, name="agent-telemetry", daemon=True)]
                self._started = True
                for thread in self._threads:
                    thread.start()
                self.store.append_event("agent.started", "Windows agent started", data={"version": VERSION, "read_only": self.read_only})
            except Exception:
                self._stop.set()
                self.notifications.stop()
                self.backend.stop()
                self._started = False
                self._release_worker_lock()
                raise

    def stop(self) -> None:
        with self._lifecycle:
            if not self._started:
                return
            self._stop.set()
            self._wake.set()
            with self._running_lock:
                for cancel in self._running.values():
                    cancel.set()
            self.notifications.stop()
            self.backend.stop()
            for thread in self._threads:
                thread.join(timeout=20)
            still_running = any(thread.is_alive() for thread in self._threads)
            self.store.append_event("agent.stopped", "Windows agent stopping", data={"work_still_finishing": still_running})
            self._started = False
            # An external process may still be unwinding cancellation; do not close
            # its database out from under it or claim its side effects rolled back.
            if not still_running:
                self._release_worker_lock()
                self.store.close()

    def _acquire_worker_lock(self) -> None:
        from .certificates import reject_links
        if os.name != "nt":
            raise OperationError("platform_unavailable", "The worker requires Windows", 503)
        import msvcrt
        path = self.data_dir / "worker.lock"
        reject_links(path)
        stream = path.open("a+b")
        try:
            if path.stat().st_size == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            stream.close()
            raise OperationError("worker_already_running", "Another worker already owns this installation", 409) from exc
        self._worker_lock = stream

    def _release_worker_lock(self) -> None:
        stream, self._worker_lock = self._worker_lock, None
        if stream is not None:
            stream.close()

    def catalog(self) -> list[dict]:
        return copy.deepcopy(list(self._definitions.values()))

    def health(self) -> dict:
        identity = self.store.identity()
        return {"agent_id": identity["id"], "name": identity["name"], "version": VERSION,
                "api_version": API_VERSION, "timestamp": time.time(), "read_only": self.read_only,
                "running": self._started, "last_sample": self._last_sample,
                "telemetry_error": self._sampling_error, "network": self.network.status(),
                "config_domains": list(CONFIG_DOMAINS)}

    def _network_tick(self) -> None:
        """Probe the configured target and record a durable transition event."""
        if self.read_only:
            return
        now = time.time()
        if now - self._network_last < self.network_interval:
            return
        self._network_last = now
        try:
            config = self.backend.get_config("monitor")["value"]
        except Exception:
            return
        if not config.get("net_watch", True):
            return
        target = str(config.get("ping_target") or "1.1.1.1")
        try:
            reachable = bool(self.network_probe(target, self.network_timeout))
        except Exception:
            reachable = False
        state = self.network.evaluate(reachable, now, target=target)
        if not state.get("changed"):
            return
        if state["state"] == "down":
            self.store.append_event("network.down", "Network reachability lost: no response from " + target,
                                    "error", {"target": target, "down_since": state.get("down_since")})
        else:
            seconds = int(state.get("seconds_down") or 0)
            minutes = max(1, round(seconds / 60)) if seconds else 0
            detail = (f"after about {minutes} minute(s)" if seconds else "on the next check")
            self.store.append_event("network.up", "Network reachability restored " + detail,
                                    "warning", {"target": target, "seconds_down": seconds})


    def _sample(self) -> None:
        while not self._stop.is_set():
            try:
                snapshot = self.backend.snapshot()
                stamp = snapshot.get("ts")
                if not isinstance(stamp, (int, float)) or not math.isfinite(stamp):
                    raise OperationError("telemetry_unavailable", "No valid telemetry sample is available", 503)
                if stamp != self._last_sample:
                    self.store.append_metric(snapshot)
                    self._last_sample = stamp
                self._sampling_error = None
            except Exception:
                if self._sampling_error is None:
                    log.exception("Telemetry collection failed")
                    self.store.append_event("telemetry.error", "Telemetry collection failed; previous data is stale", "warning")
                self._sampling_error = "Telemetry collection failed"
            self._network_tick()
            self._stop.wait(2)

    def _actor(self, actor: dict | None, capability: str = "view") -> dict:
        if actor is self._internal_actor:
            return actor
        if not isinstance(actor, dict) or not isinstance(actor.get("id"), str):
            raise OperationError("authentication_required", "An enrolled device is required", 401)
        current = self.security.active_actor(actor["id"])
        self.security.authorize(current, capability)
        return current

    def _descriptor(self, identifier: str) -> dict:
        if identifier == "configuration.update":
            return {"id": identifier, "capability": "configure", "destructive": True, "fields": []}
        descriptor = self._definitions.get(identifier)
        if descriptor is None:
            raise OperationError("unknown_operation", "The agent does not support this operation", 404)
        return descriptor

    @staticmethod
    def _validate_args(descriptor: dict, args: dict) -> dict:
        if not isinstance(args, dict):
            raise OperationError("invalid_arguments", "Operation arguments must be an object")
        try:
            encoded = json.dumps(args, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise OperationError("invalid_arguments", "Arguments must contain valid JSON values") from exc
        if len(encoded.encode("utf-8")) > 65536:
            raise OperationError("arguments_too_large", "Operation arguments exceed 64 KiB", 413)
        fields = {item["name"]: item for item in descriptor.get("fields", [])}
        extra = set(args) - set(fields)
        if extra:
            raise OperationError("invalid_arguments", "Unknown argument: " + sorted(extra)[0])
        result = dict(args)
        for name, spec in fields.items():
            if name not in result and "default" in spec:
                result[name] = copy.deepcopy(spec["default"])
            value = result.get(name)
            if value is None or value == "":
                if spec.get("required"):
                    raise OperationError("invalid_arguments", spec.get("label", name) + " is required")
                continue
            kind = spec.get("type", "string")
            valid = True
            if kind in {"string", "secret", "path", "choice"}:
                valid = isinstance(value, str)
            elif kind == "boolean":
                valid = isinstance(value, bool)
            elif kind == "integer":
                valid = isinstance(value, int) and not isinstance(value, bool)
            elif kind == "number":
                valid = isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
            if not valid:
                raise OperationError("invalid_arguments", "Invalid value type for " + spec.get("label", name))
            if spec.get("choices") and value not in spec["choices"]:
                raise OperationError("invalid_arguments", "Invalid choice for " + spec.get("label", name))
            if isinstance(value, str) and "\x00" in value:
                raise OperationError("invalid_arguments", "NUL characters are not permitted")
        return result

    def _public_job(self, job: dict) -> dict:
        result = copy.deepcopy(job)
        descriptor = self._definitions.get(result.get("operation"), {})
        secret_fields = {item["name"] for item in descriptor.get("fields", []) if item.get("type") == "secret"}
        result.pop("config_snapshot", None)
        result.pop("args_hash", None)
        result["args"] = _redact(result.get("args", {}), secret_fields)
        result["result"] = _redact(result.get("result"))
        if isinstance(result.get("result"), dict):
            result["result"]["artifacts"] = [public_artifact(item) for item in result["result"].get("artifacts", [])]
        return result

    def submit(self, actor: dict, operation: str, args: dict, request_id: str, nonce: str | None = None) -> dict:
        descriptor = self._descriptor(operation)
        current = self._actor(actor, descriptor["capability"])
        if self.read_only and descriptor["capability"] != "view":
            raise OperationError("read_only", "This agent was explicitly started in read-only mode", 403)
        normalized = self._validate_args(descriptor, args)
        if not isinstance(request_id, str) or not 8 <= len(request_id) <= 128:
            raise OperationError("invalid_request_id", "A stable request ID between 8 and 128 characters is required")
        with self._admission_lock:
            existing = self.store.find_job(current["id"], request_id)
            if existing is not None:
                if existing["operation"] != operation or existing["args"] != normalized:
                    raise OperationError("request_id_conflict", "This request ID was already used with different parameters", 409)
                return self._public_job(existing)
            if descriptor.get("destructive") and current is not self._internal_actor:
                self.security.consume(current, operation, normalized, nonce)
            revisions = self.store.config_versions()
            job, created = self.store.create_job(current["id"], operation, normalized, request_id, config_revision=revisions)
            if created:
                secret_fields = {item["name"] for item in descriptor.get("fields", []) if item.get("type") == "secret"}
                self.store.append_audit(current, operation, "accepted", _redact(normalized, secret_fields), job_id=job["id"])
                self._wake.set()
        return self._public_job(job)

    def _submit_scheduled(self, operation: str, args: dict, request_id: str) -> dict:
        if self.read_only or self._stop.is_set():
            raise OperationError("agent_not_accepting", "Scheduled operations are not currently accepted", 503)
        return self.submit(self._internal_actor, operation, args, request_id)

    def _run_jobs(self) -> None:
        while not self._stop.is_set():
            job = self.store.claim_job()
            if job is None:
                self._wake.wait(0.5)
                self._wake.clear()
                continue
            cancel = threading.Event()
            if job.get("cancel_requested"):
                cancel.set()
            with self._running_lock:
                self._running[job["id"]] = cancel
            try:
                if cancel.is_set():
                    self.store.update_job(job["id"], state="cancelled", message="Cancelled before execution", finished=time.time())
                    continue
                descriptor = self._descriptor(job["operation"])
                actor = (self._internal_actor if job["device_id"] == "agent"
                         else self._actor({"id": job["device_id"]}, descriptor["capability"]))
                if self.read_only and descriptor["capability"] != "view":
                    raise OperationError("read_only", "Write operations are disabled", 403)
                context = ExecutionContext(
                    actor=actor, cancel=cancel,
                    progress=lambda percent, message: self._progress(job["id"], percent, message),
                    emit=lambda kind, message, severity="info", data=None: self.store.append_event(kind, message, severity, _redact(data), actor=actor),
                    artifact=lambda path, name=None, media_type="application/octet-stream": self.store.add_artifact(Path(path), name, media_type, device_id=actor["id"]),
                    config_snapshot=copy.deepcopy(job.get("config_snapshot")))
                if job["operation"] == "files.upload":
                    result = self.transfers.commit(actor["id"], job["args"]["upload_id"], context)
                elif job["operation"] == "monitoring.network_health":
                    result = {"status": "succeeded", "message": "Network reachability state retrieved",
                              "data": self.network.status()}
                else:
                    result = self.backend.execute(job["operation"], copy.deepcopy(job["args"]), context)
                if not isinstance(result, dict) or result.get("status") not in TERMINAL_STATES:
                    result = {"status": "succeeded", "message": "Operation completed", "data": result}
                state = result["status"]
                self.store.update_job(job["id"], state=state, progress=100 if state == "succeeded" else None,
                                      message=str(result.get("message", "Operation completed"))[:4000],
                                      result=result, finished=time.time())
                self.store.append_audit(actor, job["operation"], state, job_id=job["id"])
                self.store.append_event("job." + state, job["operation"] + ": " + str(result.get("message", state))[:500],
                                        "error" if state == "failed" else "warning" if state == "partial" else "info",
                                        {"job_id": job["id"], "operation": job["operation"]}, actor=actor)
            except OperationError as exc:
                state = "cancelled" if exc.code in {"cancelled", "upload_cancelled"} else "failed"
                self.store.update_job(job["id"], state=state, message=exc.message,
                                      result={"status": state, "message": exc.message, "code": exc.code}, finished=time.time())
                self.store.append_audit({"id": job["device_id"]}, job["operation"], state, {"code": exc.code}, job_id=job["id"])
            except Exception:
                correlation = uuid.uuid4().hex
                log.exception("Job execution failed (%s)", correlation)
                message = "Operation failed; consult agent diagnostics with reference " + correlation
                self.store.update_job(job["id"], state="failed", message=message,
                                      result={"status": "failed", "message": message, "correlation_id": correlation}, finished=time.time())
                self.store.append_audit({"id": job["device_id"]}, job["operation"], "failed", {"correlation_id": correlation}, job_id=job["id"])
            finally:
                with self._running_lock:
                    self._running.pop(job["id"], None)

    def _progress(self, identifier: str, percent: int | None, message: str) -> None:
        value = None if percent is None else max(0, min(100, int(percent)))
        self.store.update_job(identifier, progress=value, message=str(message)[:2000])
        job = self.store.job(identifier)
        if job and job.get("cancel_requested"):
            with self._running_lock:
                cancel = self._running.get(identifier)
                if cancel:
                    cancel.set()

    def _owned_job(self, actor: dict, identifier: str) -> dict:
        job = self.store.job(identifier)
        if job is None:
            raise OperationError("job_not_found", "The requested job does not exist", 404)
        if actor["role"] != "owner" and job["device_id"] not in {actor["id"], "agent"}:
            raise OperationError("forbidden", "This job belongs to another device", 403)
        return job

    def cancel(self, actor: dict, job_id: str) -> dict:
        current = self._actor(actor)
        job = self._owned_job(current, job_id)
        self.security.authorize(current, self._descriptor(job["operation"])["capability"])
        if job["device_id"] == "agent" and current["role"] == "viewer":
            raise OperationError("forbidden", "Viewers cannot cancel scheduled work", 403)
        result = self.store.request_cancel(job_id)
        with self._running_lock:
            cancel = self._running.get(job_id)
            if cancel:
                cancel.set()
        self._wake.set()
        self.store.append_audit(current, job["operation"], "cancellation_requested", job_id=job_id)
        return self._public_job(result)

    def _artifact(self, actor: dict, identifier: str) -> dict:
        self.security.authorize(actor, "files")
        artifact = self.store.artifact(identifier)
        if artifact is None:
            raise OperationError("artifact_not_found", "The artifact is unavailable or expired", 404)
        if actor["role"] != "owner" and artifact.get("device_id") not in {actor["id"], "agent"}:
            raise OperationError("forbidden", "This artifact belongs to another device", 403)
        path = Path(artifact["path"]).resolve()
        approved = (self.data_dir / "artifacts").resolve()
        if not path.is_relative_to(approved) or not path.is_file():
            raise OperationError("artifact_unavailable", "The artifact is no longer available", 404)
        return artifact

    def rpc(self, method: str, params: dict | None = None, actor: dict | None = None) -> Any:
        params = params or {}
        if not isinstance(params, dict):
            raise OperationError("invalid_arguments", "RPC parameters must be an object")
        if method == "health":
            health = self.health()
            if actor is None:
                return {key: health[key] for key in ("agent_id", "name", "version", "api_version", "timestamp")}
            self._actor(actor)
            return health
        if method == "pairing.enroll":
            return self.security.enroll(str(params.get("code", "")), str(params.get("name", "")), str(params.get("csr", "")))
        if method in {"direct.bootstrap", "direct.complete"}:
            from .direct import direct_bootstrap
            if set(params) != {"nonce"}:
                raise OperationError("invalid_arguments", "Direct requests require only a nonce.")
            return direct_bootstrap(self.security, self.data_dir, params["nonce"],
                                    actor=actor, complete=method == "direct.complete")
        # pairing.begin and transport.tls are intentionally not public RPCs. Only
        # authenticated local-administrator CLI/IPC code can invoke those methods.
        current = self._actor(actor)
        if method == "catalog":
            result = self.catalog()
            for item in result:
                try:
                    self.security.authorize(current, item["capability"])
                    item["allowed"] = not self.read_only or item["capability"] == "view"
                except OperationError:
                    item["allowed"] = False
            return {"operations": result}
        if method == "snapshot":
            snapshot = self.backend.latest_snapshot()
            return dict(snapshot, collection_error=self._sampling_error, read_only=self.read_only,
                        network=self.network.status())
        if method == "history":
            limit = self._limit(params.get("limit"), 1000, 5000)
            return {"items": self.store.metrics(limit=limit)}
        if method == "confirmations.prepare":
            operation = str(params.get("operation", ""))
            descriptor = self._descriptor(operation)
            self.security.authorize(current, descriptor["capability"])
            if self.read_only and descriptor["capability"] != "view":
                raise OperationError("read_only", "Write operations are disabled", 403)
            args = params.get("args", {})
            if operation != "configuration.update":
                args = self._validate_args(descriptor, args)
            return self.security.prepare(current, operation, args)
        if method == "jobs.submit":
            return {"job": self.submit(current, str(params.get("operation", "")), params.get("args", {}),
                                       params.get("request_id"), params.get("nonce"))}
        if method == "jobs.list":
            limit = self._limit(params.get("limit"), 100, 500)
            jobs = self.store.jobs(limit=limit)
            if current["role"] != "owner":
                jobs = [job for job in jobs if job["device_id"] in {current["id"], "agent"}]
            return {"items": [self._public_job(job) for job in jobs]}
        if method == "jobs.get":
            return {"job": self._public_job(self._owned_job(current, str(params.get("id", ""))))}
        if method == "jobs.cancel":
            return {"job": self.cancel(current, str(params.get("id", "")))}
        if method == "events.list":
            after = self._cursor(params.get("after", 0))
            items = self.store.events(after=after, limit=self._limit(params.get("limit"), 100, 500))
            return {"items": items, "next_cursor": items[-1]["id"] if items else after}
        if method == "events.ack":
            self.store.acknowledge(self._cursor(params.get("id")), current["id"])
            return {"ok": True}
        if method == "audit.list":
            self.security.authorize(current, "manage")
            items = self.store.audits(after=self._cursor(params.get("after", 0)), limit=self._limit(params.get("limit"), 100, 500))
            return {"items": items}
        if method == "devices.list":
            self.security.authorize(current, "manage")
            return {"items": self.security.devices()}
        if method == "devices.renew":
            csr = params.get("csr")
            if not isinstance(csr, str):
                raise OperationError("invalid_csr", "A certificate signing request is required")
            return self.security.renew(current, csr)
        if method == "devices.revoke":
            self.security.authorize(current, "manage")
            self.security.revoke(str(params.get("id", "")), current)
            return {"ok": True}
        if method == "notifications.register":
            return self.notifications.register(current, params.get("provider"), params.get("token"), params.get("min_severity", "warning"))
        if method == "notifications.unregister":
            return self.notifications.unregister(current, params.get("provider"))
        if method == "notifications.status":
            return self.notifications.status(current)
        if method == "notifications.test":
            if self.read_only:
                raise OperationError("read_only", "Push delivery is disabled in read-only mode", 403)
            return self.notifications.test(current)
        if method.startswith("uploads."):
            self.security.authorize(current, "files")
            if self.read_only:
                raise OperationError("read_only", "File uploads are disabled in read-only mode", 403)
            if method == "uploads.begin":
                return {"upload": self.transfers.begin(current["id"], params.get("name"), params.get("size"), params.get("sha256"))}
            if method == "uploads.status":
                return {"upload": self.transfers.status(current["id"], str(params.get("id", "")))}
            if method == "uploads.write":
                try:
                    encoded = params.get("data", "")
                    if not isinstance(encoded, str) or len(encoded) > 349528:
                        raise ValueError("chunk size")
                    block = base64.b64decode(encoded, validate=True)
                except (ValueError, TypeError) as exc:
                    raise OperationError("invalid_chunk", "A bounded base64 file chunk is required", 413) from exc
                return {"upload": self.transfers.write(current["id"], str(params.get("id", "")), params.get("offset"), block)}
            if method == "uploads.complete":
                identifier = str(params.get("id", ""))
                self.transfers.status(current["id"], identifier)
                return {"job": self.submit(current, "files.upload", {"upload_id": identifier}, params.get("request_id"))}
        if method == "config.get":
            domain = self._domain(params.get("domain"))
            self.security.authorize(current, "configure")
            return self.notifications.get_config() if domain == "notifications" else self.backend.get_config(domain)
        if method == "config.set":
            self.security.authorize(current, "configure")
            if self.read_only:
                raise OperationError("read_only", "Write operations are disabled", 403)
            domain = self._domain(params.get("domain"))
            revision, value = params.get("revision"), params.get("value")
            if not isinstance(revision, int) or isinstance(revision, bool) or not isinstance(value, dict):
                raise OperationError("invalid_configuration", "A revision and configuration object are required")
            args = {"domain": domain, "revision": revision, "value": value}
            self.security.consume(current, "configuration.update", args, params.get("nonce"))
            context = ExecutionContext(current, threading.Event(), lambda _p, _m: None,
                                       lambda kind, message, severity="info", data=None: self.store.append_event(kind, message, severity, _redact(data), actor=current),
                                       lambda path, name=None, media_type="application/octet-stream": self.store.add_artifact(Path(path), name, media_type, device_id=current["id"]))
            result = (self.notifications.set_config(value, revision) if domain == "notifications"
                      else self.backend.set_config(domain, value, revision, context))
            self.store.append_audit(current, "configuration.update", "succeeded", {"domain": domain, "revision": result["revision"]})
            return result
        if method == "artifacts.get":
            return self._artifact(current, str(params.get("id", "")))
        if method == "artifacts.read":
            artifact = self._artifact(current, str(params.get("id", "")))
            offset = self._cursor(params.get("offset", 0))
            length = self._limit(params.get("length"), 262144, 262144)
            with open(artifact["path"], "rb") as stream:
                stream.seek(offset)
                block = stream.read(length)
            return {"data": base64.b64encode(block).decode("ascii"), "eof": offset + len(block) >= artifact["size"], "size": artifact["size"]}
        raise OperationError("unknown_method", "The agent does not support this API method", 404)

    @staticmethod
    def _limit(value: Any, default: int, maximum: int) -> int:
        if value is None:
            return default
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise OperationError("invalid_limit", "A positive integer limit is required") from exc
        if isinstance(value, bool) or not 1 <= result <= maximum:
            raise OperationError("invalid_limit", "Limit must be between 1 and " + str(maximum))
        return result

    @staticmethod
    def _cursor(value: Any) -> int:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise OperationError("invalid_cursor", "A nonnegative integer cursor is required") from exc
        if isinstance(value, bool) or result < 0:
            raise OperationError("invalid_cursor", "A nonnegative integer cursor is required")
        return result

    @staticmethod
    def _domain(value: Any) -> str:
        if value not in CONFIG_DOMAINS:
            raise OperationError("unknown_configuration", "Unknown configuration domain", 404)
        return value
