"""Transactional, thread/process-safe agent state with bounded durable retention.

JSON-bearing private columns (configuration, job arguments/results/snapshots) are
Windows-DPAPI encrypted, in addition to a verified private directory/DB ACL. Each
transaction owns its SQLite connection; no connection crosses a thread boundary.
Public methods return detached dictionaries/lists, never live mutable state.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import stat
import threading
import uuid
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

from .certificates import (agent_identity, protect_path, protect_secret,
                           protected_directory, reject_links, timestamp, unprotect_secret, utcnow)
from .contracts import OperationError, TERMINAL_STATES

MAX_JSON_BYTES = 4 * 1024 * 1024
_SECRET_KEYS = {"password", "passwd", "secret", "token", "credential", "private_key", "api_key", "authorization", "csr", "code", "nonce"}
_STATES = {"queued", "running", "cancelling", *TERMINAL_STATES}
_TRANSITIONS = {
    "queued": {"running", "cancelled", "failed", "interrupted"},
    "running": {"cancelling", *TERMINAL_STATES},
    "cancelling": set(TERMINAL_STATES),
}


def canonical_json(value, *, max_bytes: int = MAX_JSON_BYTES) -> str:
    """Strict, interoperable JSON; reject cycles, NaN, non-string keys and objects.

    Integral floats and negative zero normalize to integers, so semantically
    equivalent JSON number spellings do not bypass idempotency or confirmation.
    """
    def normalize(item, depth):
        if depth > 48:
            raise OperationError("invalid_json", "JSON nesting exceeds the supported limit.")
        if item is None or type(item) in (str, bool):
            return item
        if type(item) is int:
            if abs(item) > 9007199254740991:
                raise OperationError("invalid_json", "JSON integers must be exactly representable by supported clients.")
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise OperationError("invalid_json", "JSON numbers must be finite.")
            if item.is_integer():
                return normalize(int(item), depth)
            return item
        if type(item) is list:
            return [normalize(child, depth + 1) for child in item]
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise OperationError("invalid_json", "JSON object keys must be strings.")
            return {key: normalize(child, depth + 1) for key, child in item.items()}
        raise OperationError("invalid_json", "Only ordinary JSON values are accepted.")
    try:
        encoded = json.dumps(normalize(value, 0), ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        size = len(encoded.encode("utf-8"))
    except (RecursionError, UnicodeError, ValueError) as exc:
        raise OperationError("invalid_json", "The JSON document is invalid.") from exc
    if size > max_bytes:
        raise OperationError("payload_too_large", "The JSON document exceeds the supported size.", 413)
    return encoded


def redact(value):
    """Validate before traversing, then redact ordinary event/audit payloads."""
    def visit(item):
        if isinstance(item, dict):
            return {key: "[redacted]" if any(word in key.lower() for word in _SECRET_KEYS) else visit(child)
                    for key, child in item.items()}
        if isinstance(item, list):
            return [visit(child) for child in item]
        return item
    return visit(json.loads(canonical_json(value)))


def _text(value, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise OperationError("invalid_argument", f"{label} must be a nonempty bounded text value.")
    return value.strip()


def _message(value, label: str, maximum: int = 8192) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 and char not in "\r\n\t" for char in value)):
        raise OperationError("invalid_argument", f"{label} must be nonempty bounded display text.")
    return value.strip()


def _limit(value, maximum=1000) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise OperationError("invalid_limit", f"Limit must be an integer between 1 and {maximum}.")
    return value


def _seal(value) -> str:
    return protect_secret(canonical_json(value).encode("utf-8"))


def _open(value):
    return json.loads(unprotect_secret(value).decode("utf-8"))


class Store:
    EVENT_LIMIT = 20000
    AUDIT_LIMIT = 50000
    METRIC_LIMIT = 86400
    ARTIFACT_QUOTA = 10 * 1024 ** 3
    ARTIFACT_MAX_SIZE = 5 * 1024 ** 3
    ARTIFACT_MAX_COUNT = 1000
    ARTIFACT_TTL_SECONDS = 24 * 3600

    def __init__(self, data_dir: Path):
        self.data_dir = protected_directory(data_dir)
        self.artifacts_dir = protected_directory(self.data_dir / "artifacts")
        self.path = self.data_dir / "state.sqlite3"
        self._closed = False
        self._artifact_lock = threading.RLock()
        identity = agent_identity(self.data_dir)
        reject_links(self.path)
        self._agent_id = identity["id"]
        for existing in (self.path, *(self.data_dir / ("state.sqlite3" + suffix) for suffix in ("-journal", "-wal", "-shm"))):
            reject_links(existing)
            if existing.exists():
                protect_path(existing)
        # The private directory protects SQLite's journal/WAL from their creation.
        with self._transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise OperationError("state_version", "Agent state was created by an incompatible version.", 500)
            statements = (
                "CREATE TABLE IF NOT EXISTS identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS config (domain TEXT PRIMARY KEY, revision INTEGER NOT NULL, value TEXT NOT NULL, updated TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, operation TEXT NOT NULL, args TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL, state TEXT NOT NULL, progress INTEGER, message TEXT NOT NULL, result TEXT, created TEXT NOT NULL, started TEXT, finished TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0, config_revision TEXT, config_snapshot TEXT NOT NULL, UNIQUE(device_id,request_id))",
                "CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(state,created,id)",
                "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, message TEXT NOT NULL, severity TEXT NOT NULL, data TEXT, created TEXT NOT NULL, actor TEXT)",
                "CREATE TABLE IF NOT EXISTS acknowledgements (event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, device_id TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY(event_id,device_id))",
                "CREATE TABLE IF NOT EXISTS audits (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, operation TEXT NOT NULL, outcome TEXT NOT NULL, detail TEXT, job_id TEXT, created TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS metrics (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, value TEXT NOT NULL)",
                "CREATE INDEX IF NOT EXISTS metrics_time ON metrics(ts)",
                "CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, media_type TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, path TEXT NOT NULL UNIQUE, device_id TEXT)",
                "CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE, certificate TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, revoked TEXT, last_seen TEXT)",
                "CREATE TABLE IF NOT EXISTS pairings (digest TEXT PRIMARY KEY, role TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, consumed TEXT)",
                "CREATE TABLE IF NOT EXISTS confirmations (digest TEXT PRIMARY KEY, device_id TEXT NOT NULL, binding TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, consumed TEXT)",
                "CREATE TABLE IF NOT EXISTS enrollment_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT NOT NULL)",
            )
            for statement in statements:
                connection.execute(statement)
            connection.execute("INSERT OR IGNORE INTO identity(singleton,value) VALUES(1,?)", (canonical_json(identity),))
            existing = json.loads(connection.execute("SELECT value FROM identity WHERE singleton=1").fetchone()[0])
            if existing["id"] != identity["id"]:
                raise OperationError("identity_mismatch", "Agent identity and state do not match.", 500)
            connection.execute("PRAGMA user_version=1")
        protect_path(self.path)

    @contextmanager
    def _transaction(self, write=True):
        if self._closed:
            raise OperationError("store_closed", "Agent state is closed.", 503)
        reject_links(self.path)
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def identity(self) -> dict:
        with self._transaction(False) as connection:
            return json.loads(connection.execute("SELECT value FROM identity WHERE singleton=1").fetchone()[0])

    def set_name(self, name):
        name = _text(name, "Agent name", 128)
        with self._transaction() as connection:
            value = json.loads(connection.execute("SELECT value FROM identity WHERE singleton=1").fetchone()[0])
            value["name"] = name
            connection.execute("UPDATE identity SET value=? WHERE singleton=1", (canonical_json(value),))

    def _event(self, row) -> dict:
        result = dict(row)
        result["data"] = json.loads(result["data"]) if result["data"] is not None else None
        result["actor"] = json.loads(result["actor"]) if result["actor"] is not None else None
        result["agent_id"] = self._agent_id
        result["acknowledged_by"] = json.loads(result.get("acknowledged_by", "[]"))
        return result

    @staticmethod
    def _prune(connection, table, maximum):
        connection.execute(f"DELETE FROM {table} WHERE id <= COALESCE((SELECT id FROM {table} ORDER BY id DESC LIMIT 1 OFFSET ?),0)", (maximum,))

    def append_event(self, kind, message, severity="info", data=None, actor=None) -> dict:
        kind, message = _text(kind, "Event kind", 128), _message(message, "Event message", 8192)
        if severity not in {"debug", "info", "warning", "error", "critical", "success"}:
            raise OperationError("invalid_severity", "Invalid event severity.")
        encoded = canonical_json(redact(data), max_bytes=262144)
        principal = canonical_json(redact(actor), max_bytes=16384) if actor is not None else None
        with self._transaction() as connection:
            identifier = connection.execute("INSERT INTO events(kind,message,severity,data,created,actor) VALUES(?,?,?,?,?,?)",
                (kind, message, severity, encoded, timestamp(), principal)).lastrowid
            row = connection.execute("SELECT * FROM events WHERE id=?", (identifier,)).fetchone()
            self._prune(connection, "events", self.EVENT_LIMIT)
            return self._event(row)

    @staticmethod
    def _cursor(connection, table, after):
        if type(after) is not int or after < 0:
            raise OperationError("invalid_cursor", "Cursor must be a nonnegative integer.")
        minimum = connection.execute(f"SELECT MIN(id) FROM {table}").fetchone()[0]
        if after and minimum is not None and after < minimum - 1:
            raise OperationError("cursor_expired", "History before this cursor has expired; refresh from cursor zero.", 410)

    def events(self, after=0, limit=100) -> list[dict]:
        _limit(limit)
        with self._transaction(False) as connection:
            self._cursor(connection, "events", after)
            rows = connection.execute("SELECT e.*,(SELECT json_group_array(device_id) FROM acknowledgements a WHERE a.event_id=e.id) AS acknowledged_by FROM events e WHERE e.id>? ORDER BY e.id LIMIT ?", (after, limit))
            return [self._event(row) for row in rows]

    def acknowledge(self, event_id, device_id):
        if type(event_id) is not int or event_id <= 0:
            raise OperationError("invalid_event", "A valid event ID is required.")
        device_id = _text(device_id, "Device ID", 128)
        with self._transaction() as connection:
            if not connection.execute("SELECT 1 FROM events WHERE id=?", (event_id,)).fetchone():
                raise OperationError("event_not_found", "Event does not exist or has expired.", 404)
            connection.execute("INSERT OR IGNORE INTO acknowledgements(event_id,device_id,created) VALUES(?,?,?)", (event_id, device_id, timestamp()))

    def append_audit(self, actor, operation, outcome, detail=None, job_id=None) -> None:
        with self._transaction() as connection:
            self._append_audit(connection, actor, operation, outcome, detail, job_id)

    def _append_audit(self, connection, actor, operation, outcome, detail=None, job_id=None) -> None:
        """Allow security mutations and their audit entry to commit together."""
        operation, outcome = _text(operation, "Operation", 256), _text(outcome, "Outcome", 128)
        principal = canonical_json(redact(actor), max_bytes=16384) if actor is not None else None
        encoded = canonical_json(redact(detail), max_bytes=262144)
        connection.execute("INSERT INTO audits(actor,operation,outcome,detail,job_id,created) VALUES(?,?,?,?,?,?)",
                           (principal, operation, outcome, encoded, job_id, timestamp()))
        self._prune(connection, "audits", self.AUDIT_LIMIT)

    def audits(self, after=0, limit=100) -> list[dict]:
        _limit(limit)
        with self._transaction(False) as connection:
            self._cursor(connection, "audits", after)
            result = []
            for row in connection.execute("SELECT * FROM audits WHERE id>? ORDER BY id LIMIT ?", (after, limit)):
                item = dict(row)
                for key in ("actor", "detail"):
                    item[key] = json.loads(item[key]) if item[key] is not None else None
                result.append(item)
            return result

    @staticmethod
    def _job(row) -> dict | None:
        if row is None:
            return None
        result = dict(row)
        result.pop("request_hash", None)
        for key in ("args", "result", "config_snapshot"):
            result[key] = _open(result[key]) if result[key] is not None else None
        result["config_revision"] = json.loads(result["config_revision"]) if result["config_revision"] is not None else None
        result["cancel_requested"] = bool(result["cancel_requested"])
        return result

    def create_job(self, device_id, operation, args, request_id, config_revision=None) -> tuple[dict, bool]:
        device_id, operation = _text(device_id, "Device ID", 128), _text(operation, "Operation", 256)
        request_id = _text(request_id, "Request ID", 128)
        if type(args) is not dict:
            raise OperationError("invalid_arguments", "Operation arguments must be a JSON object.")
        if config_revision is not None and type(config_revision) not in (int, dict):
            raise OperationError("invalid_revision", "Configuration revision must be an integer or domain revision map.")
        if type(config_revision) is int and config_revision < 0:
            raise OperationError("invalid_revision", "Configuration revision cannot be negative.")
        if type(config_revision) is dict and any(type(domain) is not str or type(revision) is not int or revision < 0 for domain, revision in config_revision.items()):
            raise OperationError("invalid_revision", "Invalid domain revision map.")
        digest = hashlib.sha256(canonical_json({"operation": operation, "args": args, "config_revision": config_revision}).encode()).hexdigest()
        with self._transaction() as connection:
            existing = connection.execute("SELECT * FROM jobs WHERE device_id=? AND request_id=?", (device_id, request_id)).fetchone()
            if existing:
                if existing["request_hash"] != digest:
                    raise OperationError("idempotency_conflict", "This request ID was already accepted with different parameters.", 409)
                return self._job(existing), False
            rows = connection.execute("SELECT domain,revision,value FROM config WHERE substr(domain,1,1)<>'_' ORDER BY domain").fetchall()
            versions = {row["domain"]: row["revision"] for row in rows}
            if isinstance(config_revision, dict) and any(versions.get(domain, 0) != revision for domain, revision in config_revision.items()):
                raise OperationError("revision_conflict", "Configuration changed before job acceptance.", 409)
            snapshot = {row["domain"]: {"revision": row["revision"], "value": _open(row["value"])} for row in rows}
            identifier = str(uuid.uuid4())
            connection.execute("INSERT INTO jobs(id,device_id,operation,args,request_id,request_hash,state,message,created,config_revision,config_snapshot) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (identifier, device_id, operation, _seal(args), request_id, digest, "queued", "Waiting for the worker.", timestamp(),
                 canonical_json(config_revision) if config_revision is not None else None, _seal(snapshot)))
            return self._job(connection.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone()), True

    def jobs(self, device_id=None, limit=100) -> list[dict]:
        _limit(limit)
        with self._transaction(False) as connection:
            if device_id is None:
                rows = connection.execute("SELECT * FROM jobs ORDER BY created DESC,id DESC LIMIT ?", (limit,))
            else:
                rows = connection.execute("SELECT * FROM jobs WHERE device_id=? ORDER BY created DESC,id DESC LIMIT ?", (device_id, limit))
            return [self._job(row) for row in rows]

    def job(self, job_id) -> dict | None:
        with self._transaction(False) as connection:
            return self._job(connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def find_job(self, device_id, request_id) -> dict | None:
        """Resolve an accepted request before consuming a fresh confirmation."""
        with self._transaction(False) as connection:
            row = connection.execute("SELECT * FROM jobs WHERE device_id=? AND request_id=?", (device_id, request_id)).fetchone()
            return self._job(row)

    def claim_job(self) -> dict | None:
        with self._transaction() as connection:
            row = connection.execute("SELECT id FROM jobs WHERE state='queued' ORDER BY created,id LIMIT 1").fetchone()
            if row is None:
                return None
            connection.execute("UPDATE jobs SET state='running',started=?,message=? WHERE id=? AND state='queued'",
                               (timestamp(), "Worker started.", row["id"]))
            return self._job(connection.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone())

    def update_job(self, job_id, **changes) -> dict:
        allowed = {"state", "progress", "message", "result", "started", "finished", "cancel_requested"}
        if set(changes) - allowed:
            raise OperationError("invalid_job_update", "The requested job fields cannot be changed.")
        if "progress" in changes and changes["progress"] is not None and (type(changes["progress"]) is not int or not 0 <= changes["progress"] <= 100):
            raise OperationError("invalid_progress", "Progress must be an integer percentage or null.")
        if "message" in changes:
            changes["message"] = _message(changes["message"], "Job message", 8192)
        if "result" in changes:
            changes["result"] = _seal(changes["result"])
        if "cancel_requested" in changes:
            if type(changes["cancel_requested"]) is not bool:
                raise OperationError("invalid_job_update", "Cancellation state must be boolean.")
            changes["cancel_requested"] = int(changes["cancel_requested"])
        with self._transaction() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise OperationError("job_not_found", "Job does not exist.", 404)
            if row["state"] in TERMINAL_STATES:
                if changes:
                    raise OperationError("job_terminal", "A completed job cannot be changed.", 409)
                return self._job(row)
            target = changes.get("state", row["state"])
            if target not in _STATES or (target != row["state"] and target not in _TRANSITIONS.get(row["state"], set())):
                raise OperationError("job_state_conflict", "The requested job transition is not allowed.", 409)
            if row["cancel_requested"] and changes.get("cancel_requested") == 0:
                raise OperationError("job_state_conflict", "A recorded cancellation request cannot be cleared.", 409)
            if target == "running" and row["started"] is None:
                changes.setdefault("started", timestamp())
            if target in TERMINAL_STATES:
                changes.setdefault("finished", timestamp())
            if changes:
                columns = ",".join(key + "=?" for key in changes)
                connection.execute("UPDATE jobs SET " + columns + " WHERE id=?", (*changes.values(), job_id))
            return self._job(connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def recover_jobs(self) -> None:
        with self._transaction() as connection:
            connection.execute("UPDATE jobs SET state='interrupted',finished=?,message=? WHERE state IN ('running','cancelling')",
                (timestamp(), "Worker stopped before an outcome was recorded. Effects may have occurred; inspect before submitting a fresh request."))

    def request_cancel(self, job_id) -> dict:
        with self._transaction() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise OperationError("job_not_found", "Job does not exist.", 404)
            if row["state"] == "queued":
                connection.execute("UPDATE jobs SET state='cancelled',cancel_requested=1,finished=?,message=? WHERE id=?",
                                   (timestamp(), "Cancelled before execution.", job_id))
            elif row["state"] in {"running", "cancelling"}:
                connection.execute("UPDATE jobs SET state='cancelling',cancel_requested=1,message=? WHERE id=?",
                                   ("Cancellation requested; already committed effects are not rolled back.", job_id))
            return self._job(connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def get_config(self, domain, default=None) -> dict:
        domain = _text(domain, "Configuration domain", 128)
        if default is not None and type(default) is not dict:
            raise OperationError("invalid_config", "Configuration defaults must be JSON objects.")
        with self._transaction(False) as connection:
            row = connection.execute("SELECT revision,value FROM config WHERE domain=?", (domain,)).fetchone()
            return {"revision": row["revision"], "value": _open(row["value"])} if row else {"revision": 0, "value": json.loads(canonical_json(default or {}))}

    def set_config(self, domain, value, expected_revision) -> dict:
        domain = _text(domain, "Configuration domain", 128)
        if type(value) is not dict:
            raise OperationError("invalid_config", "Configuration values must be JSON objects.")
        if type(expected_revision) is not int or expected_revision < 0:
            raise OperationError("invalid_revision", "Expected revision must be a nonnegative integer.")
        encoded = _seal(value)
        with self._transaction() as connection:
            row = connection.execute("SELECT revision FROM config WHERE domain=?", (domain,)).fetchone()
            revision = row["revision"] if row else 0
            if revision != expected_revision:
                raise OperationError("revision_conflict", "Configuration has changed; refresh before applying this edit.", 409)
            connection.execute("INSERT INTO config(domain,revision,value,updated) VALUES(?,?,?,?) ON CONFLICT(domain) DO UPDATE SET revision=excluded.revision,value=excluded.value,updated=excluded.updated",
                               (domain, revision + 1, encoded, timestamp()))
            return {"revision": revision + 1, "value": json.loads(canonical_json(value))}

    def config_versions(self) -> dict[str, int]:
        with self._transaction(False) as connection:
            return {row["domain"]: row["revision"] for row in connection.execute("SELECT domain,revision FROM config WHERE substr(domain,1,1)<>'_' ORDER BY domain")}

    def append_metric(self, snapshot: dict) -> None:
        if type(snapshot) is not dict or type(snapshot.get("ts")) not in (int, float) or not math.isfinite(snapshot["ts"]):
            raise OperationError("invalid_metric", "Metric snapshots require a finite UTC Unix timestamp in ts.")
        encoded = canonical_json(redact(snapshot), max_bytes=1024 * 1024)
        with self._transaction() as connection:
            connection.execute("INSERT INTO metrics(ts,value) VALUES(?,?)", (snapshot["ts"], encoded))
            self._prune(connection, "metrics", self.METRIC_LIMIT)

    def metrics(self, limit=1000, after=None, before=None, detailed=False) -> list[dict]:
        _limit(limit, 10000)
        conditions, parameters = [], []
        for boundary, sign in ((after, ">"), (before, "<=")):
            if boundary is not None:
                if type(boundary) not in (int, float) or not math.isfinite(boundary):
                    raise OperationError("invalid_timestamp", "Metric boundaries must be finite Unix timestamps.")
                conditions.append("ts" + sign + "?")
                parameters.append(boundary)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        columns = "value" if detailed else """ts,
            CASE WHEN json_type(value,'$.cpu')='object'
                 THEN json_extract(value,'$.cpu.pct') ELSE json_extract(value,'$.cpu') END AS cpu,
            CASE WHEN json_type(value,'$.ram')='object'
                 THEN json_extract(value,'$.ram.pct') ELSE json_extract(value,'$.ram') END AS ram,
            json_extract(value,'$.up_bps') AS up_bps,
            json_extract(value,'$.down_bps') AS down_bps"""
        with self._transaction(False) as connection:
            rows = connection.execute("SELECT " + columns + " FROM metrics" + where + " ORDER BY ts DESC,id DESC LIMIT ?", (*parameters, limit)).fetchall()
            return [json.loads(row["value"]) if detailed else dict(row) for row in reversed(rows)]

    def _expired_artifacts(self, connection) -> None:
        for row in connection.execute("SELECT id,path FROM artifacts WHERE expires<=?", (timestamp(),)).fetchall():
            path = Path(row["path"])
            if path.parent != self.artifacts_dir:
                raise OperationError("artifact_state_invalid", "Stored artifact path is invalid.", 500)
            reject_links(path)
            path.unlink(missing_ok=True)
            connection.execute("DELETE FROM artifacts WHERE id=?", (row["id"],))
        # A terminated process may leave an unregistered copy. A write transaction
        # excludes concurrent copies, so only files absent from the DB are removed.
        registered = {Path(row["path"]).name for row in connection.execute("SELECT path FROM artifacts")}
        for path in self.artifacts_dir.iterdir():
            if path.name.endswith((".part", ".bin")) and path.name not in registered:
                reject_links(path)
                if path.is_file():
                    path.unlink()

    def add_artifact(self, path: Path, name=None, media_type="application/octet-stream", device_id=None) -> dict:
        source = Path(os.path.abspath(path))
        reject_links(source)
        name = _text(name or source.name, "Artifact name", 240)
        if any(char in name for char in ("/", "\\", ":")) or name in {".", ".."}:
            raise OperationError("invalid_artifact_name", "Artifact names cannot contain path components.")
        media_type = _text(media_type, "Media type", 128)
        if device_id is not None:
            device_id = _text(device_id, "Device ID", 128)
        identifier = str(uuid.uuid4())
        destination = self.artifacts_dir / (identifier + ".bin")
        temporary = self.artifacts_dir / (identifier + ".part")
        # The DB write transaction serializes quota reservation/copy across all
        # worker processes; only a completed copy is ever visible to readers.
        with self._artifact_lock, self._transaction() as connection:
            self._expired_artifacts(connection)
            usage = connection.execute("SELECT COALESCE(SUM(size),0),COUNT(*) FROM artifacts").fetchone()
            if usage[1] >= self.ARTIFACT_MAX_COUNT:
                raise OperationError("artifact_quota", "Artifact count quota is exhausted; wait for expiry or remove old exports.", 507)
            try:
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(source, flags)
                with os.fdopen(descriptor, "rb") as incoming:
                    initial = os.fstat(incoming.fileno())
                    if not stat.S_ISREG(initial.st_mode):
                        raise OperationError("invalid_artifact", "Only regular files can be stored as artifacts.")
                    if initial.st_size > self.ARTIFACT_MAX_SIZE or usage[0] + initial.st_size > self.ARTIFACT_QUOTA:
                        raise OperationError("artifact_quota", "Artifact exceeds the protected export quota.", 507)
                    out_descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
                    digest, size = hashlib.sha256(), 0
                    with os.fdopen(out_descriptor, "wb") as outgoing:
                        protect_path(temporary)
                        while True:
                            chunk = incoming.read(1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            if size > self.ARTIFACT_MAX_SIZE or usage[0] + size > self.ARTIFACT_QUOTA:
                                raise OperationError("artifact_quota", "Artifact grew beyond the protected export quota.", 507)
                            digest.update(chunk)
                            outgoing.write(chunk)
                        outgoing.flush()
                        os.fsync(outgoing.fileno())
                    final = os.fstat(incoming.fileno())
                    current = source.stat()
                    reject_links(source)
                    if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns) != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) or (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino):
                        raise OperationError("artifact_changed", "The source changed during export; generate a fresh artifact.", 409)
                os.replace(temporary, destination)
                protect_path(destination)
                created = timestamp()
                expires = timestamp(utcnow() + timedelta(seconds=self.ARTIFACT_TTL_SECONDS))
                result = {"id": identifier, "name": name, "size": size, "sha256": digest.hexdigest(), "media_type": media_type,
                          "created": created, "expires": expires, "path": str(destination), "device_id": device_id}
                connection.execute("INSERT INTO artifacts(id,name,size,sha256,media_type,created,expires,path,device_id) VALUES(:id,:name,:size,:sha256,:media_type,:created,:expires,:path,:device_id)", result)
                return result
            except Exception:
                temporary.unlink(missing_ok=True)
                destination.unlink(missing_ok=True)
                raise

    def artifact(self, identifier) -> dict | None:
        with self._artifact_lock, self._transaction() as connection:
            self._expired_artifacts(connection)
            row = connection.execute("SELECT * FROM artifacts WHERE id=?", (identifier,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            path = Path(result["path"])
            if path.parent != self.artifacts_dir:
                raise OperationError("artifact_state_invalid", "Stored artifact path is invalid.", 500)
            reject_links(path)
            if not path.is_file() or path.stat().st_size != result["size"]:
                raise OperationError("artifact_missing", "The artifact is no longer available.", 410)
            return result

    # Security uses these private transactions/schema under the same lock and
    # commit rules; no gateway or backend may issue raw SQL.
    def close(self) -> None:
        self._closed = True
