"""Single-process SQLite authority for hashed relay capabilities.

Only hashes of random tokens reach SQLite. Transactions redeem invitations,
activate grants and revoke routes atomically; agent identities remain tombstones.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, fields
from pathlib import Path
from uuid import uuid4

from .protocol import canonical_id, new_token, token_hash


class RelayError(Exception):
    """Public, fixed diagnostic; never include submitted values."""

    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Limits:
    agents: int = 256
    invitations: int = 128
    grants_per_route: int = 32
    pairings_per_route: int = 32
    streams_per_route: int = 16
    streams: int = 256
    pending_control: int = 64

    def __post_init__(self):
        # One explicit bound per field. Deriving the maxima from the field list
        # keeps a newly added limit bounded by default instead of silently
        # sharing (or escaping) an existing ceiling through a short zip.
        maxima = {"agents": 256, "invitations": 128, "grants_per_route": 32,
                  "pairings_per_route": 32, "streams_per_route": 16, "streams": 256,
                  "pending_control": 64}
        if {field.name for field in fields(self)} != set(maxima):
            raise ValueError("Relay limits must declare exactly one bound per field.")
        for name, maximum in maxima.items():
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"Relay limit {name} must be a positive integer no greater than {maximum}.")


class Store:
    def __init__(self, path: str | Path, *, limits: Limits | None = None):
        self.path = Path(path)
        self.limits = limits or Limits()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._mutex = threading.RLock()
        self._lock_file = None
        self.db = None
        try:
            # A second worker must fail, not share durable state while keeping
            # independent socket registries. The OS releases this lock on crash.
            self._lock_file = open(str(self.path) + ".lock", "a+b")
            self._lock_file.seek(0)
            if os.name == "nt":
                import msvcrt
                if not self._lock_file.read(1):
                    self._lock_file.write(b"\0")
                    self._lock_file.flush()
                self._lock_file.seek(0)
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(str(self.path), isolation_level=None, check_same_thread=False,
                                      timeout=5)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS agents (
                    route_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL, token_hash TEXT UNIQUE, created_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS invitations (
                    token_hash TEXT PRIMARY KEY, expires INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS grants (
                    grant_id TEXT PRIMARY KEY, route_id TEXT NOT NULL REFERENCES agents(route_id),
                    token_hash TEXT UNIQUE, created_at INTEGER NOT NULL, expires INTEGER NOT NULL,
                    activated_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS grants_route ON grants(route_id);
                CREATE TABLE IF NOT EXISTS pairings (
                    lookup_id TEXT PRIMARY KEY, route_id TEXT NOT NULL REFERENCES agents(route_id),
                    ciphertext TEXT NOT NULL, expires INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS pairings_route ON pairings(route_id);
            """)
            self.cleanup()
        except BaseException:
            self.close()
            raise

    def close(self):
        with self._mutex:
            if self.db is not None:
                self.db.close()
                self.db = None
            if self._lock_file is not None:
                self._lock_file.close()
                self._lock_file = None

    @contextmanager
    def _transaction(self):
        with self._mutex:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    @staticmethod
    def _prune(db, now: int):
        db.execute("DELETE FROM invitations WHERE expires <= ?", (now,))
        db.execute("DELETE FROM pairings WHERE expires <= ?", (now,))
        db.execute("DELETE FROM grants WHERE activated_at IS NULL AND expires <= ?", (now,))

    def cleanup(self):
        with self._transaction() as db:
            self._prune(db, int(time.time()))

    @staticmethod
    def _agent(db, route_id: str, credential_hash: str):
        row = db.execute("SELECT route_id FROM agents WHERE route_id=? AND token_hash=? AND revoked=0",
                         (route_id, credential_hash)).fetchone()
        if row is None:
            raise RelayError("invalid_agent_credential", 401)

    def authenticate_agent(self, route_id: str, credential_hash: str):
        with self._mutex:
            self._agent(self.db, route_id, credential_hash)

    def create_invitation(self, ttl: int) -> tuple[str, int]:
        now = int(time.time())
        token = new_token()
        with self._transaction() as db:
            self._prune(db, now)
            if db.execute("SELECT COUNT(*) FROM invitations").fetchone()[0] >= self.limits.invitations:
                raise RelayError("invitation_quota", 429)
            db.execute("INSERT INTO invitations VALUES (?, ?)", (token_hash(token), now + ttl))
        return token, now + ttl

    def register(self, invitation: str, agent_id: str, name: str) -> dict:
        credential_hash = token_hash(invitation)
        canonical_id(agent_id)
        token = new_token()
        route_id = str(uuid4())
        now = int(time.time())
        with self._transaction() as db:
            self._prune(db, now)
            if db.execute("SELECT 1 FROM invitations WHERE token_hash=? AND expires>?",
                          (credential_hash, now)).fetchone() is None:
                raise RelayError("invalid_installation_invitation", 401)
            if db.execute("SELECT 1 FROM agents WHERE agent_id=?", (agent_id,)).fetchone():
                raise RelayError("agent_identity_exists", 409)
            # Tombstones count toward the finite identity budget as well.
            if db.execute("SELECT COUNT(*) FROM agents").fetchone()[0] >= self.limits.agents:
                raise RelayError("agent_quota", 429)
            db.execute("INSERT INTO agents VALUES (?, ?, ?, ?, ?, 0)",
                       (route_id, agent_id, name, token_hash(token), now))
            db.execute("DELETE FROM invitations WHERE token_hash=?", (credential_hash,))
        return {"route_id": route_id, "agent_token": token}

    def agents(self) -> list[dict]:
        with self._mutex:
            return [dict(row) for row in self.db.execute(
                "SELECT route_id,agent_id,name,created_at,revoked FROM agents ORDER BY created_at,route_id")]

    def create_grant(self, route_id: str, credential_hash: str) -> dict:
        now = int(time.time())
        token = new_token()
        grant_id = str(uuid4())
        with self._transaction() as db:
            self._prune(db, now)
            self._agent(db, route_id, credential_hash)
            # Remove powerless history before admitting another grant, bounding
            # the durable table as well as the active capabilities.
            db.execute("DELETE FROM grants WHERE route_id=? AND revoked=1", (route_id,))
            if db.execute("SELECT COUNT(*) FROM grants WHERE route_id=? AND revoked=0",
                          (route_id,)).fetchone()[0] >= self.limits.grants_per_route:
                raise RelayError("grant_quota", 429)
            db.execute("INSERT INTO grants VALUES (?, ?, ?, ?, ?, NULL, 0)",
                       (grant_id, route_id, token_hash(token), now, now + 600))
        return {"grant_id": grant_id, "route_token": token}

    def activate_grant(self, route_id: str, credential_hash: str) -> str:
        now = int(time.time())
        with self._transaction() as db:
            self._prune(db, now)
            row = db.execute("SELECT g.grant_id FROM grants g JOIN agents a USING(route_id) "
                             "WHERE g.route_id=? AND g.token_hash=? AND g.revoked=0 AND a.revoked=0 "
                             "AND (g.activated_at IS NOT NULL OR g.expires>?)",
                             (route_id, credential_hash, now)).fetchone()
            if row is None:
                raise RelayError("invalid_route_credential", 401)
            db.execute("UPDATE grants SET activated_at=COALESCE(activated_at,?) WHERE grant_id=?",
                       (now, row["grant_id"]))
            return row["grant_id"]

    def grants(self, route_id: str) -> list[dict]:
        # Read path: still prune opportunistically, but never take the write lock
        # (BEGIN IMMEDIATE) that a durable capability mutation would need.
        with self._mutex:
            self._prune(self.db, int(time.time()))
            if self.db.execute("SELECT 1 FROM agents WHERE route_id=?", (route_id,)).fetchone() is None:
                raise RelayError("route_not_found", 404)
            return [dict(row) for row in self.db.execute(
                "SELECT grant_id,created_at,activated_at,revoked FROM grants WHERE route_id=? "
                "ORDER BY created_at,grant_id", (route_id,))]

    def revoke_agent(self, route_id: str):
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM agents WHERE route_id=?", (route_id,)).fetchone() is None:
                raise RelayError("route_not_found", 404)
            db.execute("UPDATE agents SET revoked=1,token_hash=NULL WHERE route_id=?", (route_id,))
            db.execute("UPDATE grants SET revoked=1,token_hash=NULL WHERE route_id=?", (route_id,))
            db.execute("DELETE FROM pairings WHERE route_id=?", (route_id,))

    def revoke_grant(self, route_id: str, grant_id: str):
        with self._transaction() as db:
            result = db.execute("UPDATE grants SET revoked=1,token_hash=NULL WHERE route_id=? AND grant_id=?",
                                (route_id, grant_id))
            if result.rowcount != 1:
                raise RelayError("grant_not_found", 404)

    def publish_pairing(self, route_id: str, credential_hash: str, lookup_id: str,
                        ciphertext: str, expires: int):
        now = int(time.time())
        with self._transaction() as db:
            self._prune(db, now)
            self._agent(db, route_id, credential_hash)
            if not now < expires <= now + 600:
                raise RelayError("invalid_pairing_expiry", 422)
            if db.execute("SELECT 1 FROM pairings WHERE lookup_id=?", (lookup_id,)).fetchone():
                raise RelayError("pairing_exists", 409)
            if db.execute("SELECT COUNT(*) FROM pairings WHERE route_id=?", (route_id,)).fetchone()[0] >= self.limits.pairings_per_route:
                raise RelayError("pairing_quota", 429)
            db.execute("INSERT INTO pairings VALUES (?, ?, ?, ?)",
                       (lookup_id, route_id, ciphertext, expires))

    def pairing(self, lookup_id: str) -> dict:
        with self._mutex:
            row = self.db.execute("SELECT p.ciphertext FROM pairings p JOIN agents a USING(route_id) "
                                  "WHERE p.lookup_id=? AND p.expires>? AND a.revoked=0",
                                  (lookup_id, int(time.time()))).fetchone()
            if row is None:
                raise RelayError("pairing_not_found", 404)
            return {"ciphertext": row["ciphertext"]}
