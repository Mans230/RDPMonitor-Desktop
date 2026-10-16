"""Certificate-bound authorization, locally approved enrollment and confirmations.

There are no bearer tokens or caller-selected privileges. Pairing challenges are
created only by the local administration transport; the approved role is durable
and cannot be overridden by an enrollment request. All admission checks reload
current device state so revocation applies to connected clients and queued jobs.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from .certificates import CertificateAuthority, timestamp, utcnow
from .contracts import CAPABILITIES, OperationError
from .store import Store, _text, canonical_json

ROLE_CAPABILITIES = {
    "owner": frozenset(CAPABILITIES),
    "operator": frozenset({"view", "operate", "backup", "files"}),
    "viewer": frozenset({"view"}),
}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class Security:
    CONFIRMATION_TTL_SECONDS = 120
    MAX_PAIRING_TTL_SECONDS = 600
    ENROLLMENT_ATTEMPTS_PER_MINUTE = 30

    def __init__(self, store: Store, ca: CertificateAuthority):
        self.store = store
        self.ca = ca
        info = ca.ensure()
        if info["agent_id"] != store.identity()["id"]:
            raise OperationError("identity_mismatch", "Certificate authority and agent state do not match.", 500)
        self.agent_id = info["agent_id"]

    def begin_pairing(self, ttl_seconds=300, role="owner") -> dict:
        """LOCAL-ONLY approval; never expose this method to remote identities."""
        if type(ttl_seconds) is not int or not 30 <= ttl_seconds <= self.MAX_PAIRING_TTL_SECONDS:
            raise OperationError("invalid_pairing_ttl", "Pairing lifetime must be between 30 and 600 seconds.")
        if not isinstance(role, str) or role not in ROLE_CAPABILITIES:
            raise OperationError("invalid_role", "Choose owner, operator, or viewer locally.")
        info = self.ca.ensure()
        code = secrets.token_urlsafe(24)
        now = utcnow()
        expires = timestamp(now + timedelta(seconds=ttl_seconds))
        with self.store._transaction() as connection:
            connection.execute("DELETE FROM pairings WHERE expires<=? OR consumed IS NOT NULL", (timestamp(now),))
            count = connection.execute("SELECT COUNT(*) FROM pairings").fetchone()[0]
            if count >= 5:
                raise OperationError("pairing_limit", "Five local approvals are already pending; allow them to expire.", 429)
            connection.execute("INSERT INTO pairings(digest,role,created,expires) VALUES(?,?,?,?)",
                               (_digest(code), role, timestamp(now), expires))
            self.store._append_audit(connection, {"id": "local", "name": "Local administrator", "role": "local"},
                                     "pairing.begin", "approved", {"role": role, "expires": expires})
        return {"code": code, "expires": expires, "agent_id": info["agent_id"], "fingerprint": info["fingerprint"]}

    def _enrollment_rate(self):
        """Commit failed attempts independently; invalid codes cannot roll back limits."""
        now = utcnow()
        with self.store._transaction() as connection:
            connection.execute("DELETE FROM enrollment_attempts WHERE created<?", (timestamp(now - timedelta(minutes=1)),))
            if connection.execute("SELECT COUNT(*) FROM enrollment_attempts").fetchone()[0] >= self.ENROLLMENT_ATTEMPTS_PER_MINUTE:
                raise OperationError("enrollment_rate_limited", "Enrollment attempts are temporarily limited; retry after one minute.", 429)
            connection.execute("INSERT INTO enrollment_attempts(created) VALUES(?)", (timestamp(now),))

    def enroll(self, code, name, csr_pem, role="owner") -> dict:
        # role is retained solely for the documented call signature. It is never
        # inspected or used: only the local approval determines privileges.
        self._enrollment_rate()
        name = _text(name, "Device name", 128)
        if not isinstance(code, str) or not 16 <= len(code) <= 128:
            raise OperationError("invalid_pairing", "Pairing approval is invalid, expired, or already used.", 403)
        self.ca.validate_csr(csr_pem)
        digest = _digest(code)
        device_id = str(uuid.uuid4())
        now = timestamp()
        with self.store._transaction() as connection:
            challenge = connection.execute("SELECT * FROM pairings WHERE digest=?", (digest,)).fetchone()
            if challenge is None or not hmac.compare_digest(challenge["digest"], digest) or challenge["consumed"] is not None or challenge["expires"] <= now:
                raise OperationError("invalid_pairing", "Pairing approval is invalid, expired, or already used.", 403)
            approved_role = challenge["role"]
            if approved_role not in ROLE_CAPABILITIES:
                raise OperationError("invalid_pairing", "The local approval has an invalid role.", 403)
            bundle = self.ca.issue_client(csr_pem, device_id)
            connection.execute("INSERT INTO devices(id,name,role,fingerprint,certificate,created,expires) VALUES(?,?,?,?,?,?,?)",
                (device_id, name, approved_role, bundle["fingerprint"], bundle["certificate"], now, bundle["expires"]))
            connection.execute("UPDATE pairings SET consumed=? WHERE digest=? AND consumed IS NULL", (now, digest))
            actor = self._actor(connection, device_id)
            self.store._append_audit(connection, actor, "pairing.enroll", "succeeded", {"role": approved_role})
        return {"device": {"id": device_id, "name": name, "role": approved_role},
                "certificate": bundle["certificate"], "ca_certificate": bundle["ca_certificate"],
                "agent_id": self.agent_id, "expires": bundle["expires"]}

    def _actor(self, connection, device_id) -> dict:
        if not isinstance(device_id, str):
            raise OperationError("unauthenticated", "An enrolled device identity is required.", 401)
        row = connection.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if row is None or row["revoked"] is not None:
            raise OperationError("device_revoked", "The device is not enrolled or has been revoked.", 401)
        if row["expires"] <= timestamp():
            raise OperationError("certificate_expired", "The device certificate has expired; approve a fresh local pairing.", 401)
        if row["role"] not in ROLE_CAPABILITIES:
            raise OperationError("invalid_device_role", "The enrolled device has no valid permission preset.", 403)
        return {"id": row["id"], "name": row["name"], "role": row["role"],
                "capabilities": sorted(ROLE_CAPABILITIES[row["role"]]), "fingerprint": row["fingerprint"],
                "expires": row["expires"], "agent_id": self.agent_id}

    def active_actor(self, device_id) -> dict:
        """Resolve a durable initiator for restart/worker admission; no supplied role."""
        with self.store._transaction(False) as connection:
            return self._actor(connection, device_id)

    def authenticate(self, peer_der: bytes) -> dict:
        certificate = self.ca.verify_client(peer_der)
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(names) != 1:
            raise OperationError("invalid_certificate", "The client certificate has no unique device identity.", 401)
        device_id = names[0].value
        with self.store._transaction() as connection:
            actor = self._actor(connection, device_id)
            if not hmac.compare_digest(actor["fingerprint"], fingerprint):
                raise OperationError("certificate_not_enrolled", "The client certificate is no longer enrolled.", 401)
            connection.execute("UPDATE devices SET last_seen=? WHERE id=?", (timestamp(), device_id))
            return actor

    def authorize(self, actor, capability) -> None:
        if capability not in CAPABILITIES:
            raise OperationError("invalid_capability", "The operation has an invalid capability requirement.", 403)
        if not isinstance(actor, dict):
            raise OperationError("unauthenticated", "An enrolled device identity is required.", 401)
        fresh = self.active_actor(actor.get("id"))
        if actor.get("fingerprint") is not None and not hmac.compare_digest(str(actor["fingerprint"]), fresh["fingerprint"]):
            raise OperationError("certificate_rotated", "The device credential has changed; reconnect using the current certificate.", 401)
        if capability not in ROLE_CAPABILITIES[fresh["role"]]:
            self.store.append_audit(fresh, "authorization", "denied", {"capability": capability})
            raise OperationError("permission_denied", "The enrolled device is not permitted to perform this operation.", 403)

    def devices(self) -> list[dict]:
        with self.store._transaction(False) as connection:
            return [{**dict(row), "capabilities": sorted(ROLE_CAPABILITIES.get(row["role"], ())) }
                    for row in connection.execute("SELECT id,name,role,created,expires,revoked,last_seen,fingerprint FROM devices ORDER BY created,id")]

    def revoke(self, device_id, actor) -> None:
        self.authorize(actor, "manage")
        with self.store._transaction() as connection:
            # Recheck in the mutation transaction to close revoke-vs-revoke races.
            fresh = self._actor(connection, actor.get("id"))
            if "manage" not in ROLE_CAPABILITIES[fresh["role"]]:
                raise OperationError("permission_denied", "Owner permission is required.", 403)
            if not connection.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone():
                raise OperationError("device_not_found", "Device does not exist.", 404)
            connection.execute("UPDATE devices SET revoked=COALESCE(revoked,?) WHERE id=?", (timestamp(), device_id))
            connection.execute("DELETE FROM confirmations WHERE device_id=?", (device_id,))
            self.store._append_audit(connection, fresh, "devices.revoke", "succeeded", {"device_id": device_id})

    def renew(self, actor, csr_pem: str) -> dict:
        """Authenticated self-rotation; previous credential is immediately retired."""
        self.authorize(actor, "view")
        self.ca.validate_csr(csr_pem)
        with self.store._transaction() as connection:
            fresh = self._actor(connection, actor.get("id"))
            if not hmac.compare_digest(str(actor.get("fingerprint", "")), fresh["fingerprint"]):
                raise OperationError("certificate_rotated", "This credential has already been rotated.", 401)
            bundle = self.ca.issue_client(csr_pem, fresh["id"])
            connection.execute("UPDATE devices SET fingerprint=?,certificate=?,expires=? WHERE id=?",
                (bundle["fingerprint"], bundle["certificate"], bundle["expires"], fresh["id"]))
            connection.execute("DELETE FROM confirmations WHERE device_id=?", (fresh["id"],))
            self.store._append_audit(connection, fresh, "devices.renew", "succeeded")
        return {"device": {key: fresh[key] for key in ("id", "name", "role")}, "certificate": bundle["certificate"],
                "ca_certificate": bundle["ca_certificate"], "expires": bundle["expires"], "agent_id": fresh["agent_id"]}

    def _confirmation_binding(self, connection, actor, operation, args) -> tuple[dict, str]:
        operation = _text(operation, "Operation", 256)
        if type(args) is not dict:
            raise OperationError("invalid_arguments", "Confirmation arguments must be a JSON object.")
        if not isinstance(actor, dict):
            raise OperationError("unauthenticated", "An enrolled device identity is required.", 401)
        fresh = self._actor(connection, actor.get("id"))
        if actor.get("fingerprint") is not None and not hmac.compare_digest(str(actor["fingerprint"]), fresh["fingerprint"]):
            raise OperationError("certificate_rotated", "Reconnect with the current device credential.", 401)
        if fresh["role"] == "viewer":
            raise OperationError("permission_denied", "Viewers cannot confirm mutations.", 403)
        if operation == "configuration.update" and "configure" not in ROLE_CAPABILITIES[fresh["role"]]:
            raise OperationError("permission_denied", "Configuration permission is required.", 403)
        versions = {row["domain"]: row["revision"] for row in connection.execute("SELECT domain,revision FROM config WHERE substr(domain,1,1)<>'_' ORDER BY domain")}
        binding = {"agent": fresh["agent_id"], "device": fresh["id"], "fingerprint": fresh["fingerprint"],
                   "role": fresh["role"], "operation": operation, "args": args, "config_versions": versions}
        return fresh, _digest(canonical_json(binding))

    def prepare(self, actor, operation, args) -> dict:
        """Runtime must first authorize the operation's catalog capability."""
        nonce = secrets.token_urlsafe(32)
        now = utcnow()
        expires = timestamp(now + timedelta(seconds=self.CONFIRMATION_TTL_SECONDS))
        with self.store._transaction() as connection:
            fresh, binding = self._confirmation_binding(connection, actor, operation, args)
            connection.execute("DELETE FROM confirmations WHERE expires<=? OR consumed IS NOT NULL", (timestamp(now),))
            if connection.execute("SELECT COUNT(*) FROM confirmations WHERE device_id=?", (fresh["id"],)).fetchone()[0] >= 32:
                raise OperationError("confirmation_limit", "Too many pending confirmations; allow older confirmations to expire.", 429)
            connection.execute("INSERT INTO confirmations(digest,device_id,binding,created,expires) VALUES(?,?,?,?,?)",
                               (_digest(nonce), fresh["id"], binding, timestamp(now), expires))
            self.store._append_audit(connection, fresh, operation, "confirmation_prepared", {"expires": expires})
        return {"nonce": nonce, "expires": expires}

    def consume(self, actor, operation, args, nonce) -> None:
        if not isinstance(nonce, str) or not 24 <= len(nonce) <= 128:
            raise OperationError("confirmation_required", "A fresh confirmation for these exact parameters is required.", 409)
        digest = _digest(nonce)
        with self.store._transaction() as connection:
            fresh, binding = self._confirmation_binding(connection, actor, operation, args)
            row = connection.execute("SELECT * FROM confirmations WHERE digest=?", (digest,)).fetchone()
            if (row is None or row["consumed"] is not None or row["expires"] <= timestamp()
                    or row["device_id"] != fresh["id"] or not hmac.compare_digest(row["digest"], digest)
                    or not hmac.compare_digest(row["binding"], binding)):
                raise OperationError("confirmation_invalid", "Confirmation is expired, already used, or no longer matches this operation and configuration.", 409)
            connection.execute("UPDATE confirmations SET consumed=? WHERE digest=? AND consumed IS NULL", (timestamp(), digest))
            self.store._append_audit(connection, fresh, operation, "confirmation_consumed")
