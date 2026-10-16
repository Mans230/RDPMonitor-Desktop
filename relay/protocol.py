"""Versioned invitation format shared by the broker and Windows agent.

The fragment of an invitation is a secret. Never navigate to it, put it in a
request URL, or include it in diagnostics. Pairing encryption is end to end;
the broker receives only a hash lookup identifier and authenticated ciphertext.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 1
MAX_ENVELOPE_BYTES = 8192
MAX_PAIRING_TTL = 600
AAD_PREFIX = b"RDPMonitor.Pairing.v1\n"
_SECRET = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")


class ProtocolError(ValueError):
    """Safe invitation error; messages never contain the invitation secret."""


def normalize_origin(value: str, *, allow_loopback: bool = False) -> str:
    """Canonical HTTPS origin. Explicit development HTTP is loopback-only."""
    try:
        if not isinstance(value, str) or not value or len(value) > 2048:
            raise ValueError
        if any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
            raise ValueError
        parsed = urlsplit(value)
        host = parsed.hostname
        if not host or parsed.username is not None or parsed.password is not None:
            raise ValueError
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError
        if "%" in host:
            raise ValueError
        host = host.encode("idna").decode("ascii").lower()
        if parsed.scheme == "http" and allow_loopback:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError
        elif parsed.scheme != "https":
            raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        authority = f"[{host}]" if ":" in host else host
        default_port = 443 if parsed.scheme == "https" else 80
        if port is not None and port != default_port:
            authority += f":{port}"
        return f"{parsed.scheme}://{authority}"
    except (ValueError, UnicodeError, TypeError):
        raise ProtocolError("Relay must be an HTTPS origin without credentials or a path.") from None


def encode_secret(value: bytes) -> str:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ProtocolError("Invitation secret must contain 256 bits.")
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_secret(value: str) -> bytes:
    if not isinstance(value, str) or not _SECRET.fullmatch(value):
        raise ProtocolError("Invitation secret is invalid.")
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
        if len(decoded) != 32 or encode_secret(decoded) != value:
            raise ValueError
        return decoded
    except ValueError:
        raise ProtocolError("Invitation secret is invalid.") from None


def token_hash(token: str) -> str:
    """Hash a canonical random token, rejecting malformed credentials first."""
    return hashlib.sha256(decode_secret(token)).hexdigest()


def new_token() -> str:
    return encode_secret(secrets.token_bytes(32))


def canonical_id(value: str) -> str:
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError
        return value
    except (ValueError, AttributeError, TypeError):
        raise ProtocolError("Agent or route identifier is invalid.") from None


def agent_hostname(agent_id: str) -> str:
    return f"{canonical_id(agent_id)}.rdpmonitor.invalid"


def agent_origin(agent_id: str) -> str:
    return f"https://{agent_hostname(agent_id)}"


@dataclass(frozen=True)
class Invitation:
    kind: str
    origin: str
    secret: bytes

    @property
    def token(self) -> str:
        return encode_secret(self.secret)

    @property
    def lookup_id(self) -> str:
        return hashlib.sha256(self.secret).hexdigest()


def make_invitation(kind: str, origin: str, token: str, *, allow_loopback: bool = False) -> str:
    if kind not in ("install", "pair"):
        raise ProtocolError("Invitation type is unsupported.")
    decode_secret(token)
    origin = normalize_origin(origin, allow_loopback=allow_loopback)
    return f"rdpmonitor://{kind}?{urlencode({'relay': origin, 'v': '1'})}#{token}"


def parse_invitation(value: str, *, kind: str, allow_loopback: bool = False) -> Invitation:
    try:
        if not isinstance(value, str) or len(value) > 4096:
            raise ValueError
        value = value.strip()
        parsed = urlsplit(value)
        query = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True)
        if (kind not in ("install", "pair") or parsed.scheme != "rdpmonitor"
                or parsed.netloc != kind or parsed.path
                or set(query) != {"relay", "v"} or query["v"] != ["1"]
                or len(query["relay"]) != 1):
            raise ValueError
        origin = normalize_origin(query["relay"][0], allow_loopback=allow_loopback)
        return Invitation(kind, origin, decode_secret(parsed.fragment))
    except (ValueError, TypeError, KeyError):
        raise ProtocolError("Invitation is invalid or uses an unsupported version.") from None


@dataclass(frozen=True)
class SetupInvitation:
    """Two independent capabilities; only the installation token reaches registration."""
    origin: str
    install_secret: bytes = field(repr=False)
    pairing_secret: bytes = field(repr=False)

    @property
    def installation_code(self) -> str:
        return make_invitation("install", self.origin, encode_secret(self.install_secret),
                               allow_loopback=self.origin.startswith("http://"))

    @property
    def connection_code(self) -> str:
        return make_invitation("pair", self.origin, encode_secret(self.pairing_secret),
                               allow_loopback=self.origin.startswith("http://"))


def make_setup_invitation(origin: str, install_token: str, pairing_secret: bytes, *,
                          allow_loopback: bool = False) -> str:
    install_secret = decode_secret(install_token)
    pairing_token = encode_secret(pairing_secret)
    if install_secret == pairing_secret:
        raise ProtocolError("Setup requires independent installation and pairing capabilities.")
    origin = normalize_origin(origin, allow_loopback=allow_loopback)
    return f"rdpmonitor://setup?{urlencode({'relay': origin, 'v': '1'})}#{install_token}.{pairing_token}"


def parse_setup_invitation(value: str, *, allow_loopback: bool = False) -> SetupInvitation:
    try:
        if not isinstance(value, str) or len(value) > 4096:
            raise ValueError
        value = value.strip()
        if re.search(r"[\x00-\x20\x7f\\]", value):
            raise ValueError
        parsed = urlsplit(value)
        query = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True)
        if (parsed.scheme != "rdpmonitor" or parsed.netloc != "setup" or parsed.path
                or set(query) != {"relay", "v"} or query["v"] != ["1"]
                or len(query["relay"]) != 1):
            raise ValueError
        install_token, pairing_token = parsed.fragment.split(".")
        install_secret, pairing_secret = decode_secret(install_token), decode_secret(pairing_token)
        if install_secret == pairing_secret:
            raise ValueError
        return SetupInvitation(normalize_origin(query["relay"][0], allow_loopback=allow_loopback),
                               install_secret, pairing_secret)
    except (ValueError, TypeError, KeyError):
        raise ProtocolError("Setup code is invalid or uses an unsupported version.") from None


def validate_pairing(payload: object, *, now: float | None = None) -> dict:
    """Validate authenticated plaintext before using any routing credential."""
    required = {"v", "agent_id", "route_id", "fingerprint", "pairing_code", "route_token", "expires", "name"}
    if not isinstance(payload, dict) or set(payload) != required or type(payload.get("v")) is not int or payload["v"] != VERSION:
        raise ProtocolError("Connection code uses an unsupported payload.")
    canonical_id(payload["agent_id"])
    canonical_id(payload["route_id"])
    if not isinstance(payload["fingerprint"], str) or not _FINGERPRINT.fullmatch(payload["fingerprint"]):
        raise ProtocolError("Connection code has an invalid agent fingerprint.")
    code = payload["pairing_code"]
    if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", code):
        raise ProtocolError("Connection code has an invalid enrollment capability.")
    decode_secret(payload["route_token"])
    if not isinstance(payload["name"], str) or not 1 <= len(payload["name"]) <= 128 or any(ord(c) < 32 for c in payload["name"]):
        raise ProtocolError("Connection code has an invalid machine name.")
    current = time.time() if now is None else now
    expiry = payload["expires"]
    if type(expiry) is not int or not current < expiry <= current + MAX_PAIRING_TTL:
        raise ProtocolError("Connection code has expired or has an invalid lifetime. Check both machines' clocks.")
    return payload


def create_pairing_envelope(origin: str, payload: dict, *, allow_loopback: bool = False,
                            secret: bytes | None = None, now: float | None = None) -> dict:
    origin = normalize_origin(origin, allow_loopback=allow_loopback)
    validate_pairing(payload, now=now)
    secret = secrets.token_bytes(32) if secret is None else secret
    token = encode_secret(secret)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    nonce = secrets.token_bytes(12)
    ciphertext = nonce + AESGCM(secret).encrypt(nonce, plaintext, AAD_PREFIX + origin.encode("utf-8"))
    if len(ciphertext) > MAX_ENVELOPE_BYTES:
        raise ProtocolError("Connection envelope exceeds the size limit.")
    return {
        "code": make_invitation("pair", origin, token, allow_loopback=allow_loopback),
        "lookup_id": hashlib.sha256(secret).hexdigest(),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii").rstrip("="),
        "expires": payload["expires"],
    }


def decrypt_pairing(origin: str, secret: bytes, ciphertext: str, *, allow_loopback: bool = False,
                    now: float | None = None) -> dict:
    origin = normalize_origin(origin, allow_loopback=allow_loopback)
    encode_secret(secret)
    try:
        if not isinstance(ciphertext, str) or not 38 <= len(ciphertext) <= (MAX_ENVELOPE_BYTES * 4 + 2) // 3:
            raise ValueError
        if not re.fullmatch(r"[A-Za-z0-9_-]+", ciphertext):
            raise ValueError
        raw = base64.b64decode(ciphertext + "=" * (-len(ciphertext) % 4), altchars=b"-_", validate=True)
        if not 28 <= len(raw) <= MAX_ENVELOPE_BYTES:
            raise ValueError
        if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != ciphertext:
            raise ValueError
        plaintext = AESGCM(secret).decrypt(raw[:12], raw[12:], AAD_PREFIX + origin.encode("utf-8"))
        payload = json.loads(plaintext.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError, InvalidTag):
        raise ProtocolError("Connection code could not be authenticated.") from None
    return validate_pairing(payload, now=now)
