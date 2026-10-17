"""Locally approved, desktop-key-bound direct installation (no remote enrollment)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
import zlib
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .certificates import (CertificateAuthority, atomic_private_write, identity_lock,
                           protect_path, protect_secret, reject_links, unprotect_secret)
from .contracts import OperationError

_PREFIX = "rdpmonitor://direct?v=1#"
_FIELDS = {"v", "endpoint", "server_key", "csr", "nonce", "expires", "source"}
_RECORD = "direct-bootstrap.json"
_RETAINED = ("identity.json", "tls", "state.sqlite3", "state.sqlite3-wal",
             "state.sqlite3-shm", "state.sqlite3-journal", "deployment.json",
             _RECORD, "gateway/relay.json")


def _invalid():
    return OperationError("direct_setup_invalid", "Invalid direct setup command. Prepare a fresh command on the desktop.")


def _base64(value, size=None):
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("base64url")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value or (size is not None and len(raw) != size):
        raise ValueError("canonical base64url")
    return raw


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("JSON constants are not permitted")


def _endpoint(value):
    if not isinstance(value, str) or not value.isascii() or len(value) > 320:
        raise ValueError("endpoint")
    parts = urlsplit(value)
    host, port = parts.hostname, parts.port
    if (parts.scheme != "https" or not host or port is None or not 1024 <= port <= 65535
            or parts.username is not None or parts.password is not None or parts.path
            or parts.query or parts.fragment or "%" in host):
        raise ValueError("endpoint origin")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                     for label in host.split(".")):
            raise ValueError("DNS host")
        formatted = host
    else:
        if address.is_unspecified or address.is_multicast:
            raise ValueError("endpoint address")
        host = str(address)
        formatted = "[" + host + "]" if address.version == 6 else host
    if value != f"https://{formatted}:{port}":
        raise ValueError("canonical origin")
    return host, port


def _source(value, endpoint):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("source")
    address = ipaddress.ip_address(value)
    if (str(address) != value or address.is_unspecified or address.is_multicast
            or address.is_link_local or getattr(address, "ipv4_mapped", None) is not None):
        raise ValueError("source literal")
    if address.is_loopback:
        try:
            local = ipaddress.ip_address(_endpoint(endpoint)[0]).is_loopback
        except ValueError:
            local = False
        if not local:
            raise ValueError("loopback source requires loopback endpoint")
    return str(address)


def _validate_spec(spec, now=None):
    if type(spec) is not dict or set(spec) != _FIELDS or type(spec["v"]) is not int or spec["v"] != 1:
        raise ValueError("fields")
    _endpoint(spec["endpoint"])
    _base64(spec["nonce"], 32)
    now = time.time() if now is None else now
    if type(spec["expires"]) is not int or spec["expires"] > now + 3600:
        raise ValueError("expiry")
    if spec["expires"] <= now:
        raise OperationError("direct_setup_expired", "Direct setup has expired. Prepare a fresh command on the desktop.")
    if spec["source"] != "auto":
        _source(spec["source"], spec["endpoint"])
    if not isinstance(spec["server_key"], str) or len(spec["server_key"]) > 4096:
        raise ValueError("transport key")
    key = serialization.load_pem_private_key(spec["server_key"].encode("ascii"), password=None)
    if (not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048
            or key.public_key().public_numbers().e != 65537):
        raise ValueError("transport RSA key")
    csr = CertificateAuthority.validate_csr(spec["csr"])
    client = csr.public_key()
    if (not isinstance(client, rsa.RSAPublicKey) or client.key_size != 2048
            or client.public_numbers() == key.public_key().public_numbers()):
        raise ValueError("distinct desktop RSA key")
    return spec


def parse_direct_setup_uri(uri, *, now=None) -> dict:
    """Validate bounded canonical v1 transport input without touching local state."""
    try:
        if not isinstance(uri, str) or len(uri.encode("utf-8")) > 4096 or not uri.startswith(_PREFIX):
            raise ValueError("URI")
        compressed = _base64(uri[len(_PREFIX):])
        inflater = zlib.decompressobj(-zlib.MAX_WBITS)
        raw = inflater.decompress(compressed, 8193)
        if len(raw) > 8192 or inflater.unconsumed_tail or not inflater.eof or inflater.unused_data:
            raise ValueError("bounded single DEFLATE stream")
        spec = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                          parse_constant=_reject_constant)
        return _validate_spec(spec, now)
    except OperationError as exc:
        if exc.code == "direct_setup_expired":
            raise
        raise _invalid() from None
    except (ValueError, TypeError, UnicodeError, RecursionError, zlib.error, OverflowError, UnsupportedAlgorithm):
        raise _invalid() from None


def resolve_desktop_source(spec) -> str:
    """Return an explicit literal or the unique active TCP RDP peer; never guess."""
    try:
        _endpoint(spec["endpoint"])
        if spec["source"] != "auto":
            return _source(spec["source"], spec["endpoint"])
        if os.name != "nt":
            raise ValueError("Windows required for RDP detection")
        import winreg
        import psutil
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp") as key:
            port = winreg.QueryValueEx(key, "PortNumber")[0]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("RDP listener port")
        peers = set()
        try:
            connections = psutil.net_connections(kind="tcp")
        except psutil.Error:
            raise ValueError("RDP connections unavailable") from None
        for connection in connections:
            if (connection.status != psutil.CONN_ESTABLISHED or not connection.laddr
                    or connection.laddr.port != port or not connection.raddr):
                continue
            candidate = ipaddress.ip_address(connection.raddr.ip)
            candidate = getattr(candidate, "ipv4_mapped", None) or candidate
            if not candidate.is_loopback:
                peers.add(_source(str(candidate), spec["endpoint"]))
        if len(peers) != 1:
            raise ValueError("no unique peer")
        return peers.pop()
    except (ValueError, TypeError, KeyError, OSError, ImportError, AttributeError):
        raise OperationError("direct_source_required", "Cannot identify one active RDP TCP desktop address. Prepare a new command with the desktop's explicit public source IP; allow that address in the provider firewall.") from None


def provision_direct_bootstrap(data_dir, spec) -> dict:
    """LOCAL ONLY: create fresh CA and approve exactly the pre-bound viewer CSR."""
    from .security import Security
    from .store import Store

    try:
        _validate_spec(spec)
        source = _source(spec["source"], spec["endpoint"])
        host, port = _endpoint(spec["endpoint"])
    except OperationError:
        raise
    except (ValueError, TypeError, UnicodeError, KeyError, UnsupportedAlgorithm):
        raise _invalid() from None
    data_dir = Path(data_dir)
    # An exclusive protected reservation survives partial failure. Retained state
    # requires local recovery, never an automatic retry that replaces identities.
    with identity_lock(data_dir):
        for relative in _RETAINED:
            path = data_dir / relative
            reject_links(path)
            if path.exists():
                raise OperationError("direct_state_exists", "Direct command installation requires fresh agent state. Use local maintenance for an existing installation.", 409)
        atomic_private_write(data_dir / _RECORD, protect_secret(b'{"reserved":true}').encode("ascii"))
    ca = CertificateAuthority(data_dir)
    info = ca.ensure(configured_hosts=[host], initial_server_key_pem=spec["server_key"])
    store = Store(data_dir)
    try:
        security = Security(store, ca)
        bundle = security.provision_viewer("Direct desktop", spec["csr"])
        record = {"v": 1, "agent_id": info["agent_id"], "endpoint": spec["endpoint"],
                  "fingerprint": info["fingerprint"], "nonce_digest": hashlib.sha256(spec["nonce"].encode("ascii")).hexdigest(),
                  "window_expires": spec["expires"], "device_id": bundle["device"]["id"],
                  "device_fingerprint": security.active_actor(bundle["device"]["id"])["fingerprint"],
                  "retired": False, "bundle": bundle}
        _write_record(data_dir, record)
    finally:
        store.close()
    return {"scope": "Direct", "host": "::" if ":" in host else "0.0.0.0", "port": port,
            "endpoint": spec["endpoint"], "remote_addresses": [source], "interfaces": []}


def _write_record(data_dir, record):
    atomic_private_write(Path(data_dir) / _RECORD,
                         protect_secret(json.dumps(record, separators=(",", ":")).encode("utf-8")).encode("ascii"))


def _read_record(data_dir):
    path = Path(data_dir) / _RECORD
    try:
        reject_links(path)
        if path.stat().st_size > 32768:
            raise ValueError("record size")
        protect_path(path)
        record = json.loads(unprotect_secret(path.read_text(encoding="ascii")))
        if type(record) is not dict or record.get("v") != 1:
            raise ValueError("record")
        return record
    except (OSError, ValueError, TypeError, OperationError):
        raise OperationError("direct_bootstrap_invalid", "Direct bootstrap is unavailable. Check the local installation or use local maintenance.", 403) from None


def direct_bootstrap(security, data_dir, nonce, *, actor=None, complete=False) -> dict:
    """Read an existing public bundle, or retire it for its actual mTLS device."""
    try:
        _base64(nonce, 32)
    except (ValueError, TypeError):
        raise OperationError("direct_bootstrap_invalid", "Invalid direct bootstrap request.", 403) from None
    # Serialize completion with reads and concurrent completion requests.
    with identity_lock(Path(data_dir)):
        record = _read_record(data_dir)
        try:
            digest = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            if not hmac.compare_digest(record["nonce_digest"], digest):
                raise ValueError("nonce")
            if type(record["window_expires"]) is not int:
                raise ValueError("window expiry")
            if not complete and record["window_expires"] <= time.time():
                raise OperationError("direct_bootstrap_expired", "The direct installation window has expired. Use local maintenance; retained identity was not changed.", 403)
            current = security.active_actor(record["device_id"])
            if current["role"] != "viewer" or not hmac.compare_digest(current["fingerprint"], record["device_fingerprint"]):
                raise ValueError("bound device")
            if current["agent_id"] != record["agent_id"]:
                raise ValueError("agent identity")
            if complete:
                if (not isinstance(actor, dict) or actor.get("id") != current["id"]
                        or not hmac.compare_digest(str(actor.get("fingerprint", "")), current["fingerprint"])):
                    raise OperationError("direct_device_mismatch", "Completion requires the original desktop's enrolled mTLS certificate.", 403)
                if not record["retired"]:
                    record["retired"] = True
                    record.pop("bundle", None)
                    _write_record(data_dir, record)
                return {"completed": True}
            if record["retired"]:
                raise ValueError("retired")
            bundle = record["bundle"]
            return {"v": 1, "agent_id": record["agent_id"], "endpoint": record["endpoint"],
                    "fingerprint": record["fingerprint"], "certificate": bundle["certificate"],
                    "ca_certificate": bundle["ca_certificate"], "device": bundle["device"], "expires": bundle["expires"]}
        except (ValueError, TypeError, KeyError):
            raise OperationError("direct_bootstrap_invalid", "Direct bootstrap is invalid or retired. Check the local installation.", 403) from None
