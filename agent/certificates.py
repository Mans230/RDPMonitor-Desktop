"""Windows-protected agent identity and a constrained, private mTLS CA.

Remote endpoint changes are local administration: call ensure(configured_hosts=[...])
with the complete approved DNS/IP set, restart TLS, then verify the new displayed
server fingerprint locally before updating client pins. The CA/device identities
remain unchanged. Copying state to another machine fails DPAPI/machine binding;
reinstallation must establish a new identity and enroll devices again.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import ipaddress
import json
import os
import socket
import stat
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from relay.protocol import agent_hostname

from .contracts import OperationError

UTC = timezone.utc
_ENTROPY = b"RDPMonitor/agent/credentials/v1"
_ID_LOCK = threading.RLock()


def utcnow() -> datetime:
    return datetime.now(UTC)


def timestamp(value: datetime | None = None) -> str:
    return (value or utcnow()).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def reject_links(path: Path) -> None:
    """Reject junctions/reparse points as well as symlinks, including ancestors."""
    path = Path(os.path.abspath(path))
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise OperationError("unsafe_state_path", "State paths cannot contain links or reparse points.", 500)


def protect_path(path: Path, *, gateway_metadata: bool = False) -> None:
    """Replace, rather than merge, ACLs; fail closed on hardening failure.

    Elevated Windows state is Administrators-owned and writable only by SYSTEM
    and Administrators, matching service startup verification. Unelevated local
    evaluation also retains its current principal. POSIX modes are not a secret store.
    """
    path = Path(path)
    reject_links(path)
    if os.name != "nt":
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
        info = path.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise OperationError("state_permissions", "Cannot protect the agent state path.", 500)
        return
    try:
        import ntsecuritycon
        import win32api
        import win32con
        import win32security
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            current = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        finally:
            token.Close()
        administrators = win32security.ConvertStringSidToSid("S-1-5-32-544")
        current_sid = win32security.ConvertSidToStringSid(current)
        elevated = current_sid == "S-1-5-18" or win32security.CheckTokenMembership(None, administrators)
        sids = {sid: win32security.ConvertStringSidToSid(sid) for sid in ("S-1-5-18", "S-1-5-32-544")}
        if not elevated:
            sids[current_sid] = current
        acl = win32security.ACL()
        flags = 3 if path.is_dir() else 0
        for sid in sids.values():
            acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, flags, ntsecuritycon.FILE_ALL_ACCESS, sid)
        metadata_sid = None
        if elevated and gateway_metadata:
            from .service import GATEWAY_METADATA_RIGHTS, gateway_sid
            metadata_sid = gateway_sid()
            acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, 0, GATEWAY_METADATA_RIGHTS,
                                     win32security.ConvertStringSidToSid(metadata_sid))
        information = win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION
        if elevated:
            information |= win32security.OWNER_SECURITY_INFORMATION
        win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, information,
                                          administrators if elevated else None, None, acl, None)
        descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
        if elevated and win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) != "S-1-5-32-544":
            raise ValueError("unexpected owner")
        actual = descriptor.GetSecurityDescriptorDacl()
        if actual is None or actual.GetAceCount() != len(sids) + (metadata_sid is not None):
            raise ValueError("unexpected ACL")
        for index in range(actual.GetAceCount()):
            ace = actual.GetAce(index)
            sid = win32security.ConvertSidToStringSid(ace[2])
            if sid == metadata_sid:
                if ace[0] != (0, 0) or ace[1] != GATEWAY_METADATA_RIGHTS:
                    raise ValueError("unexpected gateway metadata grant")
            elif ace[0][0] != 0 or ace[1] != ntsecuritycon.FILE_ALL_ACCESS or sid not in sids:
                raise ValueError("unexpected ACL entry")
        if not descriptor.GetSecurityDescriptorControl()[0] & 0x1000:
            raise ValueError("unprotected ACL")
    except Exception as exc:
        raise OperationError("state_permissions", "Cannot establish protected Windows state permissions.", 500) from exc


def protected_directory(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    reject_links(path)
    # Harden the parent before creating any secret-bearing children.
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    protect_path(path)
    return path


def protected_data_directory(path: Path) -> Path:
    """Private root with noninheriting gateway descriptor/traverse access only."""
    path = Path(os.path.abspath(path))
    reject_links(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    protect_path(path, gateway_metadata=True)
    return path


def _dpapi(data: bytes, decrypt: bool = False) -> bytes:
    if os.name != "nt":
        raise OperationError("secure_storage_unavailable", "Windows DPAPI is required for agent credentials; plaintext fallback is disabled.", 500)
    class Blob(ctypes.Structure):
        _fields_ = [("size", ctypes.c_ulong), ("data", ctypes.POINTER(ctypes.c_ubyte))]
    def blob(value):
        buffer = ctypes.create_string_buffer(value)
        return Blob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer
    source, source_buffer = blob(data)
    entropy, entropy_buffer = blob(_ENTROPY)
    result = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob), ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(Blob)]
    function.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    # Machine scope permits the installed worker identity to recover after a
    # service-account change; the verified ACL is the local-user boundary.
    flags = 1 if decrypt else 5
    if not function(ctypes.byref(source), None, ctypes.byref(entropy), None, None, flags, ctypes.byref(result)):
        raise OperationError("credential_unavailable", "Protected credentials are unavailable on this machine.", 500)
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        kernel.LocalFree(result.data)


def protect_secret(data: bytes) -> str:
    return "dpapi:" + base64.b64encode(_dpapi(data)).decode("ascii")


def unprotect_secret(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("dpapi:"):
        raise OperationError("credential_format", "Unprotected credential state is not accepted.", 500)
    try:
        return _dpapi(base64.b64decode(value[6:], validate=True), decrypt=True)
    except (ValueError, TypeError) as exc:
        raise OperationError("credential_format", "Protected credential state is invalid.", 500) from exc


def atomic_private_write(path: Path, content: bytes) -> None:
    reject_links(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            protect_path(temporary)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        protect_path(path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def identity_lock(data_dir: Path):
    """Serialize local CLI/worker identity changes across processes."""
    directory = protected_data_directory(data_dir)
    path = directory / ".identity.lock"
    reject_links(path)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
    try:
        protect_path(path)
        if os.name == "nt":
            import msvcrt
            import time
            deadline = time.monotonic() + 30
            while True:
                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    break
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise OperationError("identity_busy", "Local identity administration is busy; retry shortly.", 503) from exc
                    time.sleep(0.05)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def agent_identity(data_dir: Path) -> dict:
    with _ID_LOCK, identity_lock(data_dir):
        directory = protected_data_directory(data_dir)
        path = directory / "identity.json"
        reject_links(path)
        if not path.exists():
            value = {"id": str(uuid.uuid4()), "name": socket.gethostname(), "created": timestamp()}
            # Exclusive creation also protects against separate local CLI processes.
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    protect_path(path)
                    json.dump(value, stream, ensure_ascii=False)
                    stream.flush()
                    os.fsync(stream.fileno())
        protect_path(path)
        value = json.loads(path.read_text(encoding="utf-8"))
        uuid.UUID(value["id"])
        return value


def certificate_time(certificate, field: str) -> datetime:
    modern = getattr(certificate, field + "_utc", None)
    return modern if modern is not None else getattr(certificate, field).replace(tzinfo=UTC)


def verify_signature(certificate: x509.Certificate, issuer: x509.Certificate) -> None:
    if certificate.issuer != issuer.subject:
        raise OperationError("invalid_certificate", "Certificate issuer is not trusted.", 401)
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes, padding.PKCS1v15(), certificate.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(certificate.signature_hash_algorithm))
        else:
            raise ValueError("issuer algorithm")
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise OperationError("invalid_certificate", "Certificate signature is not trusted.", 401) from exc


class CertificateAuthority:
    def __init__(self, data_dir: Path):
        self.data_dir = protected_data_directory(data_dir)
        self.directory = protected_directory(self.data_dir / "tls")
        self._lock = threading.RLock()
        self._ca = None
        self._key = None
        self._info = None

    def _binding(self) -> str:
        if os.name != "nt":
            raise OperationError("secure_storage_unavailable", "The agent certificate authority requires Windows protected storage.", 500)
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            machine = winreg.QueryValueEx(key, "MachineGuid")[0]
        return hashlib.sha256(str(machine).encode("utf-8")).hexdigest()

    def ensure(self, configured_hosts: list[str] | None = None) -> dict:
        """Return stable public TLS paths/identity, reissuing a server near expiry.

        An explicit configured_hosts list replaces the locally approved extra
        SANs; None retains the persisted set. Caller must be local administration.
        """
        with self._lock:
            # agent_identity takes the same cross-process lock independently;
            # release it before taking the certificate administration lock.
            identity = agent_identity(self.data_dir)
            return self._ensure_locked(identity, configured_hosts)

    def _ensure_locked(self, identity, configured_hosts):
        with identity_lock(self.data_dir):
            binding = self._binding()
            ca_path = self.directory / "ca.pem"
            private_path = self.directory / "ca.key.dpapi"
            metadata_path = self.directory / "authority.json"
            for path in (ca_path, private_path, metadata_path):
                reject_links(path)
            present = [path.exists() for path in (ca_path, private_path, metadata_path)]
            if any(present) and not all(present):
                raise OperationError("ca_incomplete", "Certificate authority state is incomplete; restore protected state or explicitly re-enroll.", 500)
            if not any(present):
                key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                now = utcnow()
                subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RDPMonitor CA " + identity["id"])])
                ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                      .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                      .not_valid_after(now + timedelta(days=3650))
                      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                      .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                      .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                      .sign(key, hashes.SHA256()))
                protected = protect_secret(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                             serialization.NoEncryption()))
                atomic_private_write(private_path, protected.encode("ascii"))
                atomic_private_write(ca_path, ca.public_bytes(serialization.Encoding.PEM))
                atomic_private_write(metadata_path, json.dumps({"agent_id": identity["id"], "machine": binding, "hosts": []}).encode())
            for path in (ca_path, private_path, metadata_path):
                protect_path(path)
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata.get("machine") != binding or metadata.get("agent_id") != identity["id"]:
                raise OperationError("cloned_identity", "Agent identity belongs to another installation; establish a fresh local identity and re-enroll devices.", 500)
            ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
            key = serialization.load_pem_private_key(unprotect_secret(private_path.read_text(encoding="ascii")), password=None)
            verify_signature(ca, ca)
            if key.public_key().public_numbers() != ca.public_key().public_numbers() or not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise OperationError("ca_invalid", "Certificate authority key and identity do not match.", 500)
            if not certificate_time(ca, "not_valid_before") <= utcnow() < certificate_time(ca, "not_valid_after"):
                raise OperationError("ca_expired", "The local authority has expired; local identity recovery and device enrollment are required.", 500)
            extras = metadata.get("hosts", []) if configured_hosts is None else configured_hosts
            if not isinstance(extras, list) or len(extras) > 64 or any(not isinstance(host, str) for host in extras):
                raise OperationError("invalid_hosts", "Provide at most 64 approved DNS or IP names.")
            hosts = {"localhost", "127.0.0.1", "::1", socket.gethostname(), socket.getfqdn(),
                     agent_hostname(identity["id"]), *extras}
            sans = []
            for host in sorted(hosts):
                if not host or len(host) > 253 or any(char.isspace() for char in host) or "*" in host:
                    raise OperationError("invalid_hosts", "Server certificate names must be exact DNS names or IP addresses.")
                try:
                    sans.append(x509.IPAddress(ipaddress.ip_address(host)))
                except ValueError:
                    encoded = host.rstrip(".").encode("idna").decode("ascii").lower()
                    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") or
                           any(not (char.isalnum() or char == "-") for char in label) for label in encoded.split(".")):
                        raise OperationError("invalid_hosts", "Invalid server certificate DNS name.")
                    sans.append(x509.DNSName(encoded))
            server_path, server_key_path = self.directory / "server.pem", self.directory / "server.key"
            for path in (server_path, server_key_path):
                reject_links(path)
            renew = not (server_path.exists() and server_key_path.exists())
            if not renew:
                try:
                    server = x509.load_pem_x509_certificate(server_path.read_bytes())
                    verify_signature(server, ca)
                    existing_key = serialization.load_pem_private_key(server_key_path.read_bytes(), password=None)
                    renew = (set(server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) != set(sans)
                             or certificate_time(server, "not_valid_after") < utcnow() + timedelta(days=30)
                             or certificate_time(server, "not_valid_before") > utcnow()
                             or existing_key.public_key().public_numbers() != server.public_key().public_numbers())
                except (ValueError, OperationError, x509.ExtensionNotFound):
                    renew = True
            if renew:
                server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                now = utcnow()
                server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity["id"])]))
                          .issuer_name(ca.subject).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
                          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(min(now + timedelta(days=365), certificate_time(ca, "not_valid_after")))
                          .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                          .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                          .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
                          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
                          .sign(key, hashes.SHA256()))
                atomic_private_write(server_key_path, server_key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                atomic_private_write(server_path, server.public_bytes(serialization.Encoding.PEM))
            protect_path(server_path)
            protect_path(server_key_path)
            metadata["hosts"] = extras
            atomic_private_write(metadata_path, json.dumps(metadata).encode())
            self._ca, self._key = ca, key
            self._info = {"agent_id": identity["id"], "certificate_path": str(server_path), "key_path": str(server_key_path),
                          "ca_path": str(ca_path), "fingerprint": server.fingerprint(hashes.SHA256()).hex()}
            return dict(self._info)

    def validate_csr(self, csr_pem: str) -> x509.CertificateSigningRequest:
        if not isinstance(csr_pem, str) or len(csr_pem.encode("utf-8")) > 32768:
            raise OperationError("invalid_csr", "A bounded PEM certificate signing request is required.")
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
            if not csr.is_signature_valid or csr.signature_hash_algorithm.name not in {"sha256", "sha384", "sha512"}:
                raise ValueError("CSR signature")
            key = csr.public_key()
            if isinstance(key, rsa.RSAPublicKey):
                if not 2048 <= key.key_size <= 8192 or key.public_numbers().e != 65537:
                    raise ValueError("RSA key")
            elif isinstance(key, ec.EllipticCurvePublicKey):
                if key.curve.name not in {"secp256r1", "secp384r1", "secp521r1"}:
                    raise ValueError("EC key")
            else:
                raise ValueError("key algorithm")
            # Never honor requested CA/server privileges or arbitrary SANs. The
            # issued subject and client-only extensions are entirely agent-owned.
            for extension in csr.extensions:
                if isinstance(extension.value, x509.BasicConstraints) and extension.value.ca:
                    raise ValueError("CA request")
                if isinstance(extension.value, x509.KeyUsage) and (extension.value.key_cert_sign or extension.value.crl_sign):
                    raise ValueError("CA key usage")
                if isinstance(extension.value, x509.ExtendedKeyUsage) and any(oid != ExtendedKeyUsageOID.CLIENT_AUTH for oid in extension.value):
                    raise ValueError("server key usage")
                if extension.critical and not isinstance(extension.value, (x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage, x509.SubjectAlternativeName)):
                    raise ValueError("unknown critical extension")
            return csr
        except (ValueError, TypeError, UnicodeError, x509.DuplicateExtension) as exc:
            raise OperationError("invalid_csr", "The CSR must have a valid SHA-256-or-stronger signature and an approved client key.") from exc

    def issue_client(self, csr_pem: str, device_id: str) -> dict:
        csr = self.validate_csr(csr_pem)
        try:
            uuid.UUID(device_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise OperationError("invalid_device", "A valid device identity is required.") from exc
        with self._lock:
            if self._ca is None:
                self.ensure()
            now = utcnow()
            expires = min(now + timedelta(days=90), certificate_time(self._ca, "not_valid_after"))
            if expires <= now + timedelta(days=1):
                raise OperationError("ca_expiring", "The authority requires local recovery before new enrollment.", 409)
            certificate = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
                           .issuer_name(self._ca.subject).public_key(csr.public_key()).serial_number(x509.random_serial_number())
                           .not_valid_before(now - timedelta(minutes=1)).not_valid_after(expires)
                           .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
                           .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()), critical=False)
                           .sign(self._key, hashes.SHA256()))
            return {"certificate": certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                    "ca_certificate": self._ca.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                    "expires": timestamp(expires), "fingerprint": certificate.fingerprint(hashes.SHA256()).hex()}

    def verify_client(self, peer_der: bytes) -> x509.Certificate:
        if not isinstance(peer_der, bytes) or not 1 <= len(peer_der) <= 16384:
            raise OperationError("client_certificate_required", "An enrolled client certificate is required.", 401)
        if self._ca is None:
            self.ensure()
        try:
            certificate = x509.load_der_x509_certificate(peer_der)
            verify_signature(certificate, self._ca)
            now = utcnow()
            if not certificate_time(certificate, "not_valid_before") <= now < certificate_time(certificate, "not_valid_after"):
                raise ValueError("expired")
            if not certificate_time(self._ca, "not_valid_before") <= now < certificate_time(self._ca, "not_valid_after"):
                raise ValueError("expired issuer")
            if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("CA cannot authenticate")
            usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if set(usage) != {ExtendedKeyUsageOID.CLIENT_AUTH}:
                raise ValueError("client EKU")
            key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
            if not key_usage.digital_signature or key_usage.key_cert_sign or key_usage.crl_sign:
                raise ValueError("key usage")
            return certificate
        except (ValueError, TypeError, x509.ExtensionNotFound, x509.DuplicateExtension) as exc:
            raise OperationError("invalid_certificate", "The client certificate is invalid or expired.", 401) from exc
