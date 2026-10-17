"""Direct installation boundaries; no accounts, services, firewall or trust-store changes."""
import base64
import json
import os
import ssl
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agent import certificates, direct
from agent.api import create_app
from agent.certificates import CertificateAuthority, atomic_private_write
from agent.contracts import OperationError
from agent.ipc import IntegratedProxy
from agent.runtime import AgentRuntime
from agent.security import Security
from agent.store import Store


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")


def identity():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Desktop")])).sign(key, hashes.SHA256()))
    return key, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def uri(raw, *, compressed=False):
    if not compressed:
        encoder = zlib.compressobj(wbits=-15)
        raw = encoder.compress(raw) + encoder.flush()
    return "rdpmonitor://direct?v=1#" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def spec(csr, transport, *, now=None):
    return {"v": 1, "endpoint": "https://127.0.0.1:8443", "server_key": pem(transport),
            "csr": csr, "nonce": base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode(),
            "expires": int(time.time() if now is None else now) + 1800, "source": "127.0.0.1"}


class DirectInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_key, cls.csr = identity()
        cls.transport, _ = identity()
        cls.intent = spec(cls.csr, cls.transport, now=2_000_000_000)

    def parse(self, intent):
        return direct.parse_direct_setup_uri(uri(json.dumps(intent, separators=(",", ":")).encode()), now=2_000_000_000)

    def test_valid_parser_and_explicit_source_have_no_state_side_effects(self):
        with mock.patch.object(certificates, "protected_data_directory", side_effect=AssertionError("filesystem mutation")):
            self.assertEqual(self.parse(self.intent), self.intent)
            self.assertEqual(direct.resolve_desktop_source(self.intent), "127.0.0.1")

    def test_uri_and_inflation_limits_and_ambiguous_json_fail_closed(self):
        raw = json.dumps(self.intent, separators=(",", ":")).encode()
        encoder = zlib.compressobj(wbits=-15)
        compressed = encoder.compress(raw) + encoder.flush()
        candidates = [uri(b" " * 8193), uri(compressed + compressed, compressed=True),
                      uri(compressed + b"trailing", compressed=True), uri(raw) + "=",
                      uri(raw.replace(b'"v":1', b'"v":1,"v":1', 1)),
                      uri(raw).replace("?v=1#", "?v=1&extra=yes#"),
                      uri(raw).replace("//direct", "//user@direct"),
                      uri(raw).replace("//direct?", "//direct/?"),
                      uri(raw) + "A" * 4096]
        for value in candidates:
            with self.subTest(kind=value[:40]), self.assertRaises(OperationError):
                direct.parse_direct_setup_uri(value, now=2_000_000_000)

    def test_exact_schema_canonical_origins_and_distinct_keys_are_required(self):
        cases = [{**self.intent, "v": True}, {**self.intent, "expires": True},
                 {**self.intent, "expires": 2_000_003_601}, {**self.intent, "unknown": "field"},
                 {**self.intent, "server_key": pem(self.client_key)},
                 {**self.intent, "nonce": self.intent["nonce"][:-1] + "_"}]
        for endpoint in ("http://127.0.0.1:8443", "https://127.0.0.1:443", "https://127.0.0.1:8443/",
                         "https://user@127.0.0.1:8443", "https://EXAMPLE.test:8443", "https://example.test:08443",
                         "https://[::]:8443", "https://example.test:8443#fragment"):
            cases.append({**self.intent, "endpoint": endpoint})
        for candidate in cases:
            with self.subTest(fields=set(candidate)), self.assertRaises(OperationError):
                self.parse(candidate)
        with self.assertRaises(OperationError) as error:
            self.parse({**self.intent, "expires": 2_000_000_000})
        self.assertEqual(error.exception.code, "direct_setup_expired")

    def test_sources_are_single_literals_and_auto_requires_one_real_rdp_peer(self):
        for source in ("Any", "0.0.0.0", "192.0.2.0/24", "desktop.example", "192.0.2.1,192.0.2.2", "::ffff:192.0.2.1"):
            with self.subTest(source=source), self.assertRaises(OperationError):
                direct.resolve_desktop_source({**self.intent, "source": source})
        with self.assertRaises(OperationError):
            direct.resolve_desktop_source({**self.intent, "endpoint": "https://192.0.2.9:8443"})
        registry = SimpleNamespace(HKEY_LOCAL_MACHINE=object(), OpenKey=mock.MagicMock(),
                                   QueryValueEx=mock.Mock(return_value=(3399, 4)))
        def peer(ip, port=3399, status="ESTABLISHED"):
            return SimpleNamespace(status=status, laddr=SimpleNamespace(port=port), raddr=SimpleNamespace(ip=ip))
        psutil = SimpleNamespace(CONN_ESTABLISHED="ESTABLISHED", Error=RuntimeError, net_connections=mock.Mock())
        intent = {**self.intent, "source": "auto"}
        with mock.patch.object(direct, "os", SimpleNamespace(name="nt")), \
                mock.patch.dict("sys.modules", {"winreg": registry, "psutil": psutil}):
            psutil.net_connections.return_value = [peer("192.0.2.2"), peer("192.0.2.2"), peer("127.0.0.1"), peer("192.0.2.8", port=3389)]
            self.assertEqual(direct.resolve_desktop_source(intent), "192.0.2.2")
            for peers in ([], [peer("192.0.2.2"), peer("192.0.2.3")], [peer("127.0.0.1")]):
                psutil.net_connections.return_value = peers
                with self.assertRaises(OperationError) as error:
                    direct.resolve_desktop_source(intent)
                self.assertEqual(error.exception.code, "direct_source_required")
            psutil.net_connections.side_effect = RuntimeError("access denied")
            with self.assertRaises(OperationError) as error:
                direct.resolve_desktop_source(intent)
            self.assertEqual(error.exception.code, "direct_source_required")


@unittest.skipUnless(os.name == "nt", "Real Windows DPAPI protects direct installation state")
class DirectProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "agent"
        self.client_key, csr = identity()
        self.transport, _ = identity()
        self.intent = spec(csr, self.transport)

    def provision(self):
        networking = direct.provision_direct_bootstrap(self.directory, self.intent)
        self.store = Store(self.directory)
        self.addCleanup(self.store.close)
        self.ca = CertificateAuthority(self.directory)
        self.security = Security(self.store, self.ca)
        runtime = AgentRuntime.__new__(AgentRuntime)
        runtime.data_dir, runtime.security = self.directory, self.security
        self.proxy = IntegratedProxy(runtime)
        return networking

    def bootstrap(self):
        return self.proxy.rpc("direct.bootstrap", {"nonce": self.intent["nonce"]})

    def test_fresh_provisioning_pins_transport_keeps_private_ca_and_issues_only_one_viewer(self):
        self.assertEqual(self.provision(), {"scope": "Direct", "host": "0.0.0.0", "port": 8443,
                         "endpoint": self.intent["endpoint"], "remote_addresses": ["127.0.0.1"], "interfaces": []})
        info = self.ca.ensure()
        server = x509.load_pem_x509_certificate(Path(info["certificate_path"]).read_bytes())
        self.assertEqual(server.public_key().public_numbers(), self.transport.public_key().public_numbers())
        self.assertEqual(CertificateAuthority(self.directory).ensure()["fingerprint"], info["fingerprint"])
        bundle = self.bootstrap()
        self.assertEqual(set(bundle), {"v", "agent_id", "endpoint", "fingerprint", "certificate", "ca_certificate", "device", "expires"})
        self.assertEqual(bundle["device"]["role"], "viewer")
        issued = x509.load_pem_x509_certificate(bundle["certificate"].encode())
        self.assertEqual(bundle["expires"], certificates.timestamp(issued.not_valid_after_utc))
        self.assertEqual(issued.public_key().public_numbers(), self.client_key.public_key().public_numbers())
        self.assertNotIn("PRIVATE KEY", json.dumps(bundle))
        self.assertNotIn(self.intent["nonce"].encode(), (self.directory / "direct-bootstrap.json").read_bytes())
        self.assertTrue((self.directory / "tls/ca.key.dpapi").read_bytes().startswith(b"dpapi:"))
        with self.store._transaction(False) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM pairings").fetchone()[0], 0)
        self.assertEqual(len(self.security.devices()), 1)
        self.assertEqual(self.bootstrap(), bundle)
        before = Path(info["key_path"]).read_bytes()
        with self.assertRaises(OperationError):
            self.ca.ensure(initial_server_key_pem=pem(self.client_key))
        self.assertEqual(Path(info["key_path"]).read_bytes(), before)

    def test_nonce_and_public_bundle_do_not_authorize_another_csr_or_tls_key(self):
        self.provision()
        bundle = self.bootstrap()
        attacker_key, attacker_csr = identity()
        for method, params in (("direct.bootstrap", {"nonce": self.intent["nonce"], "csr": attacker_csr}),
                               ("direct.complete", {"nonce": self.intent["nonce"]}),
                               ("direct.provision", {"csr": attacker_csr}),
                               ("pairing.enroll", {"code": self.intent["nonce"], "name": "Attacker", "csr": attacker_csr})):
            with self.subTest(method=method), self.assertRaises(OperationError):
                self.proxy.rpc(method, params)
        certificate_path = self.directory / "stolen-public.pem"
        wrong_key_path = self.directory / "wrong-private.key"
        atomic_private_write(certificate_path, bundle["certificate"].encode())
        atomic_private_write(wrong_key_path, pem(attacker_key).encode())
        context = ssl.create_default_context(cadata=bundle["ca_certificate"])
        with self.assertRaises(ssl.SSLError):
            context.load_cert_chain(str(certificate_path), str(wrong_key_path))
        self.assertEqual(len(self.security.devices()), 1)

    def test_actual_mtls_bound_completion_retires_publication_and_is_idempotent(self):
        self.provision()
        bundle = self.bootstrap()
        cert_path, key_path = self.directory / "desktop.pem", self.directory / "desktop.key"
        atomic_private_write(cert_path, bundle["certificate"].encode())
        atomic_private_write(key_path, pem(self.client_key).encode())
        client = ssl.create_default_context(cadata=bundle["ca_certificate"])
        client.load_cert_chain(str(cert_path), str(key_path))
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        info = self.ca.ensure()
        server.load_cert_chain(info["certificate_path"], info["key_path"])
        server.load_verify_locations(cadata=bundle["ca_certificate"])
        server.verify_mode = ssl.CERT_REQUIRED
        client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
        c = client.wrap_bio(client_in, client_out, server_hostname="127.0.0.1")
        s = server.wrap_bio(server_in, server_out, server_side=True)
        completed = set()
        for _ in range(20):
            for name, connection in (("client", c), ("server", s)):
                if name not in completed:
                    try:
                        connection.do_handshake()
                        completed.add(name)
                    except ssl.SSLWantReadError:
                        pass
            for incoming, outgoing in ((server_in, client_out), (client_in, server_out)):
                if outgoing.pending:
                    incoming.write(outgoing.read())
            if len(completed) == 2:
                break
        self.assertEqual(completed, {"client", "server"})
        peer = s.getpeercert(binary_form=True)
        # A different genuinely enrolled device is still not the bound desktop.
        _, other_csr = identity()
        other = self.security.provision_viewer("Other local viewer", other_csr)
        other_der = x509.load_pem_x509_certificate(other["certificate"].encode()).public_bytes(serialization.Encoding.DER)
        with self.assertRaises(OperationError) as error:
            self.proxy.rpc("direct.complete", {"nonce": self.intent["nonce"]}, peer_der=other_der)
        self.assertEqual(error.exception.code, "direct_device_mismatch")
        # Issued credentials can be saved after the setup window has elapsed.
        # Their authenticated completion must still retire publication and retry.
        with mock.patch.object(direct.time, "time", return_value=self.intent["expires"] + 1):
            for _ in range(2):
                self.assertEqual(self.proxy.rpc("direct.complete", {"nonce": self.intent["nonce"]}, peer_der=peer), {"completed": True})
        with self.assertRaises(OperationError):
            self.bootstrap()
        self.assertEqual(len(self.security.devices()), 2)

    def test_wrong_nonce_expiry_and_revocation_close_publication(self):
        self.provision()
        bundle = self.bootstrap()
        with self.assertRaises(OperationError):
            self.proxy.rpc("direct.bootstrap", {"nonce": "A" * 43})
        with mock.patch.object(direct.time, "time", return_value=self.intent["expires"]):
            with self.assertRaises(OperationError) as error:
                self.bootstrap()
            self.assertEqual(error.exception.code, "direct_bootstrap_expired")
        with self.store._transaction() as connection:
            connection.execute("UPDATE devices SET revoked=? WHERE id=?", ("2020-01-01T00:00:00Z", bundle["device"]["id"]))
        with self.assertRaises(OperationError) as error:
            self.bootstrap()
        self.assertEqual(error.exception.code, "device_revoked")

    def test_retained_and_partial_state_are_never_overwritten(self):
        for relative in ("identity.json", "tls", "state.sqlite3", "deployment.json", "direct-bootstrap.json", "gateway/relay.json"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "agent"
                path = root / relative
                path.parent.mkdir(parents=True)
                if relative == "tls":
                    path.mkdir()
                else:
                    path.write_bytes(b"retained-user-state")
                with self.assertRaises(OperationError) as error:
                    direct.provision_direct_bootstrap(root, self.intent)
                self.assertEqual(error.exception.code, "direct_state_exists")
                if relative != "tls":
                    self.assertEqual(path.read_bytes(), b"retained-user-state")


class DirectApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_direct_bodies_are_bounded_exact_and_complete_requires_transport_certificate(self):
        proxy = SimpleNamespace(rpc=mock.Mock(return_value={"public": True}))
        app = create_app(proxy)
        async def tls_scope(scope, receive, send):
            scope["rdpmonitor.tls"] = True
            await app(scope, receive, send)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=tls_scope), base_url="https://agent.test") as client:
            for body in ('{"nonce":"' + "A" * 43 + '","csr":"forbidden"}',
                         '{"nonce":"' + "A" * 43 + '","nonce":"' + "A" * 43 + '"}',
                         '{"nonce":42}'):
                self.assertEqual((await client.post("/api/v1/direct/bootstrap", content=body)).status_code, 422)
            response = await client.post("/api/v1/direct/bootstrap", content=b" " * 257)
            self.assertEqual(response.status_code, 413)
            proxy.rpc.assert_not_called()
            response = await client.post("/api/v1/direct/bootstrap", json={"nonce": "A" * 43})
            self.assertEqual(response.status_code, 200)
            proxy.rpc.assert_called_once_with("direct.bootstrap", {"nonce": "A" * 43}, peer_der=None)
            proxy.rpc.reset_mock()
            response = await client.post("/api/v1/direct/complete", json={"nonce": "A" * 43})
            self.assertEqual(response.status_code, 401)
            proxy.rpc.assert_not_called()
