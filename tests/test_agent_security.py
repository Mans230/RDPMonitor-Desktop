"""Real certificates/DPAPI; tests never touch firewall, accounts or services."""
import hashlib
import ipaddress
import os
import socket
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent import certificates
from agent.certificates import CertificateAuthority, utcnow
from agent.contracts import CAPABILITIES, OperationError
from agent.security import Security
from agent.store import Store


def make_csr(*, key_size=2048, ca=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-caller-subject")]))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    csr = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode("ascii")
    return key, csr


def der(bundle):
    return x509.load_pem_x509_certificate(bundle["certificate"].encode()).public_bytes(serialization.Encoding.DER)


class SecretStoragePolicyTests(unittest.TestCase):
    def test_non_windows_secrets_do_not_fall_back_to_plaintext_or_base64(self):
        with mock.patch.object(certificates, "os", SimpleNamespace(name="posix")):
            with self.assertRaises(OperationError) as error:
                certificates.protect_secret(b"sensitive")
        self.assertEqual(error.exception.code, "secure_storage_unavailable")

    def test_unprotected_credential_formats_are_not_silently_accepted(self):
        for value in ("plain-password", "cGxhaW4tcGFzc3dvcmQ=", "", None):
            with self.subTest(value=value), self.assertRaises(OperationError):
                certificates.unprotect_secret(value)


@unittest.skipUnless(os.name == "nt", "Production certificate keys require actual Windows DPAPI.")
class AgentSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "agent"
        self.store = Store(self.directory)
        self.ca = CertificateAuthority(self.directory)
        self.security = Security(self.store, self.ca)
        self.key, self.csr = make_csr()

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def enroll(self, role="owner", name="Device"):
        challenge = self.security.begin_pairing(role=role)
        bundle = self.security.enroll(challenge["code"], name, self.csr)
        return self.security.authenticate(der(bundle)), bundle

    def test_ca_server_identity_and_protected_keys_are_real_and_persistent(self):
        info = self.ca.ensure()
        self.assertEqual(info["agent_id"], self.store.identity()["id"])
        certificate = x509.load_pem_x509_certificate(Path(info["certificate_path"]).read_bytes())
        self.assertEqual(certificate.fingerprint(hashes.SHA256()).hex(), info["fingerprint"])
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("localhost", names.get_values_for_type(x509.DNSName))
        self.assertIn(socket.gethostname().lower(), names.get_values_for_type(x509.DNSName))
        self.assertIn(ipaddress.ip_address("127.0.0.1"), names.get_values_for_type(x509.IPAddress))
        self.assertIn(ipaddress.ip_address("::1"), names.get_values_for_type(x509.IPAddress))
        self.assertIn(info["agent_id"] + ".rdpmonitor.invalid", names.get_values_for_type(x509.DNSName))
        from agent.service import verify_protected_tree
        verify_protected_tree(self.directory, ancestors=False)
        protected = (self.directory / "tls" / "ca.key.dpapi").read_bytes()
        self.assertTrue(protected.startswith(b"dpapi:"))
        self.assertNotIn(b"PRIVATE KEY", protected)
        self.assertEqual(CertificateAuthority(self.directory).ensure()["fingerprint"], info["fingerprint"])
        self.assertTrue(Path(info["key_path"]).exists())

    def test_worker_startup_preserves_gateway_descriptor_access_without_private_data_access(self):
        import win32security
        from agent.service import GATEWAY_METADATA_RIGHTS, gateway_sid

        def grants(path):
            descriptor = win32security.GetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION)
            acl = descriptor.GetSecurityDescriptorDacl()
            return {win32security.ConvertSidToStringSid(acl.GetAce(index)[2]): acl.GetAce(index)
                    for index in range(acl.GetAceCount())}

        sid = gateway_sid()
        self.ca.ensure()
        # Both a worker restart and local enrollment re-enter root hardening.
        CertificateAuthority(self.directory).ensure()
        self.store.identity()
        root_grant = grants(self.directory)[sid]
        self.assertEqual(root_grant[0], (win32security.ACCESS_ALLOWED_ACE_TYPE, 0))
        self.assertEqual(root_grant[1], GATEWAY_METADATA_RIGHTS)
        self.assertFalse(root_grant[1] & 0x3)  # No directory listing or file writes.
        for private in (self.directory / "identity.json", self.store.path,
                        self.directory / "tls", self.directory / "tls" / "ca.key.dpapi"):
            with self.subTest(path=private.name):
                self.assertNotIn(sid, grants(private))

    def test_remote_san_reissue_preserves_authority_and_enrolled_identity(self):
        actor, bundle = self.enroll()
        before = self.ca.ensure()
        public_ca = Path(before["ca_path"]).read_bytes()
        after = self.ca.ensure(configured_hosts=["agent.example.test", "192.0.2.45"])
        certificate = x509.load_pem_x509_certificate(Path(after["certificate_path"]).read_bytes())
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("agent.example.test", names.get_values_for_type(x509.DNSName))
        self.assertIn(ipaddress.ip_address("192.0.2.45"), names.get_values_for_type(x509.IPAddress))
        self.assertNotEqual(before["fingerprint"], after["fingerprint"])
        self.assertEqual(Path(after["ca_path"]).read_bytes(), public_ca)
        self.assertEqual(self.security.authenticate(der(bundle))["id"], actor["id"])
        self.assertEqual(CertificateAuthority(self.directory).ensure()["fingerprint"], after["fingerprint"])

    def test_pairing_is_local_role_approved_and_one_use_even_after_restart(self):
        challenge = self.security.begin_pairing(role="viewer")
        bundle = self.security.enroll(challenge["code"], "Viewer", self.csr, role="owner")
        self.assertEqual(bundle["device"]["role"], "viewer")
        actor = self.security.authenticate(der(bundle))
        self.security = Security(self.store, CertificateAuthority(self.directory))
        with self.assertRaises(OperationError) as error:
            self.security.enroll(challenge["code"], "Replay", self.csr)
        self.assertEqual(error.exception.code, "invalid_pairing")
        with self.assertRaises(OperationError):
            self.security.authorize({**actor, "role": "owner", "capabilities": list(CAPABILITIES)}, "manage")
        self.security.authorize(actor, "view")
        self.assertNotIn(challenge["code"].encode(), self.store.path.read_bytes())

    def test_simultaneous_pairing_replay_can_enroll_only_one_device(self):
        challenge = self.security.begin_pairing(role="operator")
        barrier = threading.Barrier(2)
        def enroll(number):
            barrier.wait()
            try:
                return self.security.enroll(challenge["code"], str(number), self.csr)["device"]["role"]
            except OperationError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(enroll, (1, 2)))
        self.assertCountEqual(results, ["operator", "invalid_pairing"])
        self.assertEqual(len(self.security.devices()), 1)

    def test_expired_pairing_and_invalid_csr_cannot_enroll(self):
        challenge = self.security.begin_pairing()
        with self.assertRaises(OperationError):
            self.security.enroll(challenge["code"], "Invalid CSR", "not a certificate request")
        # A malformed request did not consume the valid local approval.
        self.security.enroll(challenge["code"], "Valid CSR", self.csr)
        expired = self.security.begin_pairing()
        with self.store._transaction() as connection:
            connection.execute("UPDATE pairings SET expires='2000-01-01T00:00:00.000Z' WHERE digest=?",
                               (hashlib.sha256(expired["code"].encode()).hexdigest(),))
        with self.assertRaises(OperationError) as error:
            self.security.enroll(expired["code"], "Expired", self.csr)
        self.assertEqual(error.exception.code, "invalid_pairing")

    def test_weak_keys_and_ca_privileges_are_rejected(self):
        for options in ({"key_size": 1024}, {"ca": True}):
            _, csr = make_csr(**options)
            with self.subTest(options=options), self.assertRaises(OperationError) as error:
                self.ca.issue_client(csr, "42f07fe5-cb43-45b7-93b9-eb89a22daf8f")
            self.assertEqual(error.exception.code, "invalid_csr")

    def test_unenrolled_certificates_and_server_cert_cannot_authenticate(self):
        signed = self.ca.issue_client(self.csr, "42f07fe5-cb43-45b7-93b9-eb89a22daf8f")
        with self.assertRaises(OperationError):
            self.security.authenticate(der(signed))
        server = x509.load_pem_x509_certificate(Path(self.ca.ensure()["certificate_path"]).read_bytes())
        with self.assertRaises(OperationError):
            self.security.authenticate(server.public_bytes(serialization.Encoding.DER))

    def test_wrong_authority_and_expired_certificates_are_denied(self):
        actor, bundle = self.enroll()
        other = CertificateAuthority(Path(self.temporary.name) / "other")
        other.ensure()
        foreign = other.issue_client(self.csr, actor["id"])
        with self.assertRaises(OperationError):
            self.security.authenticate(der(foreign))
        now = utcnow()
        expired = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, actor["id"])]))
                   .issuer_name(self.ca._ca.subject).public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=2)).not_valid_after(now - timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
                   .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                   .sign(self.ca._key, hashes.SHA256()))
        with self.assertRaises(OperationError):
            self.security.authenticate(expired.public_bytes(serialization.Encoding.DER))

    def test_revocation_invalidates_cached_actor_certificate_and_confirmation(self):
        owner, _ = self.enroll()
        operator, bundle = self.enroll(role="operator", name="Operator")
        nonce = self.security.prepare(operator, "backup.create", {})["nonce"]
        self.security.revoke(operator["id"], owner)
        for action in (lambda: self.security.authorize(operator, "view"),
                       lambda: self.security.authenticate(der(bundle)),
                       lambda: self.security.active_actor(operator["id"]),
                       lambda: self.security.consume(operator, "backup.create", {}, nonce)):
            with self.assertRaises(OperationError):
                action()
        self.assertIsNotNone(next(item for item in self.security.devices() if item["id"] == operator["id"])["revoked"])

    def test_operator_and_viewer_presets_cannot_gain_privileged_capabilities(self):
        operator, _ = self.enroll(role="operator")
        viewer, _ = self.enroll(role="viewer")
        for capability in ("execute", "accounts", "security", "configure", "manage"):
            with self.subTest(capability=capability), self.assertRaises(OperationError):
                self.security.authorize({**operator, "role": "owner"}, capability)
        with self.assertRaises(OperationError):
            self.security.prepare(viewer, "backup.create", {})
        with self.assertRaises(OperationError):
            self.security.prepare(operator, "configuration.update", {"domain": "monitor", "revision": 0, "value": {}})

    def test_confirmation_binds_parameters_operation_principal_and_revision(self):
        owner, _ = self.enroll()
        other, _ = self.enroll(name="Other owner")
        args = {"pid": 123, "identity": "original-creation-time", "nested": {"b": 2, "a": 1}}
        nonce = self.security.prepare(owner, "process.stop", args)["nonce"]
        for actor, operation, changed in ((owner, "process.stop", {**args, "pid": 456}),
                                          (owner, "power.restart", args), (other, "process.stop", args)):
            with self.assertRaises(OperationError):
                self.security.consume(actor, operation, changed, nonce)
        self.security.consume(owner, "process.stop", {"nested": {"a": 1.0, "b": 2}, "identity": "original-creation-time", "pid": 123.0}, nonce)
        with self.assertRaises(OperationError):
            self.security.consume(owner, "process.stop", args, nonce)
        newer = self.security.prepare(owner, "process.stop", args)["nonce"]
        self.store.set_config("monitor", {"threshold": 90}, 0)
        with self.assertRaises(OperationError) as error:
            self.security.consume(owner, "process.stop", args, newer)
        self.assertEqual(error.exception.code, "confirmation_invalid")

    def test_concurrent_confirmation_consumers_have_one_winner(self):
        owner, _ = self.enroll()
        nonce = self.security.prepare(owner, "power.restart", {"delay": 30})["nonce"]
        barrier = threading.Barrier(2)
        def consume(_):
            barrier.wait()
            try:
                self.security.consume(owner, "power.restart", {"delay": 30}, nonce)
                return "consumed"
            except OperationError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(consume, (1, 2)))
        self.assertCountEqual(results, ["consumed", "confirmation_invalid"])

    def test_confirmation_expiry_is_durable_across_security_restart(self):
        owner, _ = self.enroll()
        nonce = self.security.prepare(owner, "power.shutdown", {})["nonce"]
        with self.store._transaction() as connection:
            connection.execute("UPDATE confirmations SET expires='2000-01-01T00:00:00.000Z'")
        self.security = Security(self.store, CertificateAuthority(self.directory))
        with self.assertRaises(OperationError) as error:
            self.security.consume(owner, "power.shutdown", {}, nonce)
        self.assertEqual(error.exception.code, "confirmation_invalid")

    def test_renewal_rotates_credential_without_role_escalation(self):
        viewer, old = self.enroll(role="viewer")
        _, new_csr = make_csr()
        replacement = self.security.renew(viewer, new_csr)
        current = self.security.authenticate(der(replacement))
        self.assertEqual(current["id"], viewer["id"])
        self.assertEqual(current["role"], "viewer")
        self.assertNotEqual(current["fingerprint"], viewer["fingerprint"])
        with self.assertRaises(OperationError):
            self.security.authenticate(der(old))
        with self.assertRaises(OperationError):
            self.security.authorize(viewer, "view")

    def test_security_mutations_fail_closed_when_audit_storage_fails(self):
        challenge = self.security.begin_pairing()
        with mock.patch.object(self.store, "_append_audit", side_effect=OSError("audit disk unavailable")):
            with self.assertRaises(OSError):
                self.security.enroll(challenge["code"], "Not committed", self.csr)
        self.assertEqual(self.security.devices(), [])
        committed = self.security.enroll(challenge["code"], "Committed", self.csr)
        self.assertEqual(len(self.security.devices()), 1)
        self.assertEqual(self.security.authenticate(der(committed))["role"], "owner")

    def test_copied_identity_is_rejected_when_machine_binding_changes(self):
        with mock.patch.object(self.ca, "_binding", return_value="another-machine"):
            with self.assertRaises(OperationError) as error:
                self.ca.ensure()
        self.assertEqual(error.exception.code, "cloned_identity")


if __name__ == "__main__":
    unittest.main()
