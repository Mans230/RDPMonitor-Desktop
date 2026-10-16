import tempfile
import unittest
import time
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agent.contracts import OperationError
from agent.runtime import AgentRuntime


ROOT = Path(__file__).resolve().parents[1]


class AgentAdmissionTests(unittest.TestCase):
    """Real persistence/enrollment and admission; never start host operations."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime = AgentRuntime(ROOT, Path(self.temporary.name))
        self.addCleanup(self.runtime.store.close)
        self.owner = self.enroll("Owner", "owner")

    def enroll(self, name, role):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        ).sign(key, hashes.SHA256())
        challenge = self.runtime.security.begin_pairing(role=role)
        bundle = self.runtime.security.enroll(
            challenge["code"], name, csr.public_bytes(serialization.Encoding.PEM).decode()
        )
        certificate = x509.load_pem_x509_certificate(bundle["certificate"].encode())
        return self.runtime.security.authenticate(certificate.public_bytes(serialization.Encoding.DER))

    def prepare_restart(self, actor, args):
        return self.runtime.rpc("confirmations.prepare", {"operation": "power.restart", "args": args}, actor)["nonce"]

    def test_one_worker_owns_installation_until_lock_is_released(self):
        other = AgentRuntime(ROOT, Path(self.temporary.name))
        try:
            self.runtime._acquire_worker_lock()
            with self.assertRaises(OperationError) as conflict:
                other._acquire_worker_lock()
            self.assertEqual(conflict.exception.code, "worker_already_running")
            self.runtime._release_worker_lock()
            other._acquire_worker_lock()
        finally:
            self.runtime._release_worker_lock()
            other._release_worker_lock()
            other.store.close()

    def test_snapshot_before_first_sample_reports_unavailable(self):
        with self.assertRaises(OperationError) as unavailable:
            self.runtime.rpc("snapshot", {}, self.owner)
        self.assertEqual(unavailable.exception.code, "telemetry_unavailable")
        self.assertEqual(unavailable.exception.status, 503)

    def test_collector_failure_retains_last_good_sample_with_stale_error(self):
        sample = self.runtime.backend.snapshot()
        self.runtime.store.append_metric(sample)
        with patch.object(self.runtime.backend, "snapshot", side_effect=OSError("collector unavailable")), \
             patch.object(self.runtime._stop, "wait", side_effect=lambda _: self.runtime._stop.set()), \
             self.assertLogs("agent.runtime", level="ERROR"):
            self.runtime._sample()
            stale = self.runtime.rpc("snapshot", {}, self.owner)
        self.assertEqual(stale["ts"], sample["ts"])
        self.assertEqual(stale["cpu"], sample["cpu"])
        self.assertIsNotNone(stale["collection_error"])

    def test_sampler_rates_use_elapsed_counters_and_resets_stay_unknown(self):
        clock = SimpleNamespace(time=time.time, monotonic=unittest.mock.Mock(side_effect=[10.0, 12.0, 14.0]))
        counters = [SimpleNamespace(bytes_sent=1000, bytes_recv=2000),
                    SimpleNamespace(bytes_sent=3000, bytes_recv=10000),
                    SimpleNamespace(bytes_sent=20, bytes_recv=50)]
        with patch("agent.backend.time", clock), \
             patch("agent.backend.psutil.net_io_counters", side_effect=counters), \
             patch("agent.backend.psutil.cpu_percent", side_effect=[0.0, 36.5, 22.0]):
            first = self.runtime.backend.snapshot()
            second = self.runtime.backend.snapshot()
            reset = self.runtime.backend.snapshot()
        self.assertIsNone(first["cpu"]["pct"])
        self.assertIsNone(first["up_bps"])
        self.assertIsNone(first["down_bps"])
        self.assertEqual(second["cpu"]["pct"], 36.5)
        self.assertEqual(second["up_bps"], 1000.0)
        self.assertEqual(second["down_bps"], 4000.0)
        self.assertIsNone(reset["up_bps"])
        self.assertIsNone(reset["down_bps"])

    def test_accepted_destructive_request_retries_without_reusing_confirmation(self):
        args = {"delay": 60, "reason": "Admission regression; never executed"}
        nonce = self.prepare_restart(self.owner, args)
        first = self.runtime.submit(self.owner, "power.restart", args, "stable-request-001", nonce)
        retried = self.runtime.submit(self.owner, "power.restart", args, "stable-request-001", nonce)
        self.assertEqual(first["id"], retried["id"])
        self.assertEqual(first["state"], "queued")
        self.assertEqual(len(self.runtime.store.jobs()), 1)
        with self.assertRaises(OperationError):
            self.runtime.submit(self.owner, "power.restart", args, "different-request-001", nonce)
        self.assertEqual(len(self.runtime.store.jobs()), 1)

    def test_request_id_cannot_change_an_accepted_destructive_action(self):
        args = {"delay": 60, "reason": "Never executed"}
        nonce = self.prepare_restart(self.owner, args)
        first = self.runtime.submit(self.owner, "power.restart", args, "stable-request-002", nonce)
        with self.assertRaises(OperationError) as conflict:
            self.runtime.submit(self.owner, "power.restart", dict(args, delay=120), "stable-request-002", nonce)
        self.assertEqual(conflict.exception.code, "request_id_conflict")
        self.assertEqual(self.runtime.store.job(first["id"])["args"], args)

    def test_missing_confirmation_never_queues_power_operation(self):
        with self.assertRaises(OperationError):
            self.runtime.submit(self.owner, "power.restart", {"delay": 60, "reason": "Never executed"}, "missing-confirmation-001")
        self.assertEqual(self.runtime.store.jobs(), [])

    def test_viewer_cannot_prepare_or_submit_power_operation(self):
        viewer = self.enroll("Viewer", "viewer")
        args = {"delay": 60, "reason": "Never executed"}
        with self.assertRaises(OperationError) as denied:
            self.prepare_restart(viewer, args)
        self.assertEqual(denied.exception.status, 403)
        with self.assertRaises(OperationError):
            self.runtime.submit(viewer, "power.restart", args, "viewer-request-001")
        self.assertEqual(self.runtime.store.jobs(), [])

    def test_read_only_mode_blocks_mutation_even_for_owner(self):
        self.runtime.read_only = True
        args = {"delay": 60, "reason": "Never executed"}
        with self.assertRaises(OperationError) as denied:
            self.prepare_restart(self.owner, args)
        self.assertEqual(denied.exception.code, "read_only")
        with self.assertRaises(OperationError):
            self.runtime.submit(self.owner, "power.restart", args, "read-only-request-001")
        self.assertEqual(self.runtime.store.jobs(), [])

    def test_cancellation_does_not_allow_another_device_to_control_job(self):
        other = self.enroll("Other", "operator")
        submitted = self.runtime.submit(self.owner, "overview.snapshot", {}, "owner-query-request-001")
        with self.assertRaises(OperationError) as denied:
            self.runtime.cancel(other, submitted["id"])
        self.assertEqual(denied.exception.status, 403)
        cancelled = self.runtime.cancel(self.owner, submitted["id"])
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertIsNone(self.runtime.store.claim_job())

    def test_public_job_does_not_disclose_secret_arguments_or_config_snapshot(self):
        args = {"value": "This-is-a-secret-not-a-real-key"}
        operation = "settings.update_hash"
        descriptor = next((item for item in self.runtime.catalog() if item["id"] == operation), None)
        if descriptor is None or not any(item.get("type") == "secret" for item in descriptor["fields"]):
            # Account creation is the stable secret-bearing user operation.
            descriptor = next(item for item in self.runtime.catalog()
                              if any(field.get("type") == "secret" for field in item.get("fields", [])))
        secret_name = next(field["name"] for field in descriptor["fields"] if field.get("type") == "secret")
        stored, _ = self.runtime.store.create_job(self.owner["id"], descriptor["id"],
                                                  {secret_name: "never-disclose-this-value"}, "secret-public-request-001")
        public = self.runtime._public_job(stored)
        self.assertEqual(public["args"][secret_name], "***")
        self.assertNotIn("config_snapshot", public)
        self.assertNotIn("never-disclose-this-value", str(public))


if __name__ == "__main__":
    unittest.main()
