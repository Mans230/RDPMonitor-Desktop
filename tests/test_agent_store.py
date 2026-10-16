"""Consumer-visible state boundaries; no host policy or service modifications."""
import hashlib
import math
import os
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.contracts import OperationError
from agent.store import Store, canonical_json


class CanonicalJsonTests(unittest.TestCase):
    def test_equivalent_objects_and_numbers_have_identical_identity(self):
        self.assertEqual(canonical_json({"z": -0.0, "a": [1.0, True, None]}),
                         canonical_json({"a": [1, True, None], "z": 0}))

    def test_ambiguous_or_non_json_values_are_rejected(self):
        cycle = []
        cycle.append(cycle)
        for value in (float("nan"), float("inf"), {1: "a", "1": "b"}, {"x": object()},
                      2 ** 53, "\ud800", cycle):
            with self.subTest(value=type(value).__name__), self.assertRaises(OperationError):
                canonical_json(value)

    def test_payload_limit_is_measured_in_utf8_bytes(self):
        with self.assertRaises(OperationError) as error:
            canonical_json("é" * 10, max_bytes=15)
        self.assertEqual(error.exception.status, 413)


class StoreFixture:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "state"
        self.store = Store(self.directory)

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()


class PublicStateTests(StoreFixture, unittest.TestCase):

    def test_multiline_monitoring_reports_and_job_results_survive_persistence(self):
        text = "CPU high\nRAM high\t95%"
        self.store.append_event("monitor.report", text)
        self.assertEqual(self.store.events()[0]["message"], text)
        job, _ = self.store.create_job("owner", "monitoring.report", {}, "report-request")
        self.store.claim_job()
        self.store.update_job(job["id"], state="succeeded", message=text)
        self.assertEqual(self.store.job(job["id"])["message"], text)
        with self.assertRaises(OperationError):
            self.store.append_event("monitor.report", "invalid\x00message")

    def test_identity_and_name_survive_restart(self):
        identifier = self.store.identity()["id"]
        self.store.set_name("Production machine")
        self.store.close()
        self.store = Store(self.directory)
        self.assertEqual(self.store.identity()["id"], identifier)
        self.assertEqual(self.store.identity()["name"], "Production machine")

    def test_event_cursors_acknowledgement_and_restart(self):
        first = self.store.append_event("monitor.alert", "Actual alert", data={"password": "never-return", "value": 7})
        second = self.store.append_event("monitor.alert", "Next alert")
        self.store.acknowledge(first["id"], "viewer")
        self.store.acknowledge(first["id"], "viewer")
        self.assertEqual(self.store.events()[0]["acknowledged_by"], ["viewer"])
        self.assertEqual(self.store.events()[0]["data"]["password"], "[redacted]")
        self.assertEqual([item["id"] for item in self.store.events(after=first["id"])], [second["id"]])
        self.store.close()
        self.store = Store(self.directory)
        self.assertEqual(self.store.events()[0]["agent_id"], self.store.identity()["id"])
        self.assertEqual(self.store.events()[0]["acknowledged_by"], ["viewer"])

    def test_pruned_cursor_is_explicitly_expired(self):
        self.store.EVENT_LIMIT = 2
        first = self.store.append_event("test", "one")
        for number in range(4):
            self.store.append_event("test", str(number))
        with self.assertRaises(OperationError) as error:
            self.store.events(after=first["id"])
        self.assertEqual(error.exception.code, "cursor_expired")
        self.assertEqual(len(self.store.events(after=0)), 2)

    def test_acknowledging_missing_event_is_not_silently_accepted(self):
        with self.assertRaises(OperationError) as error:
            self.store.acknowledge(100, "device")
        self.assertEqual(error.exception.status, 404)

    def test_bounded_audit_redacts_nested_credentials(self):
        self.store.AUDIT_LIMIT = 2
        for value in range(4):
            self.store.append_audit({"id": "owner"}, "configuration.update", "succeeded",
                                    {"nested": [{"restic_password": "sensitive"}], "value": value})
        items = self.store.audits()
        self.assertEqual(len(items), 2)
        self.assertEqual(items[-1]["detail"]["nested"][0]["restic_password"], "[redacted]")

    def test_metrics_use_measured_timestamps_not_insertion_positions(self):
        self.store.METRIC_LIMIT = 3
        for ts in (300, 100, 200, 400):
            self.store.append_metric({"ts": ts, "cpu": {"pct": ts / 10}})
        self.assertEqual([value["ts"] for value in self.store.metrics()], [100, 200, 400])
        self.assertEqual([value["ts"] for value in self.store.metrics(limit=2)], [200, 400])
        self.assertEqual([value["ts"] for value in self.store.metrics(after=100, before=300)], [200])
        with self.assertRaises(OperationError):
            self.store.append_metric({"ts": math.nan})

    def test_metric_history_fits_transport_without_repeating_process_inventories(self):
        from agent.ipc import MAX_MESSAGE
        processes = [{"pid": pid, "name": "p" * 512} for pid in range(1000, 2000)]
        measured = [1700000000.1234567 + index for index in range(4)]
        for index in range(4):
            self.store.append_metric({"ts": measured[index], "cpu": {"pct": 10 + index},
                                      "ram": {"pct": 40}, "up_bps": 1024, "down_bps": 2048,
                                      "procs": processes})
        history = self.store.metrics()
        self.assertEqual([row["ts"] for row in history], measured)
        self.assertEqual([row["cpu"] for row in history], [10, 11, 12, 13])
        self.assertEqual([row["ram"] for row in history], [40, 40, 40, 40])
        self.assertTrue(all("procs" not in row for row in history))
        self.assertLess(len(canonical_json({"items": history}, max_bytes=MAX_MESSAGE).encode()), MAX_MESSAGE)
        latest = self.store.metrics(limit=1, detailed=True)[0]
        self.assertEqual(latest["procs"][-1]["pid"], 1999)

    def test_artifact_is_an_independent_copy_with_integrity_and_owner(self):
        source = Path(self.temporary.name) / "report.txt"
        source.write_bytes(b"actual generated report")
        metadata = self.store.add_artifact(source, device_id="creator", media_type="text/plain")
        source.write_bytes(b"changed")
        stored = self.store.artifact(metadata["id"])
        self.assertEqual(Path(stored["path"]).read_bytes(), b"actual generated report")
        self.assertEqual(stored["sha256"], hashlib.sha256(b"actual generated report").hexdigest())
        self.assertEqual(stored["device_id"], "creator")
        self.assertEqual(Path(stored["path"]).parent, self.directory / "artifacts")

    def test_artifact_quota_and_expiry_do_not_delete_original(self):
        source = Path(self.temporary.name) / "data.bin"
        source.write_bytes(b"123456")
        self.store.ARTIFACT_QUOTA = 10
        first = self.store.add_artifact(source, device_id="owner")
        with self.assertRaises(OperationError) as error:
            self.store.add_artifact(source, device_id="owner")
        self.assertEqual(error.exception.code, "artifact_quota")
        with self.store._transaction() as connection:
            connection.execute("UPDATE artifacts SET expires='2000-01-01T00:00:00.000Z' WHERE id=?", (first["id"],))
        self.assertIsNone(self.store.artifact(first["id"]))
        self.assertFalse(Path(first["path"]).exists())
        self.assertTrue(source.exists())
        self.assertEqual(self.store.add_artifact(source)["size"], 6)

    def test_artifact_quota_is_atomic_between_store_instances(self):
        source = Path(self.temporary.name) / "source.bin"
        source.write_bytes(b"123456")
        other = Store(self.directory)
        self.addCleanup(other.close)
        self.store.ARTIFACT_QUOTA = other.ARTIFACT_QUOTA = 6
        barrier = threading.Barrier(2)
        def copy(store):
            barrier.wait()
            try:
                return store.add_artifact(source)["id"]
            except OperationError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(copy, (self.store, other)))
        self.assertEqual(results.count("artifact_quota"), 1)

    def test_artifact_path_components_and_reparse_sources_are_rejected(self):
        source = Path(self.temporary.name) / "source.bin"
        source.write_bytes(b"report")
        with self.assertRaises(OperationError):
            self.store.add_artifact(source, name="../outside")
        link = Path(self.temporary.name) / "linked.bin"
        try:
            link.symlink_to(source)
        except OSError:
            self.skipTest("Symlink creation requires an enabled Windows developer privilege.")
        with self.assertRaises(OperationError) as error:
            self.store.add_artifact(link)
        self.assertEqual(error.exception.code, "unsafe_state_path")

    def test_state_directory_has_no_untrusted_permission_grants(self):
        if os.name == "nt":
            import win32security
            descriptor = win32security.GetNamedSecurityInfo(str(self.directory), win32security.SE_FILE_OBJECT,
                                                           win32security.DACL_SECURITY_INFORMATION)
            self.assertTrue(descriptor.GetSecurityDescriptorControl()[0] & 0x1000)
            dacl = descriptor.GetSecurityDescriptorDacl()
            forbidden = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}
            actual = {win32security.ConvertSidToStringSid(dacl.GetAce(i)[2]) for i in range(dacl.GetAceCount())}
            self.assertFalse(actual & forbidden)
            self.assertIn("S-1-5-18", actual)
        else:
            self.assertEqual(self.directory.stat().st_mode & 0o077, 0)


@unittest.skipUnless(os.name == "nt", "Persistent private job/config payloads require actual Windows DPAPI.")
class PrivateStateTests(StoreFixture, unittest.TestCase):
    def test_idempotency_and_conflicting_arguments(self):
        first, created = self.store.create_job("device", "process.stop", {"pid": 123}, "request")
        again, repeated = self.store.create_job("device", "process.stop", {"pid": 123.0}, "request")
        self.assertTrue(created)
        self.assertFalse(repeated)
        self.assertEqual(first["id"], again["id"])
        self.assertEqual(self.store.find_job("device", "request")["id"], first["id"])
        with self.assertRaises(OperationError) as error:
            self.store.create_job("device", "process.stop", {"pid": 456}, "request")
        self.assertEqual(error.exception.code, "idempotency_conflict")
        other, created = self.store.create_job("other", "process.stop", {"pid": 456}, "request")
        self.assertTrue(created)
        self.assertNotEqual(other["id"], first["id"])

    def test_parallel_duplicate_acceptance_and_claim_are_single_execution(self):
        barrier = threading.Barrier(6)
        def submit(index):
            barrier.wait()
            return self.store.create_job("device", "backup.create", {"kind": "zip"}, "same")
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(submit, range(6)))
        self.assertEqual(sum(created for _, created in results), 1)
        self.assertEqual(len({job["id"] for job, _ in results}), 1)
        with ThreadPoolExecutor(max_workers=6) as pool:
            claims = list(pool.map(lambda _: self.store.claim_job(), range(6)))
        self.assertEqual(sum(item is not None for item in claims), 1)

    def test_revision_compare_and_swap_and_immutable_job_configuration(self):
        configured = self.store.set_config("monitor", {"threshold": 70, "password": "private"}, 0)
        self.assertEqual(configured["revision"], 1)
        job, _ = self.store.create_job("device", "monitor.report", {}, "one", {"monitor": 1})
        self.store.set_config("monitor", {"threshold": 80}, 1)
        snapshot = self.store.job(job["id"])["config_snapshot"]
        self.assertEqual(snapshot["monitor"]["value"]["threshold"], 70)
        with self.assertRaises(OperationError) as error:
            self.store.set_config("monitor", {"threshold": 90}, 1)
        self.assertEqual(error.exception.code, "revision_conflict")
        with self.assertRaises(OperationError):
            self.store.create_job("device", "monitor.report", {}, "two", {"monitor": 1})
        self.assertEqual(self.store.get_config("monitor")["value"]["threshold"], 80)
        self.assertEqual(self.store.create_job("device", "monitor.report", {}, "one", {"monitor": 1})[0]["id"], job["id"])

    def test_concurrent_revision_updates_have_one_winner(self):
        self.store.set_config("monitor", {"value": 0}, 0)
        barrier = threading.Barrier(2)
        def update(value):
            barrier.wait()
            try:
                return self.store.set_config("monitor", {"value": value}, 1)["revision"]
            except OperationError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(update, (1, 2)))
        self.assertCountEqual(results, [2, "revision_conflict"])

    def test_cancel_queued_and_running_have_distinct_truthful_states(self):
        first, _ = self.store.create_job("device", "backup.create", {}, "queued")
        cancelled = self.store.request_cancel(first["id"])
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertIsNotNone(cancelled["finished"])
        self.assertIsNone(self.store.claim_job())
        second, _ = self.store.create_job("device", "backup.create", {}, "running")
        self.store.claim_job()
        cancelling = self.store.request_cancel(second["id"])
        self.assertEqual(cancelling["state"], "cancelling")
        self.assertIsNone(cancelling["finished"])
        completed = self.store.update_job(second["id"], state="succeeded", result={"committed": True})
        self.assertTrue(completed["cancel_requested"])
        self.assertEqual(completed["state"], "succeeded")
        self.assertEqual(self.store.request_cancel(second["id"])["state"], "succeeded")
        with self.assertRaises(OperationError):
            self.store.update_job(second["id"], state="running")

    def test_restart_interrupts_inflight_without_replaying_it(self):
        job, _ = self.store.create_job("device", "power.restart", {}, "destructive")
        self.store.claim_job()
        self.store.close()
        self.store = Store(self.directory)
        self.store.recover_jobs()
        self.assertEqual(self.store.job(job["id"])["state"], "interrupted")
        self.assertIsNone(self.store.claim_job())
        repeated, created = self.store.create_job("device", "power.restart", {}, "destructive")
        self.assertFalse(created)
        self.assertEqual(repeated["state"], "interrupted")

    def test_private_configuration_and_job_values_are_encrypted_at_rest(self):
        secret = "SENSITIVE_TEST_CREDENTIAL_613732"
        self.store.set_config("backup", {"password": secret}, 0)
        job, _ = self.store.create_job("device", "accounts.create", {"password": secret}, "secret")
        self.store.claim_job()
        self.store.update_job(job["id"], state="succeeded", result={"sensitive": secret})
        self.assertNotIn(secret.encode(), self.store.path.read_bytes())
        self.assertEqual(self.store.get_config("backup")["value"]["password"], secret)

    def test_invalid_configuration_preserves_last_known_good(self):
        self.store.set_config("monitor", {"value": 1}, 0)
        with self.assertRaises(OperationError):
            self.store.set_config("monitor", {"value": math.nan}, 1)
        self.assertEqual(self.store.get_config("monitor"), {"revision": 1, "value": {"value": 1}})

    def test_internal_delivery_state_is_not_job_configuration(self):
        self.store.set_config("_notification_targets", {"token": "private"}, 0)
        self.store.set_config("monitor", {"threshold": 80}, 0)
        self.assertEqual(self.store.config_versions(), {"monitor": 1})
        job, _ = self.store.create_job("device", "backup.create", {}, "snapshot", {"monitor": 1})
        self.assertEqual(set(job["config_snapshot"]), {"monitor"})
        self.assertEqual(self.store.get_config("_notification_targets")["value"], {"token": "private"})


if __name__ == "__main__":
    unittest.main()
