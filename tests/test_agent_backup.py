"""Deterministic backup boundaries; no production backup/cloud/tool operation runs.

Parent integration verification: python -m unittest discover -s tests -p test_agent_backup.py
All engine exercises use temporary source/data trees or injected process adapters.
"""
import copy
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.backup import BackupManager
from agent.contracts import OperationError


class BackupBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        with patch.object(BackupManager, "_migrate_legacy"):
            self.manager = BackupManager(ROOT, self.base / "data", lambda *a, **kw: None)
        self.context = types.SimpleNamespace(
            cancel=threading.Event(), progress=lambda *a: None,
            emit=lambda *a, **kw: None, artifact=lambda p, *a: {"name": Path(p).name},
            config_snapshot={})
        # Never inherit real administrator settings into isolated test jobs.
        self.manager._cfg = copy.deepcopy(self.manager.config.DEFAULT_CONFIG)
        self.manager._cfg["schedule"].update(timezone="local", catch_up=True)
        self.manager._cfg["cloud"]["rclone_config"] = self.manager.cloud.RCLONE_CONFIG

    def tearDown(self):
        self.manager.stop()
        self.temp.cleanup()

    def test_public_secrets_are_markers_and_job_snapshot_is_independent(self):
        self.manager._cfg["backup"]["archive_password"] = "do-not-return"
        public = self.manager.get_config()
        self.assertEqual(public["value"]["backup"]["archive_password"], "***")
        self.assertNotIn("do-not-return", json.dumps(public))
        snapshot = self.manager.job_snapshot()
        self.assertEqual(snapshot["value"]["backup"]["archive_password"], "do-not-return")
        self.manager._cfg["backup"]["sources"].append("later")
        self.assertEqual(snapshot["value"]["backup"]["sources"], [])
        self.assertNotIn("bot_token", json.dumps(public))

    def test_redaction_marker_does_not_replace_secret(self):
        self.manager._cfg["restic"]["password"] = "existing"
        def save(candidate):
            self.manager._cfg = candidate
        with patch.object(self.manager, "_save", side_effect=save):
            self.manager.set_config({"restic": {"password": "***"}}, 0)
        self.assertEqual(self.manager._cfg["restic"]["password"], "existing")

    def test_revision_conflict_is_visible_and_does_not_save(self):
        with patch.object(self.manager, "_save") as save:
            with self.assertRaises(OperationError):
                self.manager.set_config({"backup": {"sources": ["new"]}}, 100)
            save.assert_not_called()
        self.assertEqual(self.manager._cfg["backup"]["sources"], [])

    def test_invalid_settings_leave_last_known_good_unchanged(self):
        before = self.manager._snapshot()
        with self.assertRaises(OperationError):
            self.manager.set_config({"schedule": {"time": "25:99"}}, 0)
        self.assertEqual(before, self.manager._snapshot())

    def test_job_uses_persisted_configuration_not_live_mutation(self):
        queued = self.manager.job_snapshot()
        queued["value"]["backup"]["sources"] = ["queued-source"]
        self.context.config_snapshot = {"backup": queued}
        self.manager._cfg["backup"]["sources"] = ["changed-source"]
        with patch.object(self.manager, "_execute", side_effect=lambda n, a, c, x, p: c) as execute:
            result = self.manager.execute("backup.run", {}, self.context)
        self.assertEqual(result["backup"]["sources"], ["queued-source"])
        execute.assert_called_once()

    def test_changed_privileged_hook_requires_resubmission(self):
        queued = self.manager.job_snapshot()
        queued["value"]["backup"]["pre_command"] = "old command"
        self.context.config_snapshot = {"backup": queued}
        with patch.object(self.manager, "_execute") as execute:
            with self.assertRaises(OperationError):
                self.manager.execute("backup.run", {}, self.context)
            execute.assert_not_called()

    def test_archive_path_traversal_and_existing_restore_refused(self):
        for name in ("../other.zip", "C:\\other.zip", "sub/backup.zip", "x:stream"):
            with self.subTest(name=name), self.assertRaises(OperationError):
                self.manager._archive(name)
        existing = self.base / "existing"
        existing.mkdir()
        with self.assertRaises(ValueError):
            self.manager.restore._assert_safe_dest(str(existing))

    def test_both_engines_fail_closed_for_missing_source_before_repo_init(self):
        cfg = self.manager._snapshot()
        cfg["backup"]["sources"] = [str(self.base / "missing")]
        with self.assertRaises(ValueError):
            self.manager.zip.create_backup(cfg, log=lambda *a: None)
        cfg["restic"].update(repository="isolated-repo", password="test-password")
        with patch.object(self.manager.restic, "validate", return_value=None), patch.object(self.manager.restic, "ensure_repo") as init:
            result = self.manager.restic.run_backup(cfg, log=lambda *a: None)
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["missing"])
        init.assert_not_called()

    def test_zip_restore_and_multipart_verify_actual_content(self):
        source = self.base / "source.txt"
        source.write_bytes(b"deterministic original content\x00" * 20)
        cfg = self.manager._snapshot()
        cfg["backup"]["sources"] = [str(source)]
        paths, status = self.manager.zip.create_backup(cfg, log=lambda *a: None)
        self.assertEqual(status, "ok")
        self.assertTrue(self.manager.zip.LAST_STATS["verified"])
        archive = Path(paths[0])
        parts = self.manager.zip.split_file(str(archive), max_part_bytes=113)
        self.assertGreater(len(parts), 1)
        archive.unlink()
        destination = self.manager.home / "restores" / "multipart-test"
        result = self.manager.restore.restore_archive(parts[0], str(destination))
        self.assertEqual(result["status"], "ok", result)
        restored = list(destination.rglob("source.txt"))
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].read_bytes(), source.read_bytes())
        Path(parts[1]).unlink()
        failed = self.manager.restore.restore_archive(parts[0], str(destination.parent / "missing-part"))
        self.assertEqual(failed["status"], "error")
        self.assertFalse(failed["created"])

    def test_restic_restore_calls_real_restore_verify_and_checks_inventory(self):
        cfg = self.manager._snapshot()
        destination = self.manager.home / "restores" / "restic-test"
        calls = []
        snapshot = "a" * 64
        def run(config, args, **kwargs):
            calls.append(args)
            if args[0] == "ls":
                return 0, json.dumps({"type": "file", "path": "/folder/value", "size": 5})
            if args[0] == "restore":
                target = Path(args[args.index("--target") + 1]) / "folder" / "value"
                target.parent.mkdir(parents=True)
                target.write_bytes(b"value")
                return 0, "restored and verified"
            raise AssertionError(args)
        with patch.object(self.manager.restic, "snapshot_details", return_value=[{"id": snapshot}]), patch.object(self.manager.restic, "_run", side_effect=run):
            result = self.manager.restic.restore_snapshot(cfg, snapshot, str(destination))
        self.assertEqual(result["status"], "ok", result)
        self.assertTrue(result["verified"])
        self.assertEqual(result["checked"], 1)
        self.assertIn("--verify", calls[-1])
        self.assertFalse(any(call[0] == "check" for call in calls), "repository check is not a restore drill")

    def test_restic_inventory_mismatch_never_reports_success(self):
        destination = self.manager.home / "restores" / "bad-restic"
        snapshot = "b" * 64
        def run(config, args, **kwargs):
            return (0, json.dumps({"type": "file", "path": "/missing", "size": 7})) if args[0] == "ls" else (0, "")
        with patch.object(self.manager.restic, "snapshot_details", return_value=[{"id": snapshot}]), patch.object(self.manager.restic, "_run", side_effect=run):
            result = self.manager.restic.restore_snapshot(self.manager._snapshot(), snapshot, str(destination))
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["missing"], ["missing"])

    def test_restic_symlink_snapshot_refused_before_destination_creation(self):
        snapshot = "c" * 64
        destination = self.manager.home / "restores" / "linked"
        with patch.object(self.manager.restic, "snapshot_details", return_value=[{"id": snapshot}]), patch.object(self.manager.restic, "_run", return_value=(0, json.dumps({"type": "symlink", "path": "/escape"}))):
            result = self.manager.restic.restore_snapshot(self.manager._snapshot(), snapshot, str(destination))
        self.assertEqual(result["status"], "error")
        self.assertFalse(destination.exists())

    def test_schedule_due_slot_is_durable_stable_and_respects_catchup(self):
        cfg = self.manager._snapshot()
        cfg["schedule"].update(enabled=True, mode="times", times=["03:00", "15:00"], timezone="UTC")
        now = dt.datetime(2026, 10, 16, 16, 0, tzinfo=dt.timezone.utc)
        self.assertEqual(self.manager._due_slot(cfg, now), "daily:2026-10-16:15:00")
        self.assertEqual(self.manager._due_slot(cfg, now + dt.timedelta(seconds=20)), "daily:2026-10-16:15:00")
        cfg["schedule"]["catch_up"] = False
        self.assertIsNone(self.manager._due_slot(cfg, now))
        cfg["schedule"]["enabled"] = False
        self.assertIsNone(self.manager._due_slot(cfg, now))

    def test_start_requires_durable_submitter_and_read_only_starts_nothing(self):
        self.manager.start(read_only=True)
        self.assertIsNone(self.manager._thread)
        with self.assertRaises(OperationError):
            self.manager.start()

    def test_schedule_submits_once_and_does_not_execute_engine(self):
        self.manager._cfg["schedule"].update(enabled=True, mode="interval", interval_hours=1)
        submissions = []
        def submit(operation, args, request_id):
            submissions.append((operation, args, request_id))
            self.manager._stop.set()
            return {"id": "durable-job"}
        self.manager.set_submitter(submit)
        with patch.object(self.manager.scheduler, "last_successful_run", return_value=None), patch.object(self.manager.scheduler, "run_with_retries") as engine:
            self.manager._loop()
        self.assertEqual(submissions[0][0], "backup.run")
        self.assertTrue(submissions[0][1]["scheduled"])
        self.assertTrue((self.manager.home / "control" / "schedule.json").is_file())
        engine.assert_not_called()

    def test_tool_install_rejects_untrusted_url_or_missing_digest_before_network(self):
        with patch("urllib.request.build_opener") as network:
            with self.assertRaises(OperationError):
                self.manager.execute("backup.tools.install", {"tool": "restic", "url": "http://example.com/tool", "version": "0.17.3", "sha256": "0" * 64}, self.context)
            network.assert_not_called()

    def test_secret_storage_has_no_plaintext_non_windows_fallback(self):
        with patch.object(self.manager.secrets, "is_available", return_value=False):
            with self.assertRaises(OSError):
                self.manager.secrets.protect("secret")

    def test_destructive_settings_and_credentials_require_confirmation_metadata(self):
        catalog = {op["id"]: op for op in self.manager.catalog()}
        for operation in ("backup.backup.set", "backup.cloud.create", "backup.cloud.remove", "backup.repository.prune", "backup.recovery.import"):
            self.assertTrue(catalog[operation]["destructive"])
        self.assertEqual(catalog["backup.backup.set"]["capability"], "execute")
        fields = {f["name"]: f for f in catalog["backup.cloud.create"]["fields"]}
        self.assertEqual(fields["options"]["type"], "secret")


if __name__ == "__main__":
    unittest.main()
