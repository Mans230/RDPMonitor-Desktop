import hashlib
import tempfile
import threading
import unittest
from pathlib import Path

from agent.contracts import ExecutionContext, OperationError
from agent.transfers import TransferManager


class AgentTransferTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = {"uploads_enabled": True, "upload_dir": str(self.root / "received")}
        self.manager = TransferManager(self.root / "state", lambda: dict(self.policy), lambda path: path.resolve())
        self.context = ExecutionContext({"id": "owner", "role": "owner"}, threading.Event(),
                                        lambda _percent, _message: None,
                                        lambda *_args, **_kwargs: None,
                                        lambda *_args, **_kwargs: {})

    def test_retried_chunk_preserves_content_and_rejects_different_bytes(self):
        upload = self.manager.begin("owner", "payload.bin", 6)
        identifier = upload["id"]
        self.manager.write("owner", identifier, 0, b"abc")
        retried = self.manager.write("owner", identifier, 0, b"abc")
        self.assertEqual(retried["offset"], 3)
        with self.assertRaises(OperationError) as conflict:
            self.manager.write("owner", identifier, 0, b"xyz")
        self.assertEqual(conflict.exception.code, "upload_conflict")
        self.manager.write("owner", identifier, 3, b"def")
        result = self.manager.commit("owner", identifier, self.context)
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual((self.root / "received" / "payload.bin").read_bytes(), b"abcdef")

    def test_actor_cannot_resume_another_devices_upload(self):
        upload = self.manager.begin("owner", "payload.bin", 1)
        with self.assertRaises(OperationError) as denied:
            self.manager.write("other", upload["id"], 0, b"a")
        self.assertEqual(denied.exception.status, 403)
        self.assertEqual(self.manager.status("owner", upload["id"])["offset"], 0)

    def test_checksum_failure_never_creates_destination(self):
        upload = self.manager.begin("owner", "payload.bin", 3, hashlib.sha256(b"xyz").hexdigest())
        self.manager.write("owner", upload["id"], 0, b"abc")
        with self.assertRaises(OperationError) as mismatch:
            self.manager.commit("owner", upload["id"], self.context)
        self.assertEqual(mismatch.exception.code, "upload_checksum")
        self.assertFalse((self.root / "received" / "payload.bin").exists())

    def test_existing_file_is_never_overwritten(self):
        upload = self.manager.begin("owner", "payload.bin", 3)
        self.manager.write("owner", upload["id"], 0, b"new")
        destination = self.root / "received"
        destination.mkdir()
        (destination / "payload.bin").write_bytes(b"original")
        with self.assertRaises(OperationError) as conflict:
            self.manager.commit("owner", upload["id"], self.context)
        self.assertEqual(conflict.exception.code, "file_exists")
        self.assertEqual((destination / "payload.bin").read_bytes(), b"original")

    def test_disabling_uploads_revokes_existing_transfer_commit(self):
        upload = self.manager.begin("owner", "payload.bin", 3)
        self.manager.write("owner", upload["id"], 0, b"abc")
        self.policy["uploads_enabled"] = False
        with self.assertRaises(OperationError) as denied:
            self.manager.commit("owner", upload["id"], self.context)
        self.assertEqual(denied.exception.code, "uploads_disabled")
        self.assertFalse((self.root / "received" / "payload.bin").exists())

    def test_incomplete_and_oversized_chunks_are_rejected(self):
        upload = self.manager.begin("owner", "payload.bin", 4)
        with self.assertRaises(OperationError) as incomplete:
            self.manager.commit("owner", upload["id"], self.context)
        self.assertEqual(incomplete.exception.code, "upload_incomplete")
        with self.assertRaises(OperationError) as overflow:
            self.manager.write("owner", upload["id"], 0, b"abcde")
        self.assertEqual(overflow.exception.code, "upload_size_mismatch")
        self.assertEqual(self.manager.status("owner", upload["id"])["offset"], 0)

    def test_windows_path_traversal_and_reserved_names_rejected(self):
        for name in ("../escape", "..\\escape", "C:\\escape", "a:b", "CON.txt", "LPT1", "trailing.", "trailing "):
            with self.subTest(name=name), self.assertRaises(OperationError):
                self.manager.begin("owner", name, 0)
        self.assertFalse((self.root / "escape").exists())

    def test_empty_file_and_completed_commit_are_idempotent(self):
        upload = self.manager.begin("owner", "empty.bin", 0, hashlib.sha256(b"").hexdigest())
        first = self.manager.commit("owner", upload["id"], self.context)
        second = self.manager.commit("owner", upload["id"], self.context)
        self.assertEqual(first["data"], second["data"])
        self.assertEqual((self.root / "received" / "empty.bin").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
