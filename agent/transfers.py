"""Bounded resumable upload staging owned by the privileged worker.

Clients may name a file, never a destination path. Committing always uses the
current enabled upload policy, creates a new file, and never overwrites one.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import threading
import time
from pathlib import Path
from typing import Callable

from .contracts import OperationError, succeeded

CHUNK_SIZE = 262144
MAX_UPLOAD = 1024 * 1024 * 1024
STAGING_QUOTA = 2 * MAX_UPLOAD
UPLOAD_TTL = 24 * 60 * 60
_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)


class TransferManager:
    def __init__(self, data_dir: Path, policy: Callable[[], dict], approve: Callable[[Path], Path]):
        self.root = Path(data_dir).resolve() / "uploads"
        self.root.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        self.approve = approve
        self._lock = threading.RLock()

    @staticmethod
    def _name(value: str) -> str:
        if (not isinstance(value, str) or not value or len(value) > 180
                or value in {".", ".."} or value[-1:] in {".", " "}
                or any(ord(char) < 32 or char in '/\\:<>"|?*' for char in value)
                or _RESERVED.match(value)):
            raise OperationError("invalid_filename", "Choose a plain filename without path or reserved Windows characters")
        return value

    @staticmethod
    def _public(manifest: dict) -> dict:
        return {key: manifest.get(key) for key in ("id", "name", "size", "offset", "expires", "state", "sha256")}

    def _path(self, identifier: str) -> Path:
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", identifier):
            raise OperationError("upload_not_found", "The upload does not exist", 404)
        return self.root / identifier

    def _save(self, directory: Path, manifest: dict) -> None:
        temporary = directory / ("manifest." + secrets.token_hex(4) + ".tmp")
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(manifest, stream, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, directory / "manifest.json")
        finally:
            temporary.unlink(missing_ok=True)

    def _load(self, identifier: str, device_id: str) -> tuple[Path, dict]:
        directory = self._path(identifier)
        try:
            manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise OperationError("upload_not_found", "The upload does not exist", 404) from exc
        if manifest.get("device_id") != device_id:
            raise OperationError("forbidden", "This upload belongs to another device", 403)
        if manifest.get("expires", 0) < time.time():
            raise OperationError("upload_expired", "The upload expired; start a new upload", 410)
        return directory, manifest

    def _enabled_policy(self) -> Path:
        config = self.policy()
        if config.get("uploads_enabled") is not True:
            raise OperationError("uploads_disabled", "File uploads are disabled in the machine settings", 403)
        configured = config.get("upload_dir")
        if not isinstance(configured, str) or not configured.strip():
            raise OperationError("upload_directory_required", "Configure an upload directory before receiving files", 409)
        destination = Path(os.path.expandvars(configured)).expanduser().resolve()
        if destination == destination.anchor or destination == Path(destination.anchor):
            raise OperationError("unsafe_upload_directory", "A drive root cannot be the upload directory", 409)
        return destination

    def begin(self, device_id: str, name: str, size: int, sha256: str | None = None) -> dict:
        self._enabled_policy()
        name = self._name(name)
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_UPLOAD:
            raise OperationError("upload_size_limit", "File size must be between zero and 1 GiB", 413)
        if sha256 is not None and (not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256)):
            raise OperationError("invalid_checksum", "SHA-256 must contain 64 hexadecimal characters")
        with self._lock:
            reserved = active = owned = 0
            for path in self.root.glob("*/manifest.json"):
                try:
                    old = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if old.get("expires", 0) < time.time():
                    shutil.rmtree(path.parent)
                    continue
                if old.get("state") != "completed":
                    reserved += int(old.get("size", 0))
                    active += 1
                    owned += old.get("device_id") == device_id
            if active >= 32 or owned >= 8 or reserved + size > STAGING_QUOTA:
                raise OperationError("upload_quota", "Upload staging quota is full", 429)
            if shutil.disk_usage(self.root).free < size + 100 * 1024 * 1024:
                raise OperationError("insufficient_space", "Insufficient staging disk space", 507)
            identifier = secrets.token_urlsafe(24)
            directory = self._path(identifier)
            directory.mkdir()
            manifest = {"id": identifier, "device_id": device_id, "name": name,
                        "size": size, "sha256": sha256.lower() if sha256 else None,
                        "offset": 0, "created": time.time(), "expires": time.time() + UPLOAD_TTL,
                        "state": "receiving"}
            (directory / "content.part").touch(exist_ok=False)
            self._save(directory, manifest)
            return self._public(manifest)

    def status(self, device_id: str, identifier: str) -> dict:
        with self._lock:
            _directory, manifest = self._load(identifier, device_id)
            return self._public(manifest)

    def write(self, device_id: str, identifier: str, offset: int, block: bytes) -> dict:
        self._enabled_policy()
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise OperationError("invalid_offset", "A nonnegative byte offset is required")
        if not isinstance(block, bytes) or not 1 <= len(block) <= CHUNK_SIZE:
            raise OperationError("invalid_chunk", "An upload chunk must contain 1 to 262144 bytes", 413)
        with self._lock:
            directory, manifest = self._load(identifier, device_id)
            if manifest["state"] != "receiving":
                raise OperationError("upload_closed", "The upload is no longer receiving data", 409)
            if offset + len(block) > manifest["size"]:
                raise OperationError("upload_size_mismatch", "The chunk exceeds the declared file size", 409)
            with (directory / "content.part").open("r+b") as stream:
                if offset < manifest["offset"]:
                    stream.seek(offset)
                    if offset + len(block) <= manifest["offset"] and stream.read(len(block)) == block:
                        return self._public(manifest)
                    raise OperationError("upload_conflict", "Previously uploaded bytes do not match", 409)
                if offset != manifest["offset"]:
                    raise OperationError("upload_offset", "Resume at the last confirmed byte offset", 409)
                stream.seek(offset)
                stream.write(block)
                stream.flush()
                os.fsync(stream.fileno())
            manifest["offset"] += len(block)
            self._save(directory, manifest)
            return self._public(manifest)

    def commit(self, device_id: str, identifier: str, context) -> dict:
        destination = self._enabled_policy()
        with self._lock:
            directory, manifest = self._load(identifier, device_id)
            if manifest["state"] == "completed":
                return succeeded("File already received", {"name": manifest["name"], "size": manifest["size"], "sha256": manifest["sha256"], "destination": manifest["destination"]})
            if manifest["offset"] != manifest["size"]:
                raise OperationError("upload_incomplete", "Upload all declared bytes before completing the transfer", 409)
            if context.cancel.is_set():
                return {"status": "cancelled", "message": "Upload commit cancelled", "data": None}
            source = directory / "content.part"
            context.progress(None, "Verifying uploaded file")
            with source.open("rb") as stream:
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            if manifest["sha256"] and checksum != manifest["sha256"]:
                raise OperationError("upload_checksum", "Uploaded file does not match the expected SHA-256", 409)
            if source.stat().st_size != manifest["size"]:
                raise OperationError("upload_size_mismatch", "The staged file size does not match the declared size", 409)
            self.approve(destination / self._name(manifest["name"]))
            destination.mkdir(parents=True, exist_ok=True)
            destination = destination.resolve()
            target = self.approve(destination / self._name(manifest["name"]))
            if target.exists() or target.is_symlink():
                raise OperationError("file_exists", "A file with that name already exists; existing files are never overwritten", 409)
            # The protected service staging area is on the same filesystem as
            # many destinations, but do not assume rename can cross volumes.
            try:
                with source.open("rb") as incoming, target.open("xb") as outgoing:
                    while True:
                        if context.cancel.is_set():
                            raise OperationError("upload_cancelled", "Upload commit cancelled", 409)
                        block = incoming.read(CHUNK_SIZE)
                        if not block:
                            break
                        outgoing.write(block)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
            except FileExistsError as exc:
                raise OperationError("file_exists", "A file with that name already exists", 409) from exc
            except Exception:
                target.unlink(missing_ok=True)
                raise
            manifest.update(state="completed", sha256=checksum, destination=str(target))
            self._save(directory, manifest)
            source.unlink(missing_ok=True)
            context.progress(100, "File received and SHA-256 verified")
            return succeeded("File received and SHA-256 verified", {"name": manifest["name"], "size": manifest["size"], "sha256": checksum, "destination": str(target)})
