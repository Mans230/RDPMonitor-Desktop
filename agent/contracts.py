"""Shared transport-independent operation contracts for the Windows agent."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any, Callable

VERSION = "1.0.0"
API_VERSION = 1
CAPABILITIES = frozenset({"view", "operate", "security", "accounts", "execute", "files", "backup", "configure", "manage"})
TERMINAL_STATES = frozenset({"succeeded", "partial", "failed", "cancelled", "interrupted"})

# One definition of what a sensitive *name* looks like, shared by the job
# transport, durable events/audit records and the configuration surfaces so the
# three can never drift apart.
SECRET_NAME_WORDS = frozenset({"password", "passwd", "secret", "token", "credential",
                               "private_key", "api_key", "api_hash", "authorization",
                               "passphrase"})
# Durable events and audit records additionally treat generic envelope fields as
# secret-shaped. Job results keep those keys because they carry user-visible codes.
SECRET_ENVELOPE_WORDS = SECRET_NAME_WORDS | frozenset({"csr", "nonce", "code"})


def secret_named(name: object, words: frozenset[str] = SECRET_NAME_WORDS) -> bool:
    """True when a field name looks like it holds credential material."""
    text = str(name).lower()
    return any(word in text for word in words)



class OperationError(Exception):
    """An expected, safe-to-display operation admission or execution error."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True)
class ExecutionContext:
    actor: dict[str, Any]
    cancel: Event
    progress: Callable[[int | None, str], None]
    emit: Callable[..., dict[str, Any] | None]
    artifact: Callable[..., dict[str, Any]]
    config_snapshot: dict[str, Any] | None = None


def operation(identifier: str, title: str, section: str, description: str,
              capability: str = "view", destructive: bool = False,
              fields: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if capability not in CAPABILITIES:
        raise ValueError("unknown capability: " + capability)
    return {"id": identifier, "title": title, "section": section,
            "description": description, "capability": capability,
            "destructive": destructive, "fields": fields or []}


def field(name: str, label: str, kind: str = "string", required: bool = False,
          default: Any = None, choices: list[str] | None = None,
          help: str = "") -> dict[str, Any]:
    result = {"name": name, "label": label, "type": kind, "required": required}
    if default is not None:
        result["default"] = default
    if choices is not None:
        result["choices"] = choices
    if help:
        result["help"] = help
    return result


def succeeded(message: str, data: Any = None, artifacts: list[dict] | None = None) -> dict:
    result = {"status": "succeeded", "message": message, "data": data}
    if artifacts is not None:
        result["artifacts"] = artifacts
    return result


def public_artifact(value: dict) -> dict:
    return {key: item for key, item in value.items() if key not in {"path", "device_id"}}
