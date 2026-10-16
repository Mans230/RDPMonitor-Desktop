"""Trusted APNs/FCM sender with protected registrations and a durable outbox.

Push is best-effort delivery of event identifiers, never the authoritative inbox.
Provider credentials and device tokens are stored in the encrypted worker store.
"""
from __future__ import annotations

import base64
import copy
import json
import re
import threading
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .contracts import OperationError

_DEFAULT = {"enabled": False, "fcm": {"project_id": "", "client_email": "", "private_key": ""},
            "apns": {"team_id": "", "key_id": "", "private_key": "", "topic": "", "environment": "production"}}
_SEVERITY = {"info": 0, "warning": 1, "error": 2, "critical": 3}


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _jwt(header: dict, claims: dict, key_pem: str, algorithm: str) -> str:
    body = ".".join(_b64(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims))
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    if algorithm == "RS256" and isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(body.encode(), padding.PKCS1v15(), hashes.SHA256())
    elif algorithm == "ES256" and isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1):
        der = key.sign(body.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        raise OperationError("invalid_provider_key", "The notification private key does not match its provider algorithm")
    return body + "." + _b64(signature)


class NotificationManager:
    def __init__(self, store, security):
        self.store = store
        self.security = security
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        self._client = None
        self._oauth: dict = {}
        self._apns_token: dict = {}
        if not store.get_config("notifications")["revision"]:
            store.set_config("notifications", copy.deepcopy(_DEFAULT), 0)

    def get_config(self) -> dict:
        record = self.store.get_config("notifications")
        result = copy.deepcopy(record)
        for provider in ("fcm", "apns"):
            key = result["value"].get(provider, {}).get("private_key")
            result["value"].setdefault(provider, {})["private_key"] = "***" if key else ""
        return result

    def set_config(self, value: dict, revision: int) -> dict:
        if not isinstance(value, dict) or set(value) - set(_DEFAULT):
            raise OperationError("invalid_notification_settings", "Unknown notification configuration fields")
        existing = self.store.get_config("notifications")["value"]
        config = copy.deepcopy(_DEFAULT)
        config.update(copy.deepcopy(value))
        if not isinstance(config["enabled"], bool):
            raise OperationError("invalid_notification_settings", "Notification enabled must be a boolean")
        for provider, template in (("fcm", _DEFAULT["fcm"]), ("apns", _DEFAULT["apns"])):
            supplied = config[provider]
            if not isinstance(supplied, dict) or set(supplied) - set(template):
                raise OperationError("invalid_notification_settings", "Unknown " + provider + " fields")
            config[provider] = dict(template, **supplied)
            if any(not isinstance(item, str) for item in config[provider].values()):
                raise OperationError("invalid_notification_settings", "Provider settings must be strings")
            if config[provider]["private_key"] == "***":
                config[provider]["private_key"] = existing.get(provider, {}).get("private_key", "")
            if config[provider]["private_key"]:
                try:
                    key = serialization.load_pem_private_key(config[provider]["private_key"].encode(), password=None)
                except (ValueError, TypeError) as exc:
                    raise OperationError("invalid_provider_key", "Invalid " + provider + " private key") from exc
                if provider == "fcm" and (not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048):
                    raise OperationError("invalid_provider_key", "FCM requires a service-account RSA key of at least 2048 bits")
                if provider == "apns" and (not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1)):
                    raise OperationError("invalid_provider_key", "APNs requires an Apple-issued P-256 private key")
        fcm, apns = config["fcm"], config["apns"]
        if fcm["project_id"] and not re.fullmatch(r"[a-z0-9][a-z0-9-]{4,62}", fcm["project_id"]):
            raise OperationError("invalid_notification_settings", "Invalid Firebase project ID")
        if apns["environment"] not in {"production", "sandbox"}:
            raise OperationError("invalid_notification_settings", "APNs environment must be production or sandbox")
        if apns["topic"] and not re.fullmatch(r"[A-Za-z0-9.-]{3,255}", apns["topic"]):
            raise OperationError("invalid_notification_settings", "Invalid APNs application topic")
        configured = self._configured(config)
        if config["enabled"] and not any(configured.values()):
            raise OperationError("notification_credentials_required", "Configure complete FCM or APNs credentials before enabling delivery", 409)
        self.store.set_config("notifications", config, revision)
        with self._lock:
            self._oauth.clear()
            self._apns_token.clear()
        return self.get_config()

    @staticmethod
    def _configured(config: dict) -> dict:
        fcm = config.get("fcm", {})
        apns = config.get("apns", {})
        return {"fcm": all(fcm.get(key) for key in ("project_id", "client_email", "private_key")),
                "apns": all(apns.get(key) for key in ("team_id", "key_id", "private_key", "topic"))}

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        import httpx
        self._client = httpx.Client(http2=True, timeout=20, follow_redirects=False,
                                    limits=httpx.Limits(max_connections=4, max_keepalive_connections=2))
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="agent-notifications", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=25)
        if self._client and (not self._thread or not self._thread.is_alive()):
            self._client.close()

    def register(self, actor: dict, provider: str, token: str, min_severity: str = "warning") -> dict:
        self.security.authorize(actor, "view")
        if provider not in {"fcm", "apns"} or min_severity not in _SEVERITY:
            raise OperationError("invalid_registration", "Select a supported provider and severity")
        if not isinstance(token, str) or not 16 <= len(token) <= 4096 or any(char.isspace() for char in token):
            raise OperationError("invalid_registration", "A valid provider registration token is required")
        if provider == "apns" and not re.fullmatch(r"[0-9a-fA-F]{64,200}", token):
            raise OperationError("invalid_registration", "APNs token must be hexadecimal")
        with self._lock:
            record = self.store.get_config("_notification_targets", {})
            targets = dict(record["value"])
            identifier = actor["id"] + ":" + provider
            targets[identifier] = {"id": identifier, "device_id": actor["id"], "provider": provider,
                                   "token": token, "min_severity": min_severity, "created": time.time()}
            self.store.set_config("_notification_targets", targets, record["revision"])
        self.store.append_audit(actor, "notifications.register", "succeeded", {"provider": provider})
        return {"ok": True, "provider": provider}

    def unregister(self, actor: dict, provider: str) -> dict:
        self.security.authorize(actor, "view")
        if provider not in {"fcm", "apns"}:
            raise OperationError("invalid_registration", "Unknown notification provider")
        with self._lock:
            record = self.store.get_config("_notification_targets", {})
            targets = dict(record["value"])
            targets.pop(actor["id"] + ":" + provider, None)
            self.store.set_config("_notification_targets", targets, record["revision"])
        self.store.append_audit(actor, "notifications.unregister", "succeeded", {"provider": provider})
        return {"ok": True}

    def status(self, actor: dict) -> dict:
        config = self.store.get_config("notifications")["value"]
        targets = self.store.get_config("_notification_targets", {})["value"]
        return {"enabled": config.get("enabled", False), "configured": self._configured(config),
                "registrations": [{key: target[key] for key in ("provider", "min_severity", "created")}
                                  for target in targets.values() if target["device_id"] == actor["id"]],
                "delivery": "best_effort", "inbox": "agent_events"}

    def test(self, actor: dict) -> dict:
        status = self.status(actor)
        if not status["enabled"] or not status["registrations"]:
            raise OperationError("notifications_not_ready", "Enable a configured provider and register this device before testing delivery", 409)
        event = self.store.append_event("notifications.test", "RDPMonitor notification test", "warning",
                                        {"target_device": actor["id"]}, actor=actor)
        return {"event_id": event["id"], "state": "queued", "message": "Test event persisted; delivery has not yet been confirmed"}

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                # The outbox remains at its previous durable cursor on failure.
                # No secret-rich provider response is logged or sent to clients.
                self._stop.wait(10)
            self._stop.wait(2)

    def _tick(self) -> None:
        config_record = self.store.get_config("notifications")
        config = config_record["value"]
        if not config.get("enabled"):
            return
        with self._lock:
            state_record = self.store.get_config("_notification_outbox", {"cursor": 0, "pending": []})
            state = copy.deepcopy(state_record["value"])
            targets = self.store.get_config("_notification_targets", {})["value"]
            changed = False
            if len(state["pending"]) < 1000:
                for event in self.store.events(after=state["cursor"], limit=100):
                    if len(state["pending"]) + len(targets) > 2000:
                        break
                    if not event["kind"].startswith("notifications.") or event["kind"] == "notifications.test":
                        for target in targets.values():
                            addressed = (event.get("data") or {}).get("target_device")
                            if addressed and addressed != target["device_id"]:
                                continue
                            if _SEVERITY.get(event.get("severity"), 0) >= _SEVERITY[target["min_severity"]]:
                                state["pending"].append({"event_id": event["id"], "target_id": target["id"],
                                                         "attempts": 0, "due": time.time(), "kind": event["kind"]})
                    state["cursor"] = event["id"]
                    changed = True
            remaining = []
            for delivery in state["pending"]:
                if self._stop.is_set():
                    remaining.append(delivery)
                    continue
                target = targets.get(delivery["target_id"])
                if target is None:
                    changed = True
                    continue
                try:
                    self.security.active_actor(target["device_id"])
                except OperationError:
                    changed = True
                    continue
                if delivery["due"] > time.time():
                    remaining.append(delivery)
                    continue
                try:
                    self._send(target, delivery, config, config_record["revision"])
                    self.store.append_event("notifications.delivered", "Push provider accepted a notification", "info",
                                            {"event_id": delivery["event_id"], "device_id": target["device_id"], "provider": target["provider"]})
                except Exception:
                    delivery["attempts"] += 1
                    if delivery["attempts"] < 5:
                        delivery["due"] = time.time() + min(600, 10 * (2 ** delivery["attempts"]))
                        remaining.append(delivery)
                    else:
                        self.store.append_event("notifications.failed", "Push delivery failed; the event remains in the agent inbox", "warning",
                                                {"event_id": delivery["event_id"], "device_id": target["device_id"], "provider": target["provider"]})
                changed = True
            if changed:
                state["pending"] = remaining
                self.store.set_config("_notification_outbox", state, state_record["revision"])

    def _send(self, target: dict, delivery: dict, config: dict, revision: int) -> None:
        now = int(time.time())
        identity = self.store.identity()
        data = {"event_id": str(delivery["event_id"]), "agent_id": identity["id"], "kind": delivery["kind"]}
        if target["provider"] == "fcm":
            provider = config["fcm"]
            if not self._configured(config)["fcm"]:
                raise OperationError("notification_credentials_required", "FCM credentials are incomplete", 409)
            if self._oauth.get("revision") != revision or self._oauth.get("expires", 0) < now + 60:
                assertion = _jwt({"alg": "RS256", "typ": "JWT"},
                                 {"iss": provider["client_email"], "scope": "https://www.googleapis.com/auth/firebase.messaging",
                                  "aud": "https://oauth2.googleapis.com/token", "iat": now, "exp": now + 3600}, provider["private_key"], "RS256")
                response = self._client.post("https://oauth2.googleapis.com/token", data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion})
                if response.status_code != 200:
                    raise OperationError("push_authentication_failed", "FCM rejected notification sender credentials", 502)
                token = response.json()
                self._oauth = {"revision": revision, "token": token["access_token"], "expires": now + min(int(token.get("expires_in", 3600)), 3600)}
            response = self._client.post("https://fcm.googleapis.com/v1/projects/" + provider["project_id"] + "/messages:send",
                                         headers={"Authorization": "Bearer " + self._oauth["token"]},
                                         json={"message": {"token": target["token"], "data": data,
                                                           "notification": {"title": "RDPMonitor alert", "body": "Open the app to view an agent event."}}})
            if response.status_code != 200:
                raise OperationError("push_rejected", "FCM did not accept the notification", 502)
        else:
            provider = config["apns"]
            if not self._configured(config)["apns"]:
                raise OperationError("notification_credentials_required", "APNs credentials are incomplete", 409)
            if self._apns_token.get("revision") != revision or self._apns_token.get("expires", 0) < now:
                token = _jwt({"alg": "ES256", "kid": provider["key_id"]}, {"iss": provider["team_id"], "iat": now}, provider["private_key"], "ES256")
                self._apns_token = {"revision": revision, "token": token, "expires": now + 3000}
            host = "api.sandbox.push.apple.com" if provider["environment"] == "sandbox" else "api.push.apple.com"
            response = self._client.post("https://" + host + "/3/device/" + target["token"],
                                         headers={"authorization": "bearer " + self._apns_token["token"], "apns-topic": provider["topic"],
                                                  "apns-push-type": "alert", "apns-priority": "10", "apns-id": str(uuid.uuid4())},
                                         json={"aps": {"alert": {"title": "RDPMonitor alert", "body": "Open the app to view an agent event."}, "sound": "default"}, **data})
            if response.status_code != 200:
                raise OperationError("push_rejected", "APNs did not accept the notification", 502)
