"""Security hardening regressions for the desktop agent and backup engine.

Covers the fail-closed configuration surface, the single shared secret-name
definition, the SHA-256 update comparison and the backup pre/post hook switch.
No real command, network or backup operation is executed.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from agent import store as agent_store
from agent.contracts import SECRET_ENVELOPE_WORDS, SECRET_NAME_WORDS, secret_named
from agent.runtime import AgentRuntime, _redact


ROOT = Path(__file__).resolve().parents[1]


class SecretDefinitionTests(unittest.TestCase):
    def test_names_that_read_as_credentials_are_detected(self):
        for name in ("password", "ssh_passphrase", "telegram_token", "private_key", "api_hash", "authorization"):
            self.assertTrue(secret_named(name), name)
        for name in ("instance_name", "cpu_alert_threshold", "tracked_ips"):
            self.assertFalse(secret_named(name), name)

    def test_envelope_words_are_a_superset_of_the_shared_names(self):
        self.assertTrue(SECRET_NAME_WORDS <= SECRET_ENVELOPE_WORDS)
        self.assertIs(agent_store._SECRET_KEYS, SECRET_ENVELOPE_WORDS)

    def test_job_transport_redacts_secret_shaped_keys(self):
        self.assertEqual(_redact({"telegram_token": "abc", "instance_name": "host"}),
                         {"telegram_token": "***", "instance_name": "host"})
        self.assertEqual(_redact({"api_hash": "abc"}), {"api_hash": "***"})

    def test_job_transport_keeps_user_visible_error_codes(self):
        self.assertEqual(_redact({"status": "failed", "code": "invalid_configuration"}),
                         {"status": "failed", "code": "invalid_configuration"})

    def test_durable_event_payloads_redact_envelope_keys(self):
        value = agent_store.redact({"code": "abc", "telegram_token": "abc", "safe": 1})
        self.assertEqual(value, {"code": "[redacted]", "telegram_token": "[redacted]", "safe": 1})


class EditableConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime = AgentRuntime(ROOT, Path(self.temporary.name))
        self.addCleanup(self.runtime.store.close)

    def test_legacy_credentials_are_not_editable(self):
        defaults = self.runtime.backend._editable_defaults()
        self.assertNotIn("telegram_token", defaults)
        self.assertNotIn("telegram_token_enc", defaults)

    def test_no_editable_default_looks_like_a_secret(self):
        for name in self.runtime.backend._editable_defaults():
            self.assertFalse(secret_named(name), name)

    def test_a_newly_added_secret_field_is_dropped_without_a_denylist_change(self):
        with patch.dict(self.runtime.backend.monitor.DEFAULT_CONFIG, {"future_api_credential": "x"}, clear=False):
            self.assertNotIn("future_api_credential", self.runtime.backend._editable_defaults())

    def test_read_configuration_never_exposes_the_token(self):
        value = self.runtime.backend.get_config("monitor")["value"]
        self.assertNotIn("telegram_token", value)
        self.assertNotIn("telegram_token_enc", value)



class BackupHookGuardTests(unittest.TestCase):
    """The backup pre/post hooks run with the worker identity, so an operator
    must be able to switch them off and every run must be auditable."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime = AgentRuntime(ROOT, Path(self.temporary.name))
        self.addCleanup(self.runtime.store.close)
        import scheduler
        self.scheduler = scheduler

    def test_default_configuration_disables_hooks(self):
        self.assertIs(self.runtime.backend.backup.config.DEFAULT_CONFIG["backup"]["hooks_enabled"], False)

    def test_disabled_hooks_do_not_execute(self):
        cfg = {"backup": {"pre_command": "echo hello", "hooks_enabled": False}}
        with patch.object(self.scheduler, "log") as log, patch.object(self.scheduler.subprocess, "Popen") as popen:
            self.assertTrue(self.scheduler.run_hook(cfg, "pre"))
        popen.assert_not_called()
        self.assertTrue(log.called)

    def test_a_disabled_hook_does_not_abort_the_mission(self):
        cfg = {"backup": {"post_command": "echo hello", "hooks_enabled": False}}
        with patch.object(self.scheduler, "log"), patch.object(self.scheduler.subprocess, "Popen") as popen:
            self.assertTrue(self.scheduler.run_hook(cfg, "post"))
        popen.assert_not_called()

    def test_a_nul_command_is_rejected_without_execution(self):
        cfg = {"backup": {"pre_command": "echo hello\x00whoami", "hooks_enabled": True}}
        with patch.object(self.scheduler, "log"), patch.object(self.scheduler.subprocess, "Popen") as popen:
            self.assertFalse(self.scheduler.run_hook(cfg, "pre"))
        popen.assert_not_called()

    def test_the_audit_line_does_not_contain_the_command_text(self):
        cfg = {"backup": {"pre_command": "echo SECRET_MARKER", "hooks_enabled": True}}
        fake = Mock()
        fake.communicate.return_value = ("", "")
        fake.returncode = 0
        with patch.object(self.scheduler, "log") as log, patch.object(self.scheduler.subprocess, "Popen", return_value=fake) as popen:
            self.assertTrue(self.scheduler.run_hook(cfg, "pre"))
        popen.assert_called_once()
        rendered = " ".join(str(call) for call in log.call_args_list)
        self.assertNotIn("SECRET_MARKER", rendered)
        self.assertIn("sha256", rendered)


if __name__ == "__main__":
    unittest.main()
