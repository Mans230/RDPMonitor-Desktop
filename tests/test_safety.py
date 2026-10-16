import ctypes
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rdp_monitor as rm  # noqa: E402


class Result:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.old_config = rm.config
        rm.config = {
            "rdp_port": 3389,
            "rdp_allowed_ips": ["198.51.100.10"],
            "learned_ips": {},
            "learn_for_lockdown": False,
            "rdpallow_disabled_rules": [],
            "pre_default_inbound": {},
        }

    def tearDown(self):
        rm.config = self.old_config

    def test_lockdown_never_trusts_current_connection(self):
        rm.config["learned_ips"] = {
            "198.51.100.20": {"t": time.time(), "u": "owner"}}
        with mock.patch.object(rm, "get_rdp_ips",
                               return_value=["203.0.113.66"]):
            self.assertEqual(rm.lockdown_ips(), ["198.51.100.10"])
            rm.config["learn_for_lockdown"] = True
            self.assertEqual(rm.lockdown_ips(),
                             ["198.51.100.10", "198.51.100.20"])

    

    def test_trusted_firewall_rules_are_explicit_tcp_and_udp(self):
        calls = []

        def fake_netsh(args):
            calls.append(args)
            return True, ""

        with mock.patch.object(rm, "_netsh", side_effect=fake_netsh), \
                mock.patch.object(rm, "ps_ok", return_value=True):
            ok, _ = rm._create_trusted_rules(3389, ["198.51.100.10"])
        self.assertTrue(ok)
        adds = [" ".join(c) for c in calls if "add" in c]
        self.assertTrue(any("protocol=TCP" in c for c in adds))
        self.assertTrue(any("protocol=UDP" in c for c in adds))

    def test_unblock_keeps_tracking_when_rule_remains(self):
        rm._blocked = {"203.0.113.8": time.time()}
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(rm, "BLOCKED_FILE", os.path.join(td, "blocked.json")), \
                mock.patch.object(rm, "_netsh", return_value=(True, "")), \
                mock.patch.object(rm.subprocess, "run", return_value=Result(b"1")):
            self.assertFalse(rm.unblock_ip("203.0.113.8"))
        self.assertIn("203.0.113.8", rm._blocked)

    def test_unblock_clears_tracking_when_rule_is_gone(self):
        rm._blocked = {"203.0.113.8": time.time()}
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(rm, "BLOCKED_FILE", os.path.join(td, "blocked.json")), \
                mock.patch.object(rm, "_netsh", return_value=(True, "")), \
                mock.patch.object(rm.subprocess, "run", return_value=Result(b"0")):
            self.assertTrue(rm.unblock_ip("203.0.113.8"))
        self.assertNotIn("203.0.113.8", rm._blocked)

    def test_firewall_transaction_persists_rule_ids(self):
        scans = iter([(["termservice-rule-id"], []), ([], [])])
        with mock.patch.object(rm, "_delete_trusted_rules"), \
                mock.patch.object(rm, "_create_trusted_rules", return_value=(True, "")), \
                mock.patch.object(rm, "_netsh", return_value=(True, "")), \
                mock.patch.object(rm, "_scan_broad_rules", side_effect=lambda *a, **k: next(scans)), \
                mock.patch.object(rm, "_set_rule_enabled", return_value=True), \
                mock.patch.object(rm, "save_config"), \
                mock.patch.object(rm.subprocess, "run", return_value=Result(b"")):
            self.assertTrue(rm.apply_rdp_allow(["198.51.100.10"]))
        self.assertEqual(rm.config["rdpallow_disabled_rules"],
                         ["termservice-rule-id"])

    @unittest.skipUnless(sys.platform == "win32", "Windows mutex test")
    def test_named_mutex_blocks_second_instance(self):
        old_handle = rm._instance_mutex
        old_base = rm.BASE_DIR
        rm._instance_mutex = None
        rm.BASE_DIR = old_base + "_test_" + str(os.getpid())
        try:
            self.assertTrue(rm.acquire_instance_lock())
            self.assertFalse(rm.acquire_instance_lock())
        finally:
            if rm._instance_mutex:
                ctypes.windll.kernel32.CloseHandle(rm._instance_mutex)
            rm._instance_mutex = old_handle
            rm.BASE_DIR = old_base

    def test_valid_ip_is_strict(self):
        for good in ("203.0.113.5", "::1", "2001:db8::1", "0.0.0.0"):
            self.assertTrue(rm._valid_ip(good), good)
        for bad in ("a1", ":::", "1.2.3", "999.1.1.1", "1.2.3.4;rm",
                    "", "1.2.3.4/24", "1.2.3.4.5"):
            self.assertFalse(rm._valid_ip(bad), bad)

    def test_disabled_accounts_cannot_reach_windows_mutation(self):
        rm.config["user_management"] = False
        with mock.patch.object(rm, "ps_ok") as windows_action:
            ok, _message = rm.api_user_action("disable", "someone")
        self.assertFalse(ok)
        windows_action.assert_not_called()

    def test_last_administrator_is_protected_through_shared_backend(self):
        rm.config["user_management"] = True
        account = {"name": "sole-admin", "admin": True, "enabled": True}
        with mock.patch.object(rm, "_local_users_detail", return_value=[account]), \
                mock.patch.object(rm, "get_rdp_sessions", return_value=[]), \
                mock.patch.object(rm, "ps_ok") as windows_action:
            ok, _message = rm.api_user_action("delete", "sole-admin")
        self.assertFalse(ok)
        windows_action.assert_not_called()

    def test_keepalive_name_is_not_an_execution_policy_bypass(self):
        rm.config.update(exec_enabled=False, keepalive=[{"name": "unapproved.exe"}])
        with mock.patch.object(rm.psutil, "process_iter", return_value=[]), \
                mock.patch.object(rm, "_event_sink", lambda *args, **kwargs: None), \
                mock.patch.object(rm.os, "startfile") as startfile, \
                mock.patch.object(rm.subprocess, "Popen") as popen:
            rm.check_keepalive()
        startfile.assert_not_called()
        popen.assert_not_called()

    

    

    

    

    

    

    














if __name__ == "__main__":
    unittest.main()
