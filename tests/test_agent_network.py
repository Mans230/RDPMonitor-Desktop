"""Agent-owned network reachability watch.

Exercises the debounced state machine, the target parser and the telemetry-thread
integration without opening real sockets: the probe is injected.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.network import STATE_DOWN, STATE_UNKNOWN, STATE_UP, NetworkWatch, split_target
from agent.runtime import AgentRuntime


ROOT = Path(__file__).resolve().parents[1]


class TargetParsingTests(unittest.TestCase):
    def test_plain_host_uses_the_default_port(self):
        self.assertEqual(split_target("1.1.1.1"), ("1.1.1.1", 443))
        self.assertEqual(split_target("example.com"), ("example.com", 443))

    def test_explicit_ports_are_honoured(self):
        self.assertEqual(split_target("8.8.8.8:53"), ("8.8.8.8", 53))
        self.assertEqual(split_target("[2606:4700:4700::1111]:443"), ("2606:4700:4700::1111", 443))

    def test_bare_ipv6_and_malformed_values_fall_back_safely(self):
        self.assertEqual(split_target("2606:4700:4700::1111"), ("2606:4700:4700::1111", 443))
        self.assertEqual(split_target(""), ("1.1.1.1", 443))
        self.assertEqual(split_target("host:70000"), ("host:70000", 443))


class NetworkWatchTests(unittest.TestCase):
    def test_first_success_establishes_state_without_a_transition(self):
        state = NetworkWatch().evaluate(True, 100.0, "one.one.one.one")
        self.assertEqual(state["state"], STATE_UP)
        self.assertFalse(state["changed"])

    def test_unknown_before_any_probe(self):
        self.assertEqual(NetworkWatch().status()["state"], STATE_UNKNOWN)
        self.assertIsNone(NetworkWatch().status()["checked_at"])

    def test_one_failure_does_not_raise_a_false_alarm(self):
        watch = NetworkWatch(down_streak=2)
        watch.evaluate(True, 100.0)
        self.assertFalse(watch.evaluate(False, 160.0)["changed"])
        self.assertEqual(watch.status()["state"], STATE_UP)

    def test_threshold_failures_report_down_from_the_first_failure(self):
        watch = NetworkWatch(down_streak=2)
        watch.evaluate(True, 100.0)
        watch.evaluate(False, 160.0)
        state = watch.evaluate(False, 220.0)
        self.assertEqual(state["state"], STATE_DOWN)
        self.assertTrue(state["changed"])
        self.assertEqual(state["down_since"], 160.0)
        self.assertEqual(state["since"], 220.0)

    def test_recovery_reports_the_outage_duration(self):
        watch = NetworkWatch(down_streak=1, up_streak=1)
        watch.evaluate(True, 0.0)
        watch.evaluate(False, 60.0)
        state = watch.evaluate(True, 300.0)
        self.assertEqual(state["state"], STATE_UP)
        self.assertTrue(state["changed"])
        self.assertEqual(state["seconds_down"], 240)
        self.assertIsNone(state["down_since"])

    def test_up_streak_debounces_a_flapping_recovery(self):
        watch = NetworkWatch(down_streak=1, up_streak=2)
        watch.evaluate(True, 0.0)
        watch.evaluate(False, 10.0)
        self.assertFalse(watch.evaluate(True, 20.0)["changed"])
        self.assertEqual(watch.evaluate(True, 30.0)["state"], STATE_UP)


class NetworkIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime = AgentRuntime(ROOT, Path(self.temporary.name))
        self.addCleanup(self.runtime.store.close)
        self.runtime.network_interval = 0.0

    def tick(self, reachable):
        self.runtime.network_probe = lambda target, timeout: reachable
        self.runtime._network_tick()

    def events(self, kind):
        return [event for event in self.runtime.store.events(after=0, limit=100)
                if event["kind"] == kind]

    def test_transitions_are_recorded_as_durable_events(self):
        self.tick(True)
        self.assertEqual(self.events("network.down"), [])
        self.tick(False)
        self.assertEqual(self.events("network.down"), [])
        self.tick(False)
        self.assertEqual(len(self.events("network.down")), 1)
        self.tick(True)
        self.assertEqual(len(self.events("network.up")), 1)
        self.assertEqual(len(self.events("network.down")), 1)

    def test_health_reports_the_current_network_state(self):
        self.tick(True)
        health = self.runtime.health()
        self.assertEqual(health["network"]["state"], STATE_UP)
        self.assertEqual(health["network"]["target"], "1.1.1.1")

    def test_network_health_operation_is_registered(self):
        catalog = {item["id"]: item for item in self.runtime.catalog()}
        self.assertIn("monitoring.network_health", catalog)
        self.assertEqual(catalog["monitoring.network_health"]["capability"], "view")
        self.assertEqual(catalog["monitoring.network_health"]["section"], "monitoring")

    def test_read_only_agent_never_probes(self):
        self.runtime.read_only = True
        seen = []
        self.runtime.network_probe = lambda target, timeout: seen.append(target) or True
        self.runtime._network_tick()
        self.assertEqual(seen, [])

    def test_disabled_net_watch_skips_probing(self):
        seen = []
        with patch.object(self.runtime.backend, "get_config",
                          return_value={"revision": 1, "value": {"net_watch": False, "ping_target": "1.1.1.1"}}):
            self.runtime.network_probe = lambda target, timeout: seen.append(target) or True
            self.runtime._network_tick()
        self.assertEqual(seen, [])

    def test_probe_exception_is_treated_as_unreachable(self):
        def explode(target, timeout):
            raise OSError("no route")
        self.runtime.network_probe = explode
        self.runtime._network_tick()
        self.runtime._network_tick()
        self.assertEqual(self.runtime.network.status()["state"], STATE_DOWN)


if __name__ == "__main__":
    unittest.main()
