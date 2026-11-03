import json
import os
import tempfile
import unittest

from app.security.network_monitor import PacketRecord
from app.security.rule_ids import ProtocolCounter, RuleBasedIDS
from app.security.workspace_apps import WorkspaceApp, launch, load_workspace_apps


def pkt(t, port=80, flags="S", proto="TCP", src="10.0.0.9", dst="10.0.0.1"):
    return PacketRecord(t, src, dst, proto, 50000, port, 60, flags)


class RuleIDSTests(unittest.TestCase):
    def test_inactive_ignores_packets(self):
        ids = RuleBasedIDS()
        ids.process_packet(pkt(1))
        self.assertEqual(ids.packets_checked, 0)

    def test_port_scan_detected_once_with_cooldown(self):
        ids = RuleBasedIDS(scan_ports=20, syn_threshold=10**6)
        ids.start()
        for i in range(60):
            ids.process_packet(pkt(i * 0.01, port=1000 + i, flags="SA"))
        rules = [a.rule for a in ids.alerts]
        self.assertEqual(rules, ["PORT_SCAN"])

    def test_syn_flood_critical(self):
        ids = RuleBasedIDS(syn_threshold=100, scan_ports=10**6)
        ids.start()
        for i in range(150):
            ids.process_packet(pkt(i * 0.01, port=443, flags="S"))
        self.assertEqual([(a.rule, a.severity) for a in ids.alerts], [("SYN_FLOOD", "critical")])

    def test_normal_traffic_no_alert(self):
        ids = RuleBasedIDS()
        ids.start()
        for i in range(50):
            ids.process_packet(pkt(i * 1.0, port=443, flags="PA"))
        self.assertEqual(ids.alerts, ())

    def test_old_packets_expire_from_window(self):
        ids = RuleBasedIDS(scan_ports=20, syn_threshold=10**6)
        ids.start()
        for i in range(19):
            ids.process_packet(pkt(i * 0.01, port=1000 + i, flags="SA"))
        ids.process_packet(pkt(100.0, port=5000, flags="SA"))  # outside window
        self.assertEqual(ids.alerts, ())

    def test_protocol_counter(self):
        c = ProtocolCounter()
        for proto in ("TCP", "tcp", "UDP"):
            c.add(pkt(1, proto=proto))
        self.assertEqual(c.snapshot(), {"TCP": 2, "UDP": 1})


class WorkspaceTests(unittest.TestCase):
    def test_missing_or_bad_config_fails_closed(self):
        self.assertEqual(load_workspace_apps("/nonexistent.json"), [])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("not json")
        self.addCleanup(os.unlink, f.name)
        self.assertEqual(load_workspace_apps(f.name), [])

    def test_only_approved_apps_launch(self):
        approved = [WorkspaceApp("Echo", "true")]
        with self.assertRaises(PermissionError):
            launch(WorkspaceApp("Evil", "true"), approved)
        launch(approved[0], approved).wait()  # approved & resolvable on PATH

    def test_loads_config(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"approved_apps": [{"name": "A", "command": "a.exe"}, {"name": "", "command": "x"}]}, f)
        self.addCleanup(os.unlink, f.name)
        self.assertEqual(load_workspace_apps(f.name), [WorkspaceApp("A", "a.exe")])


if __name__ == "__main__":
    unittest.main()
