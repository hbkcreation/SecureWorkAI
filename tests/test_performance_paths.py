import time
import unittest

import numpy as np

from app.ml import live_synthetic as ls
from app.security.flow_aggregator import LiveFlowAggregator
from app.security.network_monitor import NetworkMonitor, PacketRecord
from app.security.packet_pipeline import PacketPipeline
from app.security.rule_ids import RuleBasedIDS


def pkt(t, src="10.0.0.2", sport=1000, dst="10.0.0.1", dport=80, proto="TCP", flags="A"):
    return PacketRecord(t, src, dst, proto, sport, dport, 100, flags)


class AggregatorExpiryTests(unittest.TestCase):
    def test_idle_flows_expire_oldest_first_and_active_ones_stay(self):
        done = []
        agg = LiveFlowAggregator(on_flow_completed=done.append, idle_timeout_seconds=5)
        agg.process_packet(pkt(0, sport=1))       # flow A, idle after t=5
        agg.process_packet(pkt(3, sport=2))       # flow B
        agg.process_packet(pkt(4, sport=1))       # A active again at t=4
        agg.process_packet(pkt(8, sport=3))       # B idle (3 -> 8), A (4 -> 8) not yet
        self.assertEqual([f.source_port for f in done], [2])
        agg.process_packet(pkt(20, sport=4))      # everything older expires
        self.assertEqual({f.source_port for f in done}, {1, 2, 3})
        self.assertEqual(agg.active_flow_count, 1)

    def test_many_flows_stay_fast(self):
        agg = LiveFlowAggregator(idle_timeout_seconds=60)
        t0 = time.perf_counter()
        for i in range(30000):
            agg.process_packet(pkt(i * 0.001, src=f"10.1.{i % 250}.{i % 200}", sport=1000 + i % 60000))
        self.assertLess(time.perf_counter() - t0, 5.0)  # was quadratic: tens of seconds


class PipelineTests(unittest.TestCase):
    def test_processes_everything_and_never_blocks_when_full(self):
        seen = []
        p = PacketPipeline([seen.append], maxsize=10)
        t0 = time.perf_counter()
        for i in range(1000):  # worker not started yet: queue fills, extras are dropped, submit never blocks
            p.submit(i)
        self.assertLess(time.perf_counter() - t0, 1.0)
        self.assertEqual(p.dropped, 990)
        p.start()
        time.sleep(0.5)
        p.stop()
        self.assertEqual(len(seen), 10)

    def test_handler_exception_does_not_kill_worker(self):
        seen = []

        def bad(x):
            raise RuntimeError("x")
        p = PacketPipeline([bad, seen.append])
        p.start()
        for i in range(5):
            p.submit(i)
        time.sleep(0.5)
        p.stop()
        self.assertEqual(seen, [0, 1, 2, 3, 4])


class BoundedMemoryTests(unittest.TestCase):
    def test_monitor_caps_tracked_flows(self):
        m = NetworkMonitor()
        m.MAX_TRACKED_FLOWS = 50
        class P:  # minimal stand-in; process_packet needs extract_packet_features, so insert records directly
            pass
        for i in range(200):
            rec = pkt(i, sport=i)
            with m._lock:
                m._flows[rec.flow_key] = object()
                if len(m._flows) > m.MAX_TRACKED_FLOWS:
                    del m._flows[next(iter(m._flows))]
        self.assertEqual(m.flow_count, 50)

    def test_rule_ids_prunes_idle_state_and_counts_alerts(self):
        ids = RuleBasedIDS(window=10, scan_ports=10**6, syn_threshold=10**6, rate_threshold=10**6)
        ids.start()
        for i in range(3000):
            ids.process_packet(pkt(i * 0.01, src=f"9.9.{i % 250}.{i // 250}", dport=1000 + i))
        ids.process_packet(pkt(1000.0, src="1.1.1.1"))  # far in the future triggers pruning
        self.assertLess(len(ids._ports) + len(ids._rate), 10)
        ids2 = RuleBasedIDS(scan_ports=5, syn_threshold=10**6)
        ids2.start()
        for i in range(10):
            ids2.process_packet(pkt(i * 0.01, dport=2000 + i))
        self.assertEqual(ids2.alert_count, 1)
        self.assertEqual(len(ids2.alerts_since(0)), 1)
        self.assertEqual(ids2.alerts_since(1), ())


class MlBatchTests(unittest.TestCase):
    def test_batch_equals_single_scoring(self):
        import os, tempfile
        from pathlib import Path
        d = Path(tempfile.mkdtemp())
        ls.train(d / "m.joblib", d / "r.json")
        from tests.test_live_synthetic_ml import flow
        flows = [flow(2, 0, 90, 0, 0.01, port=22), flow(30, 60, 9000, 80000, 5), flow(4000, 100, 5400000, 6000, 200),
                 flow(8000, 0, 640000, 0, 3, "udp", 53)]
        single = ls.LiveMLAnalyzer(d / "m.joblib"); single.load_or_train(); single.start()
        batch = ls.LiveMLAnalyzer(d / "m.joblib", batch=True); batch.load_or_train(); batch.start()
        for f in flows:
            single.inspect_completed_flow(f)
            batch.inspect_completed_flow(f)
        self.assertEqual(batch.flows_scored, 0)  # queued, not scored yet
        self.assertEqual(batch.flush(), 4)
        self.assertEqual([e.label for e in single.events], [e.label for e in batch.events])
        self.assertEqual((single.flows_scored, single.attack_flows), (batch.flows_scored, batch.attack_flows))


if __name__ == "__main__":
    unittest.main()


class NoiseFilterTests(unittest.TestCase):
    def test_multicast_and_broadcast_are_noise(self):
        from app.security.traffic_filters import is_noise_destination as n
        for ip in ("239.255.255.250", "224.0.0.251", "255.255.255.255", "ff02::fb"):
            self.assertTrue(n(ip), ip)
        for ip in ("10.0.0.1", "8.8.8.8", "", None, "not-an-ip"):
            self.assertFalse(n(ip), ip)

    def test_ml_skips_multicast_flows_and_ignores_weak_guesses(self):
        import tempfile
        from pathlib import Path
        from tests.test_live_synthetic_ml import flow
        d = Path(tempfile.mkdtemp())
        ls.train(d / "m.joblib", d / "r.json")
        a = ls.LiveMLAnalyzer(d / "m.joblib")
        a.load_or_train()
        a.start()
        f = flow(8000, 0, 640000, 0, 3, "udp", 1900)  # flood-shaped, but to multicast
        object.__setattr__(f, "destination_ip", "239.255.255.250")
        a.inspect_completed_flow(f)
        self.assertEqual((a.flows_scored, a.skipped_noise, a.attack_flows), (0, 1, 0))
        a.inspect_completed_flow(flow(8000, 0, 640000, 0, 3, "udp", 53))  # same shape, unicast
        self.assertEqual(a.attack_flows, 1)
        # a guess below the confidence floor counts as normal
        a2 = ls.LiveMLAnalyzer(d / "m.joblib")
        a2.load_or_train()
        a2.start()
        orig = ls.MIN_ATTACK_CONFIDENCE
        ls.MIN_ATTACK_CONFIDENCE = 1.01
        try:
            a2.inspect_completed_flow(flow(8000, 0, 640000, 0, 3, "udp", 53))
        finally:
            ls.MIN_ATTACK_CONFIDENCE = orig
        self.assertEqual((a2.flows_scored, a2.attack_flows), (1, 0))

    def test_rule_ids_ignores_multicast_rate(self):
        ids = RuleBasedIDS(rate_threshold=50, scan_ports=10**6, syn_threshold=10**6)
        ids.start()
        for i in range(500):
            ids.process_packet(pkt(i * 0.001, dst="239.255.255.250", dport=1900, proto="UDP"))
        self.assertEqual(ids.alert_count, 0)
        for i in range(500):
            ids.process_packet(pkt(i * 0.001, dst="10.0.0.1", dport=80))
        self.assertEqual(ids.alert_count, 1)
