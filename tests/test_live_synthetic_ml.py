import os
import tempfile
import unittest
from pathlib import Path

import numpy as np

from app.ml import live_synthetic as ls
from app.security.flow_aggregator import CompletedFlow


def flow(sp, dp, sb, db, dur, proto="tcp", port=443):
    return CompletedFlow("f", "10.0.0.9", "10.0.0.1", 4000, port, proto, 0.0, dur, sp + dp, sb + db, sp, dp, sb, db,
                         None, None, None, None, None, None, None, None, None, None, None, None, None, None, "idle")


class LiveSyntheticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        cls.report = ls.train(cls.dir / "m.joblib", cls.dir / "r.json")
        cls.analyzer = ls.LiveMLAnalyzer(cls.dir / "m.joblib")
        cls.analyzer.load_or_train()

    def test_generator_is_deterministic_and_balanced(self):
        X1, y1 = ls.generate(50, seed=3)
        X2, y2 = ls.generate(50, seed=3)
        self.assertTrue(np.array_equal(X1, X2))
        self.assertEqual(sorted(set(y1)), sorted(ls.CLASSES))
        self.assertEqual(X1.shape[1], len(ls.FEATURES))

    def test_report_marks_data_as_synthetic(self):
        self.assertIn("SYNTHETIC", self.report["data"])
        self.assertGreater(self.report["holdout_accuracy"], 0.9)

    def test_predictions_on_crafted_flows(self):
        a = self.analyzer
        self.assertEqual(a.predict_flow(flow(2, 0, 90, 0, 0.01, port=22))[0], "port_scan")
        self.assertEqual(a.predict_flow(flow(8000, 0, 640000, 0, 3, "udp", 53))[0], "dos_flood")
        self.assertEqual(a.predict_flow(flow(4000, 100, 5400000, 6000, 200))[0], "data_exfiltration")
        self.assertEqual(a.predict_flow(flow(30, 60, 9000, 80000, 5))[0], "normal")

    def test_analyzer_inactive_ignores_and_active_records(self):
        a = ls.LiveMLAnalyzer(self.dir / "m.joblib")
        a.load_or_train()
        a.inspect_completed_flow(flow(2, 0, 90, 0, 0.01))
        self.assertEqual(a.flows_scored, 0)
        a.start()
        a.inspect_completed_flow(flow(2, 0, 90, 0, 0.01))
        a.inspect_completed_flow(flow(30, 60, 9000, 80000, 5))
        self.assertEqual((a.flows_scored, a.attack_flows), (2, 1))
        self.assertEqual(a.events[0].label, "port_scan")

    def test_bad_model_file_retrains(self):
        bad = self.dir / "bad.joblib"
        bad.write_bytes(b"not a model")
        a = ls.LiveMLAnalyzer(bad)
        self.assertEqual(a.load_or_train(), "trained")
        self.assertTrue(a.loaded)


if __name__ == "__main__":
    unittest.main()
