import json
import os
import tempfile
import unittest

from app.security import alert_email as ae
from app.security.app_monitor import check_running
from app.security.remediation import AlertInfo, advice_for
from app.security.verification import VerificationState, is_fully_verified, run_checks
from app.security.workspace_apps import WorkspaceApp

CFG = ae.EmailConfig("me@example.com", "smtp.example.com", 587, "bot@example.com")


class EmailTests(unittest.TestCase):
    def test_validation(self):
        self.assertTrue(ae.valid_email("a.b+c@sub.example.com"))
        for bad in ("", "no-at", "a@b", "a@b.c", "x@y.com\nBcc: evil@z.com"):
            self.assertFalse(ae.valid_email(bad), bad)
        self.assertTrue(ae.is_configured(CFG))
        self.assertFalse(ae.is_configured(ae.EmailConfig("me@example.com", "", 587)))

    def test_config_roundtrip_has_no_password(self):
        p = os.path.join(tempfile.mkdtemp(), "c.json")
        ae.save_config(CFG, p)
        self.assertEqual(ae.load_config(p), CFG)
        self.assertNotIn("password", json.dumps(json.load(open(p))).lower())
        self.assertEqual(ae.load_config("/nonexistent.json"), ae.EmailConfig())

    def test_message_has_steps_and_blocks_header_injection(self):
        a = AlertInfo("PORT_SCAN", "high", "Port scan\r\nBcc: evil@x.com", "20 ports", "10.0.0.9", "10.0.0.1")
        m = ae.build_message(CFG, a, hostname="LAPTOP\nX")
        self.assertNotIn("\n", m["Subject"])
        self.assertIsNone(m["Bcc"])
        body = m.get_content()
        self.assertIn("What to do now", body)
        self.assertIn("phishing", body.lower())
        self.assertIn("10.0.0.9", body)

    def test_notifier_sends_and_rate_limits(self):
        sent = []
        n = ae.EmailNotifier(lambda: CFG, sender=lambda c, pw, m: sent.append((pw, m)), min_interval=600, global_interval=0)
        n.set_password("secret")
        a = AlertInfo("PORT_SCAN", "high", "t", "d", "10.0.0.9")
        self.assertTrue(n.notify(a, wait=True))
        self.assertFalse(n.notify(a, wait=True))  # same kind+source inside window
        self.assertTrue(n.notify(AlertInfo("SYN_FLOOD", "critical", "t", "d", "10.0.0.9"), wait=True))
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0][0], "secret")
        self.assertIn("Email sent", n.status)

    def test_notifier_unconfigured_and_failure(self):
        n = ae.EmailNotifier(lambda: ae.EmailConfig(), sender=lambda *a: None)
        self.assertFalse(n.notify(AlertInfo("TEST", "low", "t", "d")))

        def boom(*_a):
            raise OSError("down")
        n2 = ae.EmailNotifier(lambda: CFG, sender=boom, global_interval=0)
        self.assertTrue(n2.notify(AlertInfo("TEST", "low", "t", "d"), wait=True))
        self.assertIn("Email failed", n2.status)


class RemediationTests(unittest.TestCase):
    def test_every_kind_has_steps(self):
        for kind in ("PORT_SCAN", "SYN_FLOOD", "HIGH_RATE", "DOS_FLOOD", "DATA_EXFILTRATION", "UNAUTHORIZED_APP", "TEST", "UNKNOWN"):
            adv = advice_for(kind)
            self.assertTrue(adv.summary and adv.steps)


class AppMonitorTests(unittest.TestCase):
    def test_only_installed_but_not_allowed_running_apps_alert(self):
        chrome = WorkspaceApp("Chrome", r"C:\Program Files\Google\chrome.exe")
        excel = WorkspaceApp("Excel", r"C:\Program Files\Office\EXCEL.EXE")
        game = WorkspaceApp("Game", r"C:\Games\game.exe")
        alerts = check_running([chrome, excel, game], [excel], {"chrome.exe", "excel.exe", "svchost.exe"})
        self.assertEqual([a.source for a in alerts], ["chrome.exe"])
        self.assertEqual(alerts[0].kind, "UNAUTHORIZED_APP")


class VerificationTests(unittest.TestCase):
    def test_full_only_when_every_check_passes(self):
        ok = VerificationState(True, True, True, True, 2, True)
        self.assertTrue(is_fully_verified(run_checks(ok)))
        for field in ("usb_adapter_approved", "capture_active", "rule_ids_active", "ml_active",
                      "app_monitor_on"):
            bad = VerificationState(**{**ok.__dict__, field: False})
            self.assertFalse(is_fully_verified(run_checks(bad)), field)
        self.assertFalse(is_fully_verified(run_checks(VerificationState(**{**ok.__dict__, "allowed_apps": 0}))))
        self.assertEqual(len(run_checks(ok)), 6)


if __name__ == "__main__":
    unittest.main()
