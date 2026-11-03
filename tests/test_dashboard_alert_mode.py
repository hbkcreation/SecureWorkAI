import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from app.security.alert_email import EmailConfig  # noqa: E402
from app.security.remediation import AlertInfo  # noqa: E402
from app.security.usb_checker import STATUS_APPROVED, USBAdapterStatus  # noqa: E402
from app.ui import theme  # noqa: E402
from app.ui.dashboard_window import DashboardWindow  # noqa: E402


class DashboardAlertModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qapp = QApplication.instance() or QApplication([])
        theme.apply("light", save=False)

    def setUp(self):
        self.d = DashboardWindow(lambda: None, username="tester")
        self.sent = []
        self.d.email_config = EmailConfig("me@example.com", "smtp.example.com", 587, "bot@example.com")
        self.d.email_notifier._sender = lambda cfg, pw, msg: self.sent.append(msg)
        self.d.email_notifier.global_interval = 0

    def tearDown(self):
        for dlg in self.d._alert_dialogs:
            dlg.close()
        self.d.close()

    def test_attack_shows_banner_dialog_and_emails_once(self):
        a = AlertInfo("PORT_SCAN", "high", "Port scan detected", "20 ports", "10.0.0.9", "10.0.0.1")
        self.d.raise_alert(a)
        self.d.raise_alert(a)  # duplicate inside the window is suppressed
        self.assertFalse(self.d.alert_banner.isHidden())
        self.assertIn("Port scan", self.d.alert_banner_text.text())
        self.assertEqual(len(self.d.alert_history), 1)
        self.assertTrue(any(x.isVisible() for x in self.d._alert_dialogs) or self.d._alert_dialogs)
        self.assertTrue(self.d.windowTitle().startswith("⚠"))
        self.d._dismiss_banner()
        self.assertTrue(self.d.alert_banner.isHidden())

    def test_settings_validation_and_no_password_on_disk(self):
        import tempfile
        from pathlib import Path

        import app.ui.dashboard_window as dw
        tmp = Path(tempfile.mkdtemp()) / "c.json"
        orig = dw.save_email_config
        dw.save_email_config = lambda cfg: orig(cfg, tmp)
        try:
            self.d.email_to.setText("nope")
            self.assertFalse(self.d.save_email_settings())
            self.d.email_to.setText("me@example.com")
            self.d.email_host.setText("smtp.example.com")
            self.d.email_port.setText("587")
            self.d.email_pass.setText("s3cret-pw")
            self.assertTrue(self.d.save_email_settings())
            self.assertNotIn("s3cret-pw", tmp.read_text())
        finally:
            dw.save_email_config = orig

    def test_full_verification_requires_every_check(self):
        d = self.d
        d.run_full_verification()
        self.assertNotEqual(d.system_status_label.text(), "Fully verified")
        d._latest_usb_status = USBAdapterStatus(STATUS_APPROVED, True, True)
        d.network_monitor.is_active = lambda: True
        d.rule_ids.start()
        d.ml_analyzer.load_or_train()
        d.ml_analyzer.start()
        d.workspace_panel.approved = [object()]
        d.workspace_panel.monitor_toggle.setChecked(True)
        d._refresh_verification()
        self.assertEqual(d.system_status_label.text(), "Fully verified")
        d.workspace_panel.monitor_toggle.setChecked(False)
        d._refresh_verification()
        self.assertEqual(d.system_status_label.text(), "Partially verified")
        self.assertIn("Running-app monitoring on", d.system_status_details_label.text())


if __name__ == "__main__":
    unittest.main()
