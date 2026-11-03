import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel  # noqa: E402

from app.security import website_filter as wf  # noqa: E402
from app.ui.websites_panel import WebsitesPanel  # noqa: E402
from tests.test_website_filter import FakeRegistry  # noqa: E402


class WebsitesPanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qapp = QApplication.instance() or QApplication([])

    def make(self):
        d = Path(tempfile.mkdtemp())
        reg = FakeRegistry({"ProxyEnable": [4, 0]})
        ctl = wf.WebsiteFilterController(d / "w.json", wf.SystemProxy(registry=reg, backup_path=d / "b.json"))
        return WebsitesPanel(ctl), ctl, reg

    def texts(self, panel):
        return [w.text() for w in panel.findChildren(QLabel)]

    def test_add_normalises_lists_and_removes(self):
        panel, ctl, _reg = self.make()
        self.assertTrue(any("No allowed websites yet" in t for t in self.texts(panel)))
        panel.input.setText("https://Docs.Example.com/x")
        panel.add_clicked()
        self.assertEqual(ctl.sites, ["docs.example.com"])
        self.assertIn("docs.example.com", self.texts(panel))
        panel.input.setText("not a site")
        panel.add_clicked()
        self.assertIn("doesn't look like a website", panel.message.text())
        panel.remove("docs.example.com")
        self.assertEqual(ctl.sites, [])

    def test_toggle_on_with_empty_list_is_refused(self):
        panel, ctl, reg = self.make()
        with mock.patch("app.ui.websites_panel.QMessageBox.warning") as warn:
            panel.toggle.setChecked(True)
        self.assertTrue(warn.called)
        self.assertFalse(panel.toggle.isChecked())
        self.assertFalse(ctl.running)
        self.assertEqual(reg.values["ProxyEnable"], [4, 0])

    def test_toggle_on_and_restore_button(self):
        panel, ctl, reg = self.make()
        ctl.add_site("example.com")
        panel.toggle.setChecked(True)
        self.assertTrue(ctl.running)
        self.assertEqual(reg.values["ProxyEnable"], [4, 1])
        self.assertTrue(panel.status_label.text().startswith("On."))
        panel.restore_clicked()
        self.assertFalse(ctl.running)
        self.assertFalse(panel.toggle.isChecked())
        self.assertEqual(reg.values["ProxyEnable"], [4, 0])

    def test_removing_last_site_while_on_switches_blocking_off(self):
        panel, ctl, reg = self.make()
        ctl.add_site("example.com")
        panel.toggle.setChecked(True)
        panel.remove("example.com")
        self.assertFalse(ctl.running)
        self.assertEqual(reg.values["ProxyEnable"], [4, 0])

    def test_tamper_signal(self):
        panel, ctl, reg = self.make()
        ctl.add_site("example.com")
        panel.toggle.setChecked(True)
        seen = []
        panel.tampered.connect(lambda: seen.append(1))
        reg.set("ProxyEnable", 4, 0)
        panel._tick()
        self.assertEqual(seen, [1])
        self.assertEqual(reg.values["ProxyEnable"], [4, 1])
        panel.restore_clicked()

    def test_saved_enabled_state_is_reapplied_and_crash_recovered(self):
        panel, ctl, reg = self.make()
        ctl.add_site("example.com")
        panel.toggle.setChecked(True)
        ctl.proxy.stop()
        ctl.proxy = None  # crash: setting left pointing at a dead port
        d = ctl.config_path.parent
        ctl2 = wf.WebsiteFilterController(ctl.config_path, ctl.system_proxy)
        panel2 = WebsitesPanel(ctl2)
        panel2.apply_saved_state()  # recover() restores, then want_enabled re-enables with a new port
        self.assertTrue(ctl2.running)
        self.assertEqual(reg.values["ProxyServer"][1], f"127.0.0.1:{ctl2.proxy.port}")
        ctl2.disable()
        self.assertEqual(reg.values["ProxyEnable"], [4, 0])


if __name__ == "__main__":
    unittest.main()
