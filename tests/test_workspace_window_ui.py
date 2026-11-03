import os
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel  # noqa: E402

from app.security.workspace_apps import WorkspaceApp, load_workspace_apps  # noqa: E402
from app.ui import theme  # noqa: E402
from app.ui.workspace_window import WorkspaceWindow  # noqa: E402

APPS = [WorkspaceApp("Alpha", "/usr/bin/true"), WorkspaceApp("Beta", "/usr/bin/false")]


class WorkspaceWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qapp = QApplication.instance() or QApplication([])

    def setUp(self):
        self.cfg = os.path.join(tempfile.mkdtemp(), "w.json")
        self.win = WorkspaceWindow(self.cfg, discovered=APPS)

    def test_toggle_on_saves_and_enables_open(self):
        toggle, open_btn = self.win.rows["Alpha"]
        self.assertFalse(toggle.isChecked())
        self.assertFalse(open_btn.isEnabled())
        toggle.click()
        toggle, open_btn = self.win.rows["Alpha"]
        self.assertTrue(toggle.isChecked() and open_btn.isEnabled())
        self.assertEqual(load_workspace_apps(self.cfg), [APPS[0]])
        toggle.click()
        self.assertEqual(load_workspace_apps(self.cfg), [])

    def test_clicking_name_reveals_location(self):
        def texts():
            return [w.text() for w in self.win.findChildren(QLabel)]
        self.assertNotIn("/usr/bin/true", texts())
        self.win.toggle_location(APPS[0])
        self.assertIn("/usr/bin/true", texts())
        self.win.toggle_location(APPS[0])
        self.assertNotIn("/usr/bin/true", texts())

    def test_search_filters(self):
        self.win.search.setText("beta")
        self.assertEqual(list(self.win.rows), ["Beta"])


class ThemeTests(unittest.TestCase):
    def test_both_modes_build_and_switch(self):
        QApplication.instance() or QApplication([])
        for mode in ("dark", "light", "bogus"):
            theme.apply(mode, save=False)
            self.assertEqual(theme.mode(), mode if mode != "bogus" else "light")
            self.assertIn(theme.c("bg"), theme.build_stylesheet())
        self.assertEqual(theme.mode(), "light")


if __name__ == "__main__":
    unittest.main()


class ExeIconTests(unittest.TestCase):
    NPCAP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "npcap-1.89.exe")

    @classmethod
    def setUpClass(cls):
        cls.qapp = QApplication.instance() or QApplication([])

    def test_extracts_real_icon_from_exe(self):
        from app.security.exe_icon import extract_icon_ico
        if not os.path.isfile(self.NPCAP):
            self.skipTest("npcap installer not present")
        ico = extract_icon_ico(self.NPCAP)
        self.assertIsNotNone(ico)
        self.assertEqual(ico[:4], b"\x00\x00\x01\x00")

    def test_pixmap_uses_exe_icon_not_letter_tile(self):
        from app.ui.workspace_window import _exe_icon_pixmap
        if not os.path.isfile(self.NPCAP):
            self.skipTest("npcap installer not present")
        pm = _exe_icon_pixmap(self.NPCAP, 40)
        self.assertIsNotNone(pm)
        self.assertFalse(pm.isNull())

    def test_non_pe_and_garbage_files_return_none(self):
        from app.security.exe_icon import extract_icon_ico
        import tempfile
        for content in (b"", b"MZ" + b"\x00" * 5000, os.urandom(4096), b"hello world" * 500):
            with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
                f.write(content)
            self.addCleanup(os.unlink, f.name)
            self.assertIsNone(extract_icon_ico(f.name))
        self.assertIsNone(extract_icon_ico("/nonexistent/app.exe"))
