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
