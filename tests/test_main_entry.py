import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class MainEntryTests(unittest.TestCase):
    def test_main_module_imports_and_logout_works(self):
        from PySide6.QtWidgets import QApplication

        import app.main as main
        qapp = QApplication.instance() or QApplication([])
        application = main.SecureWorkApplication(qapp)
        application.show_dashboard()
        self.assertIsNotNone(application.dashboard_window)
        application.logout()
        self.assertIsNone(application.dashboard_window)
        application.shutdown()


if __name__ == "__main__":
    unittest.main()
