"""Application entry point for SecureWork AI."""
import logging
import sys
from PySide6.QtWidgets import QApplication
from app.security.network_monitor import NetworkMonitor
from app.security.usb_checker import USBAdapterChecker
from app.ui.dashboard_window import DashboardWindow
from app.ui.login_window import LoginWindow
from app.ui import theme
from app.ui.widgets import app_icon
from app.ui.workspace_window import WorkspaceWindow
from app.utils.logging_config import configure_logging


class SecureWorkApplication:
    def __init__(self, app: QApplication) -> None:
        self.app = app
        self.usb_checker = USBAdapterChecker()
        self.network_monitor = NetworkMonitor(usb_checker=self.usb_checker)
        self.login_window = LoginWindow(self.show_dashboard)
        self.dashboard_window = None
        self.workspace_window = None

    def show_dashboard(self) -> None:
        self.login_window.hide()
        self.dashboard_window = DashboardWindow(
            self.logout,
            usb_checker=self.usb_checker,
            network_monitor=self.network_monitor,
            username=self.login_window.username.text().strip(),
        )
        self.dashboard_window.show()
        self.workspace_window = WorkspaceWindow()
        self.workspace_window.show()

    def logout(self) -> None:
        logging.getLogger(__name__).info("User logged out")
        if self.network_monitor.is_active():
            self.network_monitor.stop_capture()
        if self.workspace_window is not None:
            self.workspace_window.close()
            self.workspace_window = None
        if self.dashboard_window is not None:
            self.dashboard_window.close()
            self.dashboard_window = None
        self.login_window.password.clear()
        self.login_window.show()

    def shutdown(self) -> None:
        """Ensure no capture worker remains when the application exits."""
        if self.network_monitor.is_active():
            self.network_monitor.stop_capture()


def main() -> int:
    configure_logging()
    logger = logging.getLogger(__name__)
    app = QApplication(sys.argv)
    app.setApplicationName("SecureWork AI")
    app.setWindowIcon(app_icon())
    theme.apply(theme.saved_mode(), save=False)
    application = SecureWorkApplication(app)
    app.aboutToQuit.connect(application.shutdown)
    application.login_window.show()
    logger.info("SecureWork AI started")
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
