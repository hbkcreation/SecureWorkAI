"""Separate Secure Workspace window: launcher for company-approved applications only."""
from __future__ import annotations

from PySide6.QtWidgets import QLabel, QMainWindow, QMessageBox, QPushButton, QVBoxLayout, QWidget

from app.security.workspace_apps import WorkspaceApp, launch, load_workspace_apps, resolve


class WorkspaceWindow(QMainWindow):
    def __init__(self, config_path=None) -> None:
        super().__init__()
        self.setWindowTitle("SecureWork AI | Secure Workspace")
        self.setMinimumSize(360, 300)
        self.apps: list[WorkspaceApp] = load_workspace_apps(config_path) if config_path else load_workspace_apps()
        central = QWidget()
        layout = QVBoxLayout(central)
        title = QLabel("Approved company applications")
        title.setObjectName("cardHeading")
        layout.addWidget(title)
        self.buttons: dict[str, QPushButton] = {}
        if not self.apps:
            note = QLabel("No approved applications configured.\nCopy config/workspace_apps.example.json to "
                          "config/workspace_apps.json and list the permitted apps.")
            note.setWordWrap(True)
            note.setObjectName("muted")
            layout.addWidget(note)
        for app in self.apps:
            installed = resolve(app) is not None
            btn = QPushButton(app.name if installed else f"{app.name} (not installed)")
            btn.setEnabled(installed)
            btn.clicked.connect(lambda _=False, a=app: self.open_app(a))
            layout.addWidget(btn)
            self.buttons[app.name] = btn
        layout.addStretch(1)
        self.setCentralWidget(central)

    def open_app(self, app: WorkspaceApp) -> None:
        try:
            launch(app, self.apps)
        except (PermissionError, FileNotFoundError, OSError) as exc:
            QMessageBox.warning(self, "Cannot open application", str(exc))
