"""Separate Secure Workspace window.

Lists applications discovered on this device. Each has an Allow/Blocked toggle (saved to
config/workspace_apps.json) and an Open button that works only for allowed apps.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
                               QPushButton, QScrollArea, QVBoxLayout, QWidget)

from app.security.app_discovery import discover_installed_apps
from app.security.workspace_apps import (DEFAULT_CONFIG, WorkspaceApp, launch, load_workspace_apps,
                                         save_workspace_apps)

STYLE = """
QFrame#appRow { background: white; border: 1px solid #dce5ef; border-radius: 10px; }
QLabel#appName { font-weight: 600; color: #102a43; }
QPushButton#allowOn { background: #16794b; }
QPushButton#allowOn:hover { background: #11623d; }
QPushButton#allowOff { background: #b42318; }
QPushButton#allowOff:hover { background: #8f1c12; }
QPushButton:disabled { background: #c7d0dc; color: #f4f7fb; }
"""


class WorkspaceWindow(QMainWindow):
    def __init__(self, config_path=None, discovered: list[WorkspaceApp] | None = None) -> None:
        super().__init__()
        self.config_path = config_path or DEFAULT_CONFIG
        self.setWindowTitle("SecureWork AI | Secure Workspace")
        self.setMinimumSize(520, 460)
        self.setStyleSheet(STYLE)
        self.approved: list[WorkspaceApp] = load_workspace_apps(self.config_path)
        self._injected = discovered
        self.rows: dict[str, tuple[QPushButton, QPushButton]] = {}
        self._all: list[WorkspaceApp] = []

        central = QWidget()
        outer = QVBoxLayout(central)
        title = QLabel("Secure Workspace")
        title.setObjectName("pageTitle")
        self.summary = QLabel()
        self.summary.setObjectName("muted")
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search applications...")
        self.search.textChanged.connect(self._render)
        self.rescan_button = QPushButton("Rescan device")
        self.rescan_button.setObjectName("secondaryButton")
        self.rescan_button.clicked.connect(self.rescan)
        bar.addWidget(self.search, 1)
        bar.addWidget(self.rescan_button)
        self.list_layout = QVBoxLayout()
        self.list_layout.setSpacing(8)
        holder = QWidget()
        holder.setLayout(self.list_layout)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(holder)
        outer.addWidget(title)
        outer.addWidget(self.summary)
        outer.addLayout(bar)
        outer.addWidget(scroll, 1)
        self.setCentralWidget(central)
        self.rescan()

    # ----- data -----
    def rescan(self) -> None:
        found = self._injected if self._injected is not None else discover_installed_apps()
        by_cmd = {a.command.lower(): a for a in found}
        for a in self.approved:  # keep approved apps visible even if no longer discovered
            by_cmd.setdefault(a.command.lower(), a)
        self._all = sorted(by_cmd.values(), key=lambda a: a.name.lower())
        self._render()

    def is_allowed(self, app: WorkspaceApp) -> bool:
        return any(a.command.lower() == app.command.lower() for a in self.approved)

    def set_allowed(self, app: WorkspaceApp, allowed: bool) -> None:
        self.approved = [a for a in self.approved if a.command.lower() != app.command.lower()]
        if allowed:
            self.approved.append(app)
        try:
            save_workspace_apps(self.approved, self.config_path)
        except OSError as exc:
            QMessageBox.warning(self, "Could not save", f"Allow list was not saved: {exc}")
        self._render()

    # ----- ui -----
    def _render(self) -> None:
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.rows.clear()
        needle = self.search.text().strip().lower()
        shown = [a for a in self._all if needle in a.name.lower() or needle in a.command.lower()]
        self.summary.setText(f"{len(self._all)} applications found on this device | "
                             f"{len(self.approved)} allowed")
        if not shown:
            msg = QLabel("No applications found. Click 'Rescan device'." if not self._all
                         else "No applications match your search.")
            msg.setObjectName("muted")
            self.list_layout.addWidget(msg)
        for app in shown:
            self.list_layout.addWidget(self._row(app))
        self.list_layout.addStretch(1)

    def _row(self, app: WorkspaceApp) -> QFrame:
        allowed = self.is_allowed(app)
        row = QFrame()
        row.setObjectName("appRow")
        lay = QHBoxLayout(row)
        text = QVBoxLayout()
        name = QLabel(app.name)
        name.setObjectName("appName")
        path = QLabel(app.command)
        path.setObjectName("muted")
        path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        text.addWidget(name)
        text.addWidget(path)
        toggle = QPushButton("Allowed" if allowed else "Blocked")
        toggle.setObjectName("allowOn" if allowed else "allowOff")
        toggle.setToolTip("Click to " + ("block" if allowed else "allow") + " this application")
        toggle.clicked.connect(lambda _=False, a=app, v=not allowed: self.set_allowed(a, v))
        open_btn = QPushButton("Open")
        open_btn.setEnabled(allowed)
        open_btn.setToolTip("Open this application" if allowed else "Allow the application first")
        open_btn.clicked.connect(lambda _=False, a=app: self.open_app(a))
        lay.addLayout(text, 1)
        lay.addWidget(toggle)
        lay.addWidget(open_btn)
        self.rows[app.name] = (toggle, open_btn)
        return row

    def open_app(self, app: WorkspaceApp) -> None:
        try:
            launch(app, self.approved)
        except (PermissionError, FileNotFoundError, OSError) as exc:
            QMessageBox.warning(self, "Cannot open application", str(exc))
