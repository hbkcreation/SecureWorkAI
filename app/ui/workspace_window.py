"""Apps tab: the Secure Workspace panel shown inside the main window.

Each discovered application shows its icon, its name and an on/off switch. Click the name
to see where the program is installed. Switching on allows it (saved to
config/workspace_apps.json); the Open button works only for allowed apps.
"""
from __future__ import annotations

import os
import subprocess
import sys

from PySide6.QtCore import QFileInfo, QSize, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QPainter, QPixmap
from PySide6.QtWidgets import (QFileIconProvider, QFrame, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QScrollArea, QVBoxLayout, QWidget)

from app.security.app_discovery import discover_installed_apps
from app.security.exe_icon import extract_icon_ico
from app.security.workspace_apps import (DEFAULT_CONFIG, WorkspaceApp, launch, load_workspace_apps,
                                         save_workspace_apps)
from app.ui import theme
from app.ui.widgets import Toggle

_TILE_COLORS = ["#2563eb", "#7c3aed", "#0d9488", "#d97706", "#db2777", "#0891b2", "#4f46e5", "#be123c"]
_provider: QFileIconProvider | None = None


_icon_cache: dict[tuple[str, float, int], QPixmap] = {}


def _exe_icon_pixmap(path: str, size: int) -> QPixmap | None:
    """The icon stored inside the program file itself (what Windows shows for it)."""
    try:
        key = (path, os.path.getmtime(path), size)
    except OSError:
        return None
    if key in _icon_cache:
        return _icon_cache[key]
    pm = None
    ico = extract_icon_ico(path)
    if ico:
        loaded = QPixmap()
        if loaded.loadFromData(ico, "ICO") and not loaded.isNull():
            pm = loaded.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    if pm is None and sys.platform == "win32":  # fall back to the Windows shell icon
        global _provider
        _provider = _provider or QFileIconProvider()
        icon = _provider.icon(QFileInfo(path))
        if not icon.isNull():
            shell = icon.pixmap(QSize(size, size))
            pm = shell if not shell.isNull() else None
    _icon_cache[key] = pm
    return pm


def app_icon_pixmap(app: WorkspaceApp, size: int = 40) -> QPixmap:
    """The program's real icon, or a coloured letter tile when it has none."""
    if os.path.isfile(app.command):
        pm = _exe_icon_pixmap(app.command, size)
        if pm is not None:
            return pm
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(_TILE_COLORS[sum(map(ord, app.name)) % len(_TILE_COLORS)]))
    p.drawRoundedRect(0, 0, size, size, size * .22, size * .22)
    p.setPen(QColor("#ffffff"))
    p.setFont(QFont("Segoe UI", int(size * .42), QFont.DemiBold))
    p.drawText(pm.rect(), Qt.AlignCenter, (app.name.strip()[:1] or "?").upper())
    p.end()
    return pm


class WorkspacePanel(QWidget):
    changed = Signal()  # emitted when the allowed-apps list changes

    def __init__(self, config_path=None, discovered: list[WorkspaceApp] | None = None) -> None:
        super().__init__()
        self.config_path = config_path or DEFAULT_CONFIG
        self.approved: list[WorkspaceApp] = load_workspace_apps(self.config_path)
        self._injected = discovered
        self._expanded: set[str] = set()
        self.rows: dict[str, tuple[Toggle, QPushButton]] = {}
        self._all: list[WorkspaceApp] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 8, 0)
        outer.setSpacing(12)
        self.summary = QLabel()
        self.summary.setObjectName("muted")
        outer.addWidget(self.summary)
        hint = QLabel("Verify your work apps: switch an app on to allow it for work. Click an app's name to see "
                      "where it is installed.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        outer.addWidget(hint)

        mon = QFrame()
        mon.setObjectName("statusCard")
        mlay = QHBoxLayout(mon)
        mlay.setContentsMargins(14, 10, 14, 10)
        mcol = QVBoxLayout()
        mcol.setSpacing(0)
        mtitle = QLabel("Monitor running apps")
        mtitle.setObjectName("cardHeading")
        self.monitor_note = QLabel("Off. When on, you get an alert if an app that is not allowed is running.")
        self.monitor_note.setObjectName("muted")
        self.monitor_note.setWordWrap(True)
        mcol.addWidget(mtitle)
        mcol.addWidget(self.monitor_note)
        self.monitor_toggle = Toggle(False)
        mlay.addLayout(mcol, 1)
        mlay.addWidget(self.monitor_toggle)
        outer.addWidget(mon)

        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search apps")
        self.search.textChanged.connect(self._render)
        self.rescan_button = QPushButton("Refresh list")
        self.rescan_button.setObjectName("secondaryButton")
        self.rescan_button.clicked.connect(self.rescan)
        bar.addWidget(self.search, 1)
        bar.addWidget(self.rescan_button)
        outer.addLayout(bar)
        self.list_layout = QVBoxLayout()
        self.list_layout.setSpacing(8)
        holder = QWidget()
        holder.setLayout(self.list_layout)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(holder)
        outer.addWidget(scroll, 1)
        self.rescan()

    @property
    def all_apps(self) -> list[WorkspaceApp]:
        return list(self._all)

    # ----- data -----
    def rescan(self) -> None:
        found = self._injected if self._injected is not None else discover_installed_apps()
        by_cmd = {a.command.lower(): a for a in found}
        for a in self.approved:  # keep allowed apps visible even if no longer discovered
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
            QMessageBox.warning(self, "Could not save", f"Your choice was not saved: {exc}")
        self._render()
        self.changed.emit()

    def toggle_location(self, app: WorkspaceApp) -> None:
        key = app.command.lower()
        self._expanded.symmetric_difference_update({key})
        self._render()

    # ----- ui -----
    def _render(self) -> None:
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)  # detach now so no stale row is painted
                widget.deleteLater()
        self.rows.clear()
        needle = self.search.text().strip().lower()
        shown = [a for a in self._all if needle in a.name.lower() or needle in a.command.lower()]
        count = len(self._all)
        self.summary.setText(f"{count} app{'s' if count != 1 else ''} found on this device · "
                             f"{len(self.approved)} allowed")
        if not shown:
            msg = QLabel("No apps found yet. Try 'Refresh list'." if not self._all else "Nothing matches your search.")
            msg.setObjectName("muted")
            self.list_layout.addWidget(msg)
        for app in shown:
            self.list_layout.addWidget(self._row(app))
        self.list_layout.addStretch(1)

    def _row(self, app: WorkspaceApp) -> QFrame:
        allowed = self.is_allowed(app)
        expanded = app.command.lower() in self._expanded
        row = QFrame()
        row.setObjectName("appRow")
        lay = QHBoxLayout(row)
        lay.setContentsMargins(12, 10, 14, 10)
        lay.setSpacing(12)
        icon = QLabel()
        icon.setPixmap(app_icon_pixmap(app))
        icon.setFixedSize(40, 40)
        icon.setAlignment(Qt.AlignCenter)

        text = QVBoxLayout()
        text.setSpacing(3)
        name = QPushButton(app.name)
        name.setObjectName("linkButton")
        name.setCursor(Qt.PointingHandCursor)
        name.setToolTip("Click to show where this app is installed")
        name.clicked.connect(lambda _=False, a=app: self.toggle_location(a))
        text.addWidget(name, alignment=Qt.AlignLeft)
        if expanded:
            loc = QLabel(app.command)
            loc.setObjectName("muted")
            loc.setWordWrap(True)
            loc.setTextInteractionFlags(Qt.TextSelectableByMouse)
            text.addWidget(loc)
            show = QPushButton("Show in folder")
            show.setObjectName("smallButton")
            show.setEnabled(os.path.exists(app.command))
            show.clicked.connect(lambda _=False, a=app: self.show_in_folder(a))
            text.addWidget(show, alignment=Qt.AlignLeft)

        state = QLabel("On" if allowed else "Off")
        state.setObjectName("muted")
        toggle = Toggle(allowed)
        toggle.setToolTip("Allow this app" if not allowed else "Stop allowing this app")
        toggle.toggled.connect(lambda checked, a=app: self.set_allowed(a, checked))
        open_btn = QPushButton("Open")
        open_btn.setObjectName("smallButton")
        open_btn.setEnabled(allowed)
        open_btn.setToolTip("Open this app" if allowed else "Switch the app on first")
        open_btn.clicked.connect(lambda _=False, a=app: self.open_app(a))

        lay.addWidget(icon)
        lay.addLayout(text, 1)
        lay.addWidget(state)
        lay.addWidget(toggle)
        lay.addWidget(open_btn)
        self.rows[app.name] = (toggle, open_btn)
        return row

    def show_in_folder(self, app: WorkspaceApp) -> None:
        try:
            if sys.platform == "win32":
                subprocess.Popen(["explorer", f"/select,{os.path.normpath(app.command)}"], shell=False)
            else:
                QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(app.command)))
        except OSError as exc:
            QMessageBox.warning(self, "Cannot open folder", str(exc))

    def open_app(self, app: WorkspaceApp) -> None:
        try:
            launch(app, self.approved)
        except (PermissionError, FileNotFoundError, OSError) as exc:
            QMessageBox.warning(self, "Cannot open application", str(exc))
