"""Websites tab: choose which websites may be opened; everything else is blocked."""
from __future__ import annotations

import time

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget, QMessageBox, QPushButton,
                               QScrollArea, QVBoxLayout, QWidget)

from app.security.website_filter import WebsiteFilterController
from app.ui.widgets import Toggle, card


class WebsitesPanel(QWidget):
    tampered = Signal()   # something changed the proxy setting and we put it back

    def __init__(self, controller: WebsiteFilterController | None = None) -> None:
        super().__init__()
        self.controller = controller or WebsiteFilterController()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 8, 0)
        outer.setSpacing(14)

        # ---- on/off
        mon = QFrame()
        mon.setObjectName("statusCard")
        row = QHBoxLayout(mon)
        row.setContentsMargins(14, 10, 14, 10)
        col = QVBoxLayout()
        col.setSpacing(0)
        title = QLabel("Block websites that are not on this list")
        title.setObjectName("cardHeading")
        self.status_label = QLabel("Off.")
        self.status_label.setObjectName("muted")
        self.status_label.setWordWrap(True)
        col.addWidget(title)
        col.addWidget(self.status_label)
        self.toggle = Toggle(False)
        self.toggle.toggled.connect(self._toggled)
        row.addLayout(col, 1)
        row.addWidget(self.toggle)
        outer.addWidget(mon)

        note = QLabel("Works for browsers that use the Windows proxy settings (Edge, Chrome and Firefox by default). "
                      "It is not a firewall: other programs, or someone changing the proxy setting by hand, can get around "
                      "it, and SecureWork AI will notice and switch it back. HTTPS pages are checked by site name only; "
                      "their content is never read.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        outer.addWidget(note)

        # ---- add
        add_row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("Add a website, e.g. example.com or https://docs.example.com")
        self.input.returnPressed.connect(self.add_clicked)
        self.add_button = QPushButton("Add website")
        self.add_button.clicked.connect(self.add_clicked)
        add_row.addWidget(self.input, 1)
        add_row.addWidget(self.add_button)
        outer.addLayout(add_row)
        self.message = QLabel(" ")
        self.message.setObjectName("muted")
        outer.addWidget(self.message)

        # ---- allowed list
        self.list_layout = QVBoxLayout()
        self.list_layout.setSpacing(6)
        holder = QWidget()
        holder.setLayout(self.list_layout)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(holder)
        outer.addWidget(scroll, 1)

        # ---- blocked log + restore
        log_card, ll = card("Recently blocked")
        self.blocked_summary = QLabel("Nothing blocked yet.")
        self.blocked_summary.setObjectName("muted")
        self.blocked_list = QListWidget()
        self.blocked_list.setMaximumHeight(120)
        btns = QHBoxLayout()
        self.restore_button = QPushButton("Restore my internet settings")
        self.restore_button.setObjectName("secondaryButton")
        self.restore_button.setToolTip("Turns the filter off and puts your original Windows proxy settings back.")
        self.restore_button.clicked.connect(self.restore_clicked)
        btns.addWidget(self.restore_button)
        btns.addStretch(1)
        ll.addWidget(self.blocked_summary)
        ll.addWidget(self.blocked_list)
        ll.addLayout(btns)
        outer.addWidget(log_card)

        self._render_sites()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(3000)

    # ---- state
    def apply_saved_state(self) -> None:
        """Called at start-up: recover from a crash, then re-enable if it was on and there are sites."""
        self.controller.recover()
        if self.controller.want_enabled and self.controller.sites:
            try:
                note = self.controller.enable()
                self._set_toggle(True)
                self.status_label.setText(f"On. {note}")
            except Exception as exc:
                self.status_label.setText(f"Could not turn the filter on: {exc}")
        self._refresh_status()

    def _set_toggle(self, on: bool) -> None:
        self.toggle.blockSignals(True)
        self.toggle.setChecked(on)
        self.toggle.blockSignals(False)
        self.toggle.update()

    def _toggled(self, on: bool) -> None:
        try:
            if on:
                if not self.controller.sites:
                    raise ValueError("Add at least one allowed website first, otherwise every website would be blocked.")
                note = self.controller.enable()
                self.status_label.setText(f"On. {note}")
            else:
                self.controller.disable()
                self.status_label.setText("Off.")
        except Exception as exc:
            self._set_toggle(False)
            self.status_label.setText("Off.")
            QMessageBox.warning(self, "Website blocking", str(exc))

    def add_clicked(self) -> None:
        ok, msg = self.controller.add_site(self.input.text())
        self.message.setText(msg)
        if ok:
            self.input.clear()
            self._render_sites()

    def remove(self, domain: str) -> None:
        self.controller.remove_site(domain)
        if not self.controller.sites and self.controller.running:  # an empty list would block everything
            self.toggle.setChecked(False)
        self._render_sites()

    def restore_clicked(self) -> None:
        self.controller.disable()
        self._set_toggle(False)
        self.status_label.setText("Off. Your original internet settings were put back.")

    def _render_sites(self) -> None:
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        if not self.controller.sites:
            empty = QLabel("No allowed websites yet. Add the sites your work needs, then switch blocking on.")
            empty.setObjectName("muted")
            empty.setWordWrap(True)
            self.list_layout.addWidget(empty)
        for domain in self.controller.sites:
            frame = QFrame()
            frame.setObjectName("appRow")
            lay = QHBoxLayout(frame)
            lay.setContentsMargins(14, 8, 12, 8)
            name = QLabel(domain)
            name.setStyleSheet("font-weight: 600;")
            sub = QLabel("and its subdomains")
            sub.setObjectName("muted")
            rm = QPushButton("Remove")
            rm.setObjectName("smallButton")
            rm.clicked.connect(lambda _=False, d=domain: self.remove(d))
            lay.addWidget(name)
            lay.addWidget(sub)
            lay.addStretch(1)
            lay.addWidget(rm)
            self.list_layout.addWidget(frame)
        self.list_layout.addStretch(1)

    def _refresh_status(self) -> None:
        p = self.controller.proxy
        if p is None:
            return
        self.blocked_summary.setText(f"{p.blocked_count:,} blocked · {p.allowed_count:,} allowed since the filter started.")
        rows = [f"{time.strftime('%H:%M:%S', time.localtime(t))}  {h}" for t, h in list(p.blocked)[-15:]][::-1]
        existing = [self.blocked_list.item(i).text() for i in range(self.blocked_list.count())]
        if rows != existing:
            self.blocked_list.clear()
            self.blocked_list.addItems(rows or ["Nothing blocked yet."])

    def _tick(self) -> None:
        if not self.controller.running:
            return
        if self.controller.tamper_check():
            self.status_label.setText("On. The proxy setting was changed by something else and has been switched back.")
            self.tampered.emit()
        if self.isVisible():
            self._refresh_status()
