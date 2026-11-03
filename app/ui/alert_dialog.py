"""Pop-up shown when an attack is detected: what happened and how to deal with it."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from app.security.remediation import PHISHING_TIPS, AlertInfo, advice_for


class AlertDialog(QDialog):
    def __init__(self, info: AlertInfo, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("alertDialog")
        self.setWindowTitle("SecureWork AI | Security alert")
        self.setModal(False)
        self.setMinimumWidth(520)
        adv = advice_for(info.kind)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 20)
        lay.setSpacing(10)
        head = QLabel(("TEST ALERT: " if info.kind == "TEST" else "ALERT: ") + info.title)
        head.setObjectName("alertTitle")
        head.setWordWrap(True)
        when = QLabel(f"{time.strftime('%H:%M:%S', time.localtime(info.timestamp))} · severity {info.severity}"
                      + (f" · from {info.source}" if info.source else "") + (f" · to {info.target}" if info.target else ""))
        when.setObjectName("muted")
        what = QLabel(adv.summary)
        what.setWordWrap(True)
        lay.addWidget(head)
        lay.addWidget(when)
        lay.addWidget(what)
        lay.addSpacing(6)
        steps_title = QLabel("What to do now")
        steps_title.setObjectName("cardHeading")
        lay.addWidget(steps_title)
        for i, step in enumerate(adv.steps, 1):
            label = QLabel(f"{i}. {step}")
            label.setWordWrap(True)
            lay.addWidget(label)
        if info.kind != "TEST":
            tips_title = QLabel("About phishing")
            tips_title.setObjectName("cardHeading")
            lay.addSpacing(6)
            lay.addWidget(tips_title)
            note = QLabel(PHISHING_TIPS[0] + " (This app cannot see message content, so it cannot detect phishing itself.)")
            note.setObjectName("muted")
            note.setWordWrap(True)
            lay.addWidget(note)
        self.more_label = QLabel("")
        self.more_label.setObjectName("muted")
        self.more_label.hide()
        lay.addWidget(self.more_label)
        self._more = 0
        row = QHBoxLayout()
        row.addStretch(1)
        ok = QPushButton("I understand")
        ok.clicked.connect(self.close)
        row.addWidget(ok)
        lay.addLayout(row)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

    def add_more(self) -> None:
        """Another alert arrived while this window is open: count it instead of opening a second window."""
        self._more += 1
        self.more_label.setText(f"{self._more} more alert{'s' if self._more != 1 else ''} since this window opened. "
                                "See the Alerts tab for the full list.")
        self.more_label.show()
