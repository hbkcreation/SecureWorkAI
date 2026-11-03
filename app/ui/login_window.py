"""Login screen for the SecureWork AI prototype."""
import logging
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QPushButton,
    QVBoxLayout, QWidget,
)
from app.security.auth import AccountStoreStatus, account_store_status, authenticate

logger = logging.getLogger(__name__)


class LoginWindow(QMainWindow):
    def __init__(self, on_login_success) -> None:
        super().__init__()
        self._on_login_success = on_login_success
        self.setWindowTitle("SecureWork AI | Sign in")
        self.setMinimumSize(900, 560)

        central = QWidget()
        row = QHBoxLayout(central)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        # Brand panel
        hero = QFrame()
        hero.setStyleSheet(
            "QFrame { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #14246b, stop:0.55 #3b1d8f,"
            " stop:1 #0a0e1a); border: 0; } QLabel { background: transparent; }"
        )
        hl = QVBoxLayout(hero)
        hl.setContentsMargins(48, 56, 48, 48)
        logo = QLabel("◈")
        logo.setStyleSheet("font-size: 54px; color: #38bdf8;")
        headline = QLabel("SecureWork AI")
        headline.setStyleSheet("font-size: 38px; font-weight: 800; color: white;")
        sub = QLabel("A protected workspace for the personal device you use for work.")
        sub.setWordWrap(True)
        sub.setStyleSheet("font-size: 15px; color: #c7d2fe;")
        hl.addWidget(logo)
        hl.addWidget(headline)
        hl.addWidget(sub)
        hl.addSpacing(26)
        for text in ("●  Live network monitoring and flow analysis",
                     "●  Rule-based and Random Forest intrusion signals",
                     "●  Approved-application workspace",
                     "●  USB Wi-Fi adapter verification"):
            item = QLabel(text)
            item.setStyleSheet("font-size: 14px; color: #e0e7ff; padding: 4px 0;")
            hl.addWidget(item)
        hl.addStretch(1)
        foot = QLabel("Prototype · alerts are signals, not proof of compromise")
        foot.setStyleSheet("font-size: 12px; color: #a5b4fc;")
        hl.addWidget(foot)
        row.addWidget(hero, 5)

        # Form panel
        right = QWidget()
        outer = QVBoxLayout(right)
        outer.setContentsMargins(56, 36, 56, 36)
        outer.setSpacing(14)
        outer.addStretch(1)
        title = QLabel("Welcome back")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Sign in to enter your secure workspace")
        subtitle.setObjectName("muted")
        outer.addWidget(title)
        outer.addWidget(subtitle)
        outer.addSpacing(10)
        ulabel = QLabel("USERNAME")
        ulabel.setObjectName("cardHeading")
        self.username = QLineEdit()
        self.username.setPlaceholderText("Enter your username")
        self.username.setText("")
        plabel = QLabel("PASSWORD")
        plabel.setObjectName("cardHeading")
        self.password = QLineEdit()
        self.password.setPlaceholderText("Enter your password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.returnPressed.connect(self._login)
        for w in (ulabel, self.username, plabel, self.password):
            outer.addWidget(w)
        self.message = QLabel(" ")
        self.message.setObjectName("message")
        self.message.setWordWrap(True)
        outer.addWidget(self.message)
        login_button = QPushButton("Sign in")
        login_button.setCursor(Qt.PointingHandCursor)
        login_button.setMinimumHeight(42)
        login_button.clicked.connect(self._login)
        outer.addWidget(login_button)
        outer.addStretch(1)
        row.addWidget(right, 4)
        self.setCentralWidget(central)
        self._show_account_store_status()

    def _show_account_store_status(self) -> None:
        status = account_store_status()
        if status is AccountStoreStatus.MISSING:
            self.message.setText("No local account is configured. Run the documented provisioning command.")
        elif status is AccountStoreStatus.UNAVAILABLE:
            self.message.setText("Local account storage is unavailable. Contact the administrator.")

    def _login(self) -> None:
        if authenticate(self.username.text().strip(), self.password.text()):
            logger.info("Local user authenticated successfully")
            self.message.setText(" ")
            self._on_login_success()
        else:
            logger.warning("Failed local login attempt")
            self.message.setText("Incorrect username or password.")
