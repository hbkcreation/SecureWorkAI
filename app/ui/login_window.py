"""Login screen for the SecureWork AI prototype."""
import logging
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QPushButton,
    QVBoxLayout, QWidget,
)
from app.ui import theme
from app.ui.widgets import LogoMark
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
        self._hero = QFrame()
        hl = QVBoxLayout(self._hero)
        hl.setContentsMargins(48, 52, 48, 44)
        hl.addWidget(LogoMark(52, inverted=True), alignment=Qt.AlignLeft)
        hl.addSpacing(14)
        self._hero_title = QLabel("SecureWork AI")
        self._hero_sub = QLabel("A safer way to use your own laptop for work.")
        self._hero_sub.setWordWrap(True)
        hl.addWidget(self._hero_title)
        hl.addWidget(self._hero_sub)
        hl.addSpacing(22)
        self._hero_items = []
        for text in ("Keeps an eye on your network traffic",
                     "Flags port scans, floods and other odd behaviour",
                     "Lets you open only the apps your company approves",
                     "Checks that your approved USB Wi-Fi adapter is in use"):
            item = QLabel("•  " + text)
            self._hero_items.append(item)
            hl.addWidget(item)
        hl.addStretch(1)
        self._hero_foot = QLabel("Prototype. Alerts are signals, not proof of a problem.")
        hl.addWidget(self._hero_foot)
        self._style_hero()
        theme.signals.changed.connect(lambda _m: self._style_hero())
        row.addWidget(self._hero, 5)

        # Form panel
        right = QWidget()
        outer = QVBoxLayout(right)
        outer.setContentsMargins(56, 36, 56, 36)
        outer.setSpacing(14)
        outer.addStretch(1)
        title = QLabel("Sign in")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Use the account your administrator set up for you.")
        subtitle.setObjectName("muted")
        outer.addWidget(title)
        outer.addWidget(subtitle)
        outer.addSpacing(10)
        ulabel = QLabel("Username")
        ulabel.setObjectName("cardHeading")
        self.username = QLineEdit()
        self.username.setPlaceholderText("Enter your username")
        self.username.setText("")
        plabel = QLabel("Password")
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

    def _style_hero(self) -> None:
        self._hero.setStyleSheet(f"QFrame {{ background: {theme.c('hero')}; border: 0; }} QLabel {{ background: transparent; }}")
        self._hero_title.setStyleSheet(f"font-size: 32px; font-weight: 700; color: {theme.c('hero_text')};")
        self._hero_sub.setStyleSheet(f"font-size: 15px; color: {theme.c('hero_sub')};")
        for item in self._hero_items:
            item.setStyleSheet(f"font-size: 14px; color: {theme.c('hero_text')}; padding: 3px 0;")
        self._hero_foot.setStyleSheet(f"font-size: 12px; color: {theme.c('hero_sub')};")

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
