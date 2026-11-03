"""Email notification for security alerts (SMTP).

* Only non-secret settings (recipient, server, port, user) are stored, in config/alert_email.json.
* The SMTP password is never written to disk: it comes from the SECUREWORK_SMTP_PASSWORD
  environment variable or is typed into the app and kept in memory for the session.
* Sending runs on a background thread and is rate limited, so an attack cannot flood
  the inbox or freeze the interface.
"""
from __future__ import annotations

import json
import logging
import os
import re
import smtplib
import socket
import ssl
import threading
import time
from dataclasses import asdict, dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Callable

from app.security.remediation import PHISHING_TIPS, AlertInfo, advice_for

logger = logging.getLogger(__name__)
CONFIG_PATH = Path("config/alert_email.json")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


@dataclass
class EmailConfig:
    recipient: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    username: str = ""
    use_ssl: bool = False  # True = implicit TLS (port 465); False = STARTTLS


def valid_email(value: str) -> bool:
    return bool(_EMAIL.match(value or "")) and "\n" not in value and "\r" not in value


def is_configured(cfg: EmailConfig) -> bool:
    return valid_email(cfg.recipient) and bool(cfg.smtp_host.strip()) and 0 < cfg.smtp_port < 65536


def load_config(path: Path | str = CONFIG_PATH) -> EmailConfig:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return EmailConfig(str(data.get("recipient", "")), str(data.get("smtp_host", "")),
                           int(data.get("smtp_port", 587)), str(data.get("username", "")),
                           bool(data.get("use_ssl", False)))
    except (OSError, ValueError, TypeError):
        return EmailConfig()


def save_config(cfg: EmailConfig, path: Path | str = CONFIG_PATH) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _clean(text: str) -> str:
    return re.sub(r"[\r\n]+", " ", text or "").strip()


def build_message(cfg: EmailConfig, alert: AlertInfo, hostname: str | None = None) -> EmailMessage:
    host = hostname or socket.gethostname()
    adv = advice_for(alert.kind)
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert.timestamp))
    msg = EmailMessage()
    msg["Subject"] = f"[SecureWork AI] {alert.severity.upper()}: {_clean(alert.title)} on {_clean(host)}"
    msg["From"] = cfg.username if valid_email(cfg.username) else cfg.recipient
    msg["To"] = cfg.recipient
    steps = "\n".join(f"  {i}. {s}" for i, s in enumerate(adv.steps, 1))
    tips = "\n".join(f"  - {t}" for t in PHISHING_TIPS)
    msg.set_content(
        f"SecureWork AI security alert\n\n"
        f"Device:   {host}\nWhen:     {when}\nSeverity: {alert.severity}\n"
        f"What:     {_clean(alert.title)}\nDetails:  {_clean(alert.detail)}\n"
        + (f"From:     {_clean(alert.source)}\n" if alert.source else "")
        + (f"To:       {_clean(alert.target)}\n" if alert.target else "")
        + f"\nWhat this means\n  {adv.summary}\n\nWhat to do now\n{steps}\n\n"
        f"Stay safe from phishing (the most common way devices are attacked)\n{tips}\n\n"
        "Note: SecureWork AI reads network metadata and running programs. It cannot see message "
        "content, so it cannot tell you whether a specific email is phishing. Alerts are signals, "
        "not proof of compromise.\n")
    return msg


def send_message(cfg: EmailConfig, password: str, msg: EmailMessage, timeout: float = 15.0) -> None:
    ctx = ssl.create_default_context()
    if cfg.use_ssl:
        server = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=timeout, context=ctx)
    else:
        server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=timeout)
    with server:
        if not cfg.use_ssl:
            server.starttls(context=ctx)
        if cfg.username and password:
            server.login(cfg.username, password)
        server.send_message(msg)


class EmailNotifier:
    """Rate-limited, non-blocking alert emailer."""

    def __init__(self, get_config: Callable[[], EmailConfig], sender: Callable = send_message,
                 min_interval: float = 600.0, global_interval: float = 30.0) -> None:
        self._get_config, self._sender = get_config, sender
        self.min_interval, self.global_interval = min_interval, global_interval
        self._password = os.environ.get("SECUREWORK_SMTP_PASSWORD", "")
        self._lock = threading.Lock()
        self._last: dict[tuple[str, str], float] = {}
        self._last_any = -1e18
        self.status = "Email alerts: not set up"
        self.sent = 0

    def set_password(self, password: str) -> None:
        self._password = password

    @property
    def configured(self) -> bool:
        return is_configured(self._get_config())

    def notify(self, alert: AlertInfo, force: bool = False, wait: bool = False) -> bool:
        """Queue an email for this alert. Returns False if skipped (not set up / rate limited)."""
        cfg = self._get_config()
        if not is_configured(cfg):
            return False
        now = time.monotonic()
        key = (alert.kind, alert.source)
        with self._lock:
            if not force and (now - self._last.get(key, -1e18) < self.min_interval
                              or now - self._last_any < self.global_interval):
                return False
            self._last[key], self._last_any = now, now
        t = threading.Thread(target=self._send, args=(cfg, alert), daemon=True)
        t.start()
        if wait:
            t.join(30)
        return True

    def _send(self, cfg: EmailConfig, alert: AlertInfo) -> None:
        try:
            self._sender(cfg, self._password, build_message(cfg, alert))
            with self._lock:
                self.sent += 1
            self.status = f"Email sent to {cfg.recipient} at {time.strftime('%H:%M:%S')}"
        except Exception as exc:  # never let email problems affect monitoring
            logger.warning("Alert email failed: %s", exc)
            self.status = f"Email failed: {type(exc).__name__}: {exc}"[:200]
