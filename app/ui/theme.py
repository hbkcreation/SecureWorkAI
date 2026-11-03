"""Light and dark themes. Light is the default; the choice is remembered between runs."""
from __future__ import annotations

from PySide6.QtCore import QObject, QSettings, Signal
from PySide6.QtWidgets import QApplication, QWidget

LIGHT = {
    "bg": "#f5f6f8", "surface": "#ffffff", "surface2": "#f0f2f5", "border": "#dfe3e8",
    "text": "#1f2937", "muted": "#6b7280", "accent": "#2563eb", "accent_hover": "#1d4ed8",
    "accent_text": "#ffffff", "accent_soft": "#e8f0fe", "ok": "#15803d", "ok_bg": "#e7f6ec",
    "warn": "#b45309", "warn_bg": "#fdf3e0", "bad": "#b91c1c", "bad_bg": "#fdeaea",
    "track": "#e9ecf1", "hero": "#2563eb", "hero_text": "#ffffff", "hero_sub": "#dbe7ff",
    "chart": ["#2563eb", "#7c3aed", "#0d9488", "#d97706", "#db2777", "#0891b2", "#6b7280"],
}
DARK = {
    "bg": "#15171c", "surface": "#1e2128", "surface2": "#191c22", "border": "#2d323c",
    "text": "#e5e7eb", "muted": "#9aa1ad", "accent": "#5b8def", "accent_hover": "#7aa3f5",
    "accent_text": "#0b1220", "accent_soft": "#26334f", "ok": "#4ade80", "ok_bg": "#17301f",
    "warn": "#fbbf24", "warn_bg": "#33280f", "bad": "#f87171", "bad_bg": "#3a1a1d",
    "track": "#2a2f3a", "hero": "#1e3a8a", "hero_text": "#ffffff", "hero_sub": "#bcd0ff",
    "chart": ["#5b8def", "#a78bfa", "#2dd4bf", "#fbbf24", "#f472b6", "#22d3ee", "#9aa1ad"],
}


class _Signals(QObject):
    changed = Signal(str)


signals = _Signals()
_mode = "light"


def mode() -> str:
    return _mode


def c(name: str):
    return (DARK if _mode == "dark" else LIGHT)[name]


def build_stylesheet() -> str:
    g = c
    return f"""
* {{ font-family: 'Segoe UI', 'Inter', 'Helvetica Neue', Arial, sans-serif; font-size: 13px; }}
QWidget {{ background: {g('bg')}; color: {g('text')}; }}
QMainWindow, QScrollArea, QScrollArea > QWidget > QWidget {{ background: {g('bg')}; border: 0; }}
QLabel {{ background: transparent; }}
QLabel#pageTitle {{ font-size: 22px; font-weight: 600; }}
QLabel#muted {{ color: {g('muted')}; }}
QLabel#cardHeading {{ font-size: 14px; font-weight: 600; color: {g('text')}; }}
QLabel#statusValue {{ font-size: 14px; font-weight: 600; color: {g('accent')}; }}
QLabel#message {{ color: {g('bad')}; min-height: 18px; }}
QLabel#brand {{ font-size: 16px; font-weight: 700; }}
QLabel#kpiValue {{ font-size: 28px; font-weight: 600; }}
QLabel#kpiTitle {{ color: {g('muted')}; font-size: 12px; }}
QLabel#bigNote {{ color: {g('muted')}; font-size: 12px; }}
QFrame#sidebar {{ background: {g('surface')}; border-right: 1px solid {g('border')}; }}
QFrame#sidebar QWidget {{ background: transparent; }}
QFrame#panel, QFrame#statusCard, QFrame#kpiCard, QFrame#appRow {{
    background: {g('surface')}; border: 1px solid {g('border')}; border-radius: 10px; }}
QFrame#appRow QWidget {{ background: transparent; }}
QPushButton {{ background: {g('accent')}; color: {g('accent_text')}; border: 0; border-radius: 7px;
    padding: 8px 16px; font-weight: 600; }}
QPushButton:hover {{ background: {g('accent_hover')}; }}
QPushButton:disabled {{ background: {g('surface2')}; color: {g('muted')}; border: 1px solid {g('border')}; }}
QPushButton#secondaryButton {{ background: {g('surface')}; color: {g('text')}; border: 1px solid {g('border')}; }}
QPushButton#secondaryButton:hover {{ background: {g('surface2')}; }}
QPushButton#secondaryButton:checked {{ background: {g('accent_soft')}; border-color: {g('accent')}; }}
QPushButton#navButton {{ background: transparent; color: {g('muted')}; text-align: left; padding: 9px 12px;
    border-radius: 7px; font-weight: 500; }}
QPushButton#navButton:hover {{ background: {g('surface2')}; color: {g('text')}; }}
QPushButton#navButton:checked {{ background: {g('accent_soft')}; color: {g('accent')}; font-weight: 600; }}
QPushButton#linkButton {{ background: transparent; color: {g('text')}; border: 0; padding: 0;
    text-align: left; font-size: 14px; font-weight: 600; }}
QPushButton#linkButton:hover {{ color: {g('accent')}; background: transparent; }}
QPushButton#smallButton {{ background: {g('surface')}; color: {g('text')}; border: 1px solid {g('border')};
    padding: 4px 10px; font-weight: 500; font-size: 12px; }}
QPushButton#smallButton:hover {{ background: {g('surface2')}; }}
QPushButton#smallButton:disabled {{ color: {g('muted')}; }}
QLineEdit, QComboBox {{ background: {g('surface')}; border: 1px solid {g('border')}; border-radius: 7px;
    padding: 8px 10px; selection-background-color: {g('accent')}; selection-color: {g('accent_text')}; }}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {g('accent')}; }}
QComboBox QAbstractItemView {{ background: {g('surface')}; color: {g('text')}; border: 1px solid {g('border')};
    selection-background-color: {g('accent_soft')}; selection-color: {g('text')}; }}
QListWidget {{ background: {g('surface')}; border: 1px solid {g('border')}; border-radius: 8px; padding: 3px; outline: 0; }}
QListWidget::item {{ padding: 6px 8px; border-radius: 5px; }}
QListWidget::item:hover {{ background: {g('surface2')}; }}
QLabel#chip {{ border-radius: 10px; padding: 3px 11px; font-size: 12px; font-weight: 500;
    background: {g('surface2')}; color: {g('muted')}; border: 1px solid {g('border')}; }}
QLabel#chip[state="ok"] {{ background: {g('ok_bg')}; color: {g('ok')}; border: 1px solid {g('ok_bg')}; }}
QLabel#chip[state="warn"] {{ background: {g('warn_bg')}; color: {g('warn')}; border: 1px solid {g('warn_bg')}; }}
QLabel#chip[state="bad"] {{ background: {g('bad_bg')}; color: {g('bad')}; border: 1px solid {g('bad_bg')}; }}
QFrame#alertBanner {{ background: {g('bad_bg')}; border: 1px solid {g('bad')}; border-radius: 10px; }}
QFrame#alertBanner QLabel {{ color: {g('bad')}; font-weight: 600; background: transparent; }}
QPushButton#alertButton {{ background: {g('bad')}; color: #ffffff; }}
QPushButton#alertButton:hover {{ background: {g('bad')}; }}
QPushButton#alertGhost {{ background: transparent; color: {g('bad')}; border: 1px solid {g('bad')}; }}
QDialog#alertDialog {{ background: {g('surface')}; }}
QLabel#alertTitle {{ font-size: 18px; font-weight: 700; color: {g('bad')}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {g('border')}; border-radius: 4px; min-height: 30px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QToolTip {{ background: {g('surface')}; color: {g('text')}; border: 1px solid {g('border')}; padding: 5px; }}
QMessageBox {{ background: {g('surface')}; }}
"""


def _settings() -> QSettings:
    return QSettings("SecureWorkAI", "SecureWorkAI")


def saved_mode() -> str:
    try:
        value = str(_settings().value("theme", "light"))
    except Exception:
        value = "light"
    return value if value in ("light", "dark") else "light"


def apply(new_mode: str, save: bool = True) -> None:
    global _mode
    _mode = new_mode if new_mode in ("light", "dark") else "light"
    app = QApplication.instance()
    if app is not None:
        app.setStyleSheet(build_stylesheet())
        for top in app.topLevelWidgets():  # repaint only live, visible windows (skip widgets pending deletion)
            if top.isVisible():
                for w in [top, *top.findChildren(QWidget)]:
                    w.update()
    if save:
        try:
            _settings().setValue("theme", _mode)
        except Exception:
            pass
    signals.changed.emit(_mode)
