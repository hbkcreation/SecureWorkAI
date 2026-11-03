"""Application-wide dark 'security operations' theme."""

BG = "#0a0e1a"
SURFACE = "#111831"
SURFACE2 = "#0d1326"
BORDER = "#1e2a52"
TEXT = "#e8ecff"
MUTED = "#8a95c0"
CYAN = "#38bdf8"
VIOLET = "#8b5cf6"
OK = "#22c55e"
WARN = "#f59e0b"
BAD = "#ef4444"

STYLESHEET = f"""
* {{ font-family: 'Segoe UI', 'Inter', 'Helvetica Neue', sans-serif; font-size: 13px; }}
QWidget {{ background: {BG}; color: {TEXT}; }}
QMainWindow, QScrollArea, QScrollArea > QWidget > QWidget {{ background: {BG}; border: 0; }}
QLabel {{ background: transparent; }}
QLabel#pageTitle {{ font-size: 24px; font-weight: 700; color: {TEXT}; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#cardHeading {{ font-size: 13px; font-weight: 700; color: {MUTED}; letter-spacing: 1px; text-transform: uppercase; }}
QLabel#statusValue {{ font-size: 15px; font-weight: 600; color: {CYAN}; }}
QLabel#message {{ color: {BAD}; min-height: 18px; }}
QLabel#brand {{ font-size: 19px; font-weight: 800; color: {TEXT}; }}
QLabel#kpiValue {{ font-size: 30px; font-weight: 800; color: {TEXT}; }}
QLabel#kpiTitle {{ color: {MUTED}; font-size: 12px; font-weight: 600; }}
QLabel#bigNote {{ color: {MUTED}; font-size: 12px; }}
QFrame#sidebar {{ background: {SURFACE2}; border-right: 1px solid {BORDER}; }}
QFrame#sidebar QWidget {{ background: transparent; }}
QFrame#panel, QFrame#statusCard, QFrame#kpiCard, QFrame#appRow {{
    background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 14px; }}
QFrame#kpiCard {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #131c3d, stop:1 #0f1630); }}
QFrame#securityBox {{ background: #101a3a; border: 1px solid {BORDER}; border-radius: 12px; }}
QFrame#cardInner, QFrame#cardInner QLabel {{ background: transparent; border: 0; }}
QPushButton {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {CYAN}, stop:1 {VIOLET});
    color: #06101f; border: 0; border-radius: 9px; padding: 9px 16px; font-weight: 700; }}
QPushButton:hover {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #7dd3fc, stop:1 #a78bfa); }}
QPushButton:pressed {{ background: {VIOLET}; }}
QPushButton:disabled {{ background: #1a2342; color: #5a6690; }}
QPushButton#secondaryButton {{ background: #1a2547; color: {TEXT}; border: 1px solid {BORDER}; }}
QPushButton#secondaryButton:hover {{ background: #223062; }}
QPushButton#secondaryButton:checked {{ background: #3b2a6b; border-color: {VIOLET}; }}
QPushButton#navButton {{ background: transparent; color: {MUTED}; text-align: left; padding: 11px 14px;
    border-radius: 10px; font-weight: 600; }}
QPushButton#navButton:hover {{ background: #141d3d; color: {TEXT}; }}
QPushButton#navButton:checked {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #1d2f63, stop:1 #2a2160);
    color: {TEXT}; border-left: 3px solid {CYAN}; }}
QPushButton#allowOn {{ background: {OK}; color: #04140a; }}
QPushButton#allowOn:hover {{ background: #16a34a; }}
QPushButton#allowOff {{ background: #3a1620; color: #ffb4bd; border: 1px solid #5a1f2c; }}
QPushButton#allowOff:hover {{ background: #4b1b28; }}
QLineEdit, QComboBox {{ background: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 9px; padding: 9px 11px;
    color: {TEXT}; selection-background-color: {VIOLET}; }}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {CYAN}; }}
QComboBox QAbstractItemView {{ background: {SURFACE}; color: {TEXT}; border: 1px solid {BORDER};
    selection-background-color: #25346b; }}
QListWidget {{ background: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 10px; padding: 4px; outline: 0; }}
QListWidget::item {{ padding: 6px 8px; border-radius: 6px; }}
QListWidget::item:hover {{ background: #141d3d; }}
QLabel#chip {{ border-radius: 11px; padding: 4px 12px; font-weight: 700; font-size: 12px;
    background: #1a2342; color: {MUTED}; border: 1px solid {BORDER}; }}
QLabel#chip[state="ok"] {{ background: #0f2a1d; color: {OK}; border: 1px solid #14532d; }}
QLabel#chip[state="warn"] {{ background: #2e2208; color: {WARN}; border: 1px solid #5b4310; }}
QLabel#chip[state="bad"] {{ background: #331219; color: {BAD}; border: 1px solid #5a1f2c; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #25316a; border-radius: 4px; min-height: 30px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QToolTip {{ background: {SURFACE}; color: {TEXT}; border: 1px solid {BORDER}; padding: 6px; }}
QMessageBox {{ background: {SURFACE}; }}
"""
