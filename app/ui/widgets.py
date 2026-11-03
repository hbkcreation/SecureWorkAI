"""Custom-painted widgets: logo, toggle switch, donut chart, sparkline, KPI card, avatar, chip."""
from __future__ import annotations

from collections import deque

from PySide6.QtCore import QEasingCurve, QPointF, QRectF, Qt, QSize, QVariantAnimation
from PySide6.QtGui import QBrush, QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import QAbstractButton, QFrame, QLabel, QSizePolicy, QVBoxLayout, QWidget

from app.ui import theme


def _qc(name: str) -> QColor:
    return QColor(theme.c(name))


def paint_logo(p: QPainter, rect: QRectF, bg: QColor, fg: QColor) -> None:
    """SecureWork mark: rounded tile with a shield and a check."""
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(bg)
    p.drawRoundedRect(rect, rect.width() * .24, rect.width() * .24)
    w, h = rect.width(), rect.height()
    x, y = rect.x(), rect.y()
    shield = QPainterPath()
    shield.moveTo(x + w * .5, y + h * .18)
    shield.lineTo(x + w * .78, y + h * .29)
    shield.lineTo(x + w * .78, y + h * .52)
    shield.quadTo(x + w * .78, y + h * .74, x + w * .5, y + h * .84)
    shield.quadTo(x + w * .22, y + h * .74, x + w * .22, y + h * .52)
    shield.lineTo(x + w * .22, y + h * .29)
    shield.closeSubpath()
    p.setBrush(fg)
    p.drawPath(shield)
    pen = QPen(bg, max(2.0, w * .075))
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    p.drawPolyline([QPointF(x + w * .37, y + h * .5), QPointF(x + w * .47, y + h * .6), QPointF(x + w * .65, y + h * .4)])


class LogoMark(QWidget):
    def __init__(self, size: int = 34, inverted: bool = False) -> None:
        super().__init__()
        self._inverted = inverted
        self.setFixedSize(size, size)

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        if self._inverted:  # white tile on a coloured panel
            paint_logo(p, QRectF(self.rect()), QColor("#ffffff"), _qc("hero"))
        else:
            paint_logo(p, QRectF(self.rect()), _qc("accent"), QColor("#ffffff"))


def app_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 32, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        paint_logo(p, QRectF(0, 0, size, size), QColor("#2563eb"), QColor("#ffffff"))
        p.end()
        icon.addPixmap(pm)
    return icon


class Toggle(QAbstractButton):
    """iOS-style on/off switch."""

    def __init__(self, checked: bool = False) -> None:
        super().__init__()
        self.setCheckable(True)
        self.setChecked(checked)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(46, 26)
        self._pos = 1.0 if checked else 0.0
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(140)
        self._anim.setEasingCurve(QEasingCurve.InOutQuad)
        self._anim.valueChanged.connect(self._tick)
        self.toggled.connect(self._animate)

    def sizeHint(self) -> QSize:
        return QSize(46, 26)

    def _tick(self, v) -> None:
        self._pos = float(v)
        self.update()

    def _animate(self, on: bool) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._pos)
        self._anim.setEndValue(1.0 if on else 0.0)
        self._anim.start()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        off, on = _qc("border"), _qc("accent")
        t = self._pos
        col = QColor(int(off.red() + (on.red() - off.red()) * t), int(off.green() + (on.green() - off.green()) * t),
                     int(off.blue() + (on.blue() - off.blue()) * t))
        if not self.isEnabled():
            col.setAlpha(120)
        p.setPen(Qt.NoPen)
        p.setBrush(col)
        p.drawRoundedRect(QRectF(0, 1, self.width(), self.height() - 2), 12, 12)
        p.setBrush(QColor("#ffffff"))
        d = self.height() - 8
        p.drawEllipse(QRectF(4 + (self.width() - d - 8) * t, 4, d, d))


class DonutChart(QWidget):
    """Donut of counts by label, total in the centre."""

    def __init__(self, center_caption: str = "packets") -> None:
        super().__init__()
        self._counts: dict[str, int] = {}
        self._progress = 1.0
        self._caption = center_caption
        self.setMinimumHeight(220)
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(600)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.valueChanged.connect(self._on_anim)

    def _on_anim(self, v) -> None:
        self._progress = float(v)
        self.update()

    def set_counts(self, counts: dict[str, int]) -> None:
        counts = {k: v for k, v in counts.items() if v > 0}
        old_keys = set(self._counts)
        if counts == self._counts:
            return
        self._counts = counts
        if set(counts) != old_keys:
            self._anim.stop()
            self._anim.start()
        else:
            self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        total = sum(self._counts.values())
        side = max(60, min(self.height() - 20, self.width() // 2 - 10))
        rect = QRectF(14, (self.height() - side) / 2, side, side)
        thick = side * 0.16
        inset = rect.adjusted(thick / 2, thick / 2, -thick / 2, -thick / 2)
        track = QPen(_qc("track"), thick)
        track.setCapStyle(Qt.FlatCap)
        p.setPen(track)
        p.setBrush(Qt.NoBrush)
        p.drawArc(inset, 0, 360 * 16)
        if not total:
            p.setPen(_qc("muted"))
            p.setFont(QFont("Segoe UI", 10))
            p.drawText(inset, Qt.AlignCenter, "No packets\ncaptured yet")
            return
        items = sorted(self._counts.items(), key=lambda kv: -kv[1])
        pal = theme.c("chart")
        start = 90.0 * 16
        for i, (_n, n) in enumerate(items):
            span = -(n / total) * 360 * 16 * self._progress
            pen = QPen(QColor(pal[i % len(pal)]), thick)
            pen.setCapStyle(Qt.FlatCap)
            p.setPen(pen)
            p.drawArc(inset, int(start), int(span))
            start += span
        p.setPen(_qc("text"))
        p.setFont(QFont("Segoe UI", int(max(13, side / 9)), QFont.DemiBold))
        p.drawText(inset.adjusted(0, -side * .05, 0, 0), Qt.AlignCenter, f"{total:,}")
        p.setPen(_qc("muted"))
        p.setFont(QFont("Segoe UI", 9))
        p.drawText(inset.adjusted(0, side * .2, 0, 0), Qt.AlignCenter, self._caption)
        x, y = int(side) + 44, max(14, int((self.height() - 24 * min(len(items), 8)) / 2))
        for i, (name, n) in enumerate(items[:8]):
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(pal[i % len(pal)]))
            p.drawRoundedRect(x, y + 3, 11, 11, 3, 3)
            p.setPen(_qc("text"))
            p.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
            p.drawText(x + 20, y + 14, name)
            p.setPen(_qc("muted"))
            p.setFont(QFont("Segoe UI", 10))
            p.drawText(x + 80, y + 14, f"{n:,}  ({n / total:.0%})")
            y += 24


class Sparkline(QWidget):
    """Line chart of recent samples (e.g. packets per second)."""

    def __init__(self, capacity: int = 90, unit: str = "pkt/s") -> None:
        super().__init__()
        self._data: deque[float] = deque([0.0] * capacity, maxlen=capacity)
        self._unit = unit
        self.setMinimumHeight(150)

    def push(self, value: float) -> None:
        self._data.append(float(value))
        self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        pad = 8.0
        peak = max(max(self._data), 1.0)
        p.setPen(QPen(_qc("track"), 1))
        for i in range(1, 4):
            y = pad + (h - 2 * pad) * i / 4
            p.drawLine(int(pad), int(y), int(w - pad), int(y))
        n = len(self._data)
        pts = [QPointF(pad + (w - 2 * pad) * i / (n - 1), h - pad - (h - 2 * pad - 14) * v / peak)
               for i, v in enumerate(self._data)]
        line = QPainterPath(pts[0])
        for pt in pts[1:]:
            line.lineTo(pt)
        area = QPainterPath(line)
        area.lineTo(pts[-1].x(), h - pad)
        area.lineTo(pts[0].x(), h - pad)
        area.closeSubpath()
        fill = _qc("accent")
        fill.setAlpha(36)
        p.fillPath(area, QBrush(fill))
        p.setPen(QPen(_qc("accent"), 2))
        p.drawPath(line)
        p.setBrush(_qc("accent"))
        p.drawEllipse(pts[-1], 3.5, 3.5)
        p.setPen(_qc("muted"))
        p.setFont(QFont("Segoe UI", 9))
        p.drawText(int(pad), 14, f"peak {peak:,.0f} {self._unit}   now {self._data[-1]:,.0f} {self._unit}")


class KpiCard(QFrame):
    def __init__(self, title: str, accent_role: str = "accent") -> None:
        super().__init__()
        self.setObjectName("kpiCard")
        self.setMinimumHeight(92)
        self._role = accent_role
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 13, 16, 13)
        lay.setSpacing(2)
        self.title = QLabel(title)
        self.title.setObjectName("kpiTitle")
        self.value = QLabel("0")
        self.value.setObjectName("kpiValue")
        self.note = QLabel(" ")
        self.note.setObjectName("bigNote")
        self.bar = QFrame()
        self.bar.setFixedHeight(3)
        lay.addWidget(self.title)
        lay.addWidget(self.value)
        lay.addWidget(self.note)
        lay.addWidget(self.bar)
        self._restyle()
        theme.signals.changed.connect(self._restyle)

    def _restyle(self, *_args) -> None:
        self.bar.setStyleSheet(f"background:{theme.c(self._role)}; border:0; border-radius:1px;")

    def set(self, value, note: str = " ") -> None:
        self.value.setText(f"{value:,}" if isinstance(value, int) else str(value))
        self.note.setText(note)


class Avatar(QWidget):
    """Circular badge with the user's initials."""

    def __init__(self, name: str = "", size: int = 34) -> None:
        super().__init__()
        self._text = (name.strip()[:2] or "U").upper()
        self.setFixedSize(size, size)

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(_qc("accent_soft"))
        p.setPen(Qt.NoPen)
        p.drawEllipse(self.rect())
        p.setPen(_qc("accent"))
        p.setFont(QFont("Segoe UI", int(self.width() * .34), QFont.DemiBold))
        p.drawText(self.rect(), Qt.AlignCenter, self._text)


def make_chip(text: str = "", state: str = "") -> QLabel:
    c = QLabel(text)
    c.setObjectName("chip")
    c.setProperty("state", state)
    return c


def set_chip(chip: QLabel, text: str, state: str) -> None:
    chip.setText(text)
    if chip.property("state") != state:
        chip.setProperty("state", state)
        chip.style().unpolish(chip)
        chip.style().polish(chip)


def card(title: str | None = None) -> tuple[QFrame, QVBoxLayout]:
    f = QFrame()
    f.setObjectName("statusCard")
    f.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
    lay = QVBoxLayout(f)
    lay.setContentsMargins(16, 14, 16, 14)
    lay.setSpacing(9)
    if title:
        h = QLabel(title)
        h.setObjectName("cardHeading")
        lay.addWidget(h)
    return f, lay
