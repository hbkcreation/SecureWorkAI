"""Custom-painted widgets: donut chart, sparkline, KPI card, avatar badge, status chip."""
from __future__ import annotations

from collections import deque

from PySide6.QtCore import QEasingCurve, QPointF, QRectF, Qt, QVariantAnimation
from PySide6.QtGui import (QBrush, QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen)
from PySide6.QtWidgets import QFrame, QLabel, QSizePolicy, QVBoxLayout, QWidget

from app.ui import theme

PALETTE = [theme.CYAN, theme.VIOLET, "#22d3a5", theme.WARN, "#f472b6", "#60a5fa", "#94a3b8"]


class DonutChart(QWidget):
    """Animated donut of counts by label, total in the centre."""

    def __init__(self, center_caption: str = "packets") -> None:
        super().__init__()
        self._counts: dict[str, int] = {}
        self._progress = 1.0
        self._caption = center_caption
        self.setMinimumHeight(220)
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(700)
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
        if set(counts) != old_keys:  # animate only when a new slice appears/disappears
            self._anim.stop()
            self._anim.start()
        else:
            self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        total = sum(self._counts.values())
        side = min(self.height() - 20, self.width() // 2 - 10)
        rect = QRectF(14, (self.height() - side) / 2, side, side)
        track = QPen(QColor("#18214a"), side * 0.17)
        track.setCapStyle(Qt.FlatCap)
        inset = rect.adjusted(side * .085, side * .085, -side * .085, -side * .085)
        p.setPen(track)
        p.setBrush(Qt.NoBrush)
        p.drawArc(inset, 0, 360 * 16)
        if not total:
            p.setPen(QColor(theme.MUTED))
            p.setFont(QFont("Segoe UI", 10))
            p.drawText(inset, Qt.AlignCenter, "No packets\ncaptured yet")
            return
        items = sorted(self._counts.items(), key=lambda kv: -kv[1])
        start = 90.0 * 16
        for i, (_n, n) in enumerate(items):
            span = -(n / total) * 360 * 16 * self._progress
            pen = QPen(QColor(PALETTE[i % len(PALETTE)]), side * 0.17)
            pen.setCapStyle(Qt.FlatCap)
            p.setPen(pen)
            p.drawArc(inset, int(start), int(span))
            start += span
        p.setPen(QColor(theme.TEXT))
        p.setFont(QFont("Segoe UI", int(max(14, side / 8)), QFont.Bold))
        p.drawText(inset.adjusted(0, -side * .06, 0, 0), Qt.AlignCenter, f"{total:,}")
        p.setPen(QColor(theme.MUTED))
        p.setFont(QFont("Segoe UI", 9))
        p.drawText(inset.adjusted(0, side * .22, 0, 0), Qt.AlignCenter, self._caption)
        x, y = int(side) + 44, max(14, int((self.height() - 22 * min(len(items), 8)) / 2))
        for i, (name, n) in enumerate(items[:8]):
            col = QColor(PALETTE[i % len(PALETTE)])
            p.setPen(Qt.NoPen)
            p.setBrush(col)
            p.drawRoundedRect(x, y + 3, 12, 12, 4, 4)
            p.setPen(QColor(theme.TEXT))
            p.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
            p.drawText(x + 20, y + 14, name)
            p.setPen(QColor(theme.MUTED))
            p.setFont(QFont("Segoe UI", 10))
            p.drawText(x + 80, y + 14, f"{n:,}  ({n / total:.0%})")
            y += 24


class Sparkline(QWidget):
    """Filled line chart of recent samples (e.g. packets per second)."""

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
        p.setPen(QPen(QColor("#18214a"), 1))
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
        grad = QLinearGradient(0, 0, 0, h)
        top = QColor(theme.CYAN)
        top.setAlpha(110)
        bot = QColor(theme.VIOLET)
        bot.setAlpha(0)
        grad.setColorAt(0, top)
        grad.setColorAt(1, bot)
        p.fillPath(area, QBrush(grad))
        p.setPen(QPen(QColor(theme.CYAN), 2.2))
        p.drawPath(line)
        p.setBrush(QColor(theme.CYAN))
        p.drawEllipse(pts[-1], 4, 4)
        p.setPen(QColor(theme.MUTED))
        p.setFont(QFont("Segoe UI", 9))
        p.drawText(int(pad), 14, f"peak {peak:,.0f} {self._unit}   now {self._data[-1]:,.0f} {self._unit}")


class KpiCard(QFrame):
    def __init__(self, title: str, accent: str = theme.CYAN) -> None:
        super().__init__()
        self.setObjectName("kpiCard")
        self.setMinimumHeight(98)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(2)
        self.title = QLabel(title.upper())
        self.title.setObjectName("kpiTitle")
        self.value = QLabel("0")
        self.value.setObjectName("kpiValue")
        self.note = QLabel(" ")
        self.note.setObjectName("bigNote")
        bar = QFrame()
        bar.setFixedHeight(3)
        bar.setStyleSheet(f"background:{accent}; border:0; border-radius:1px;")
        lay.addWidget(self.title)
        lay.addWidget(self.value)
        lay.addWidget(self.note)
        lay.addWidget(bar)

    def set(self, value, note: str = " ") -> None:
        self.value.setText(f"{value:,}" if isinstance(value, int) else str(value))
        self.note.setText(note)


class Avatar(QWidget):
    """Circular gradient badge with the user's initials."""

    def __init__(self, name: str = "", size: int = 38) -> None:
        super().__init__()
        self._text = (name.strip()[:2] or "U").upper()
        self.setFixedSize(size, size)

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        g = QLinearGradient(0, 0, self.width(), self.height())
        g.setColorAt(0, QColor(theme.CYAN))
        g.setColorAt(1, QColor(theme.VIOLET))
        p.setBrush(QBrush(g))
        p.setPen(Qt.NoPen)
        p.drawEllipse(self.rect())
        p.setPen(QColor("#06101f"))
        p.setFont(QFont("Segoe UI", int(self.width() * .34), QFont.Bold))
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
    lay.setContentsMargins(18, 16, 18, 16)
    lay.setSpacing(10)
    if title:
        h = QLabel(title.upper())
        h.setObjectName("cardHeading")
        lay.addWidget(h)
    return f, lay
