"""Dependency-free pie chart of live packet counts by protocol (QPainter)."""
from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import QWidget

PALETTE = ["#2673c9", "#e8a317", "#16794b", "#b42318", "#7c3aed", "#0e7490", "#64748b"]


class ProtocolPieChart(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._counts: dict[str, int] = {}
        self.setMinimumHeight(190)

    def set_counts(self, counts: dict[str, int]) -> None:
        counts = {k: v for k, v in counts.items() if v > 0}
        if counts != self._counts:
            self._counts = counts
            self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        total = sum(self._counts.values())
        if not total:
            p.setPen(QColor("#64748b"))
            p.drawText(self.rect(), Qt.AlignCenter, "No packets captured yet")
            return
        side = min(self.height() - 16, self.width() // 2 - 16)
        rect = QRectF(12, 8, side, side)
        start = 0.0
        items = sorted(self._counts.items(), key=lambda kv: -kv[1])
        for i, (_name, n) in enumerate(items):
            span = n / total * 360 * 16
            p.setBrush(QColor(PALETTE[i % len(PALETTE)]))
            p.setPen(QColor("white"))
            p.drawPie(rect, int(start), int(span))
            start += span
        p.setFont(QFont("Segoe UI", 9))
        y = 14
        for i, (name, n) in enumerate(items[:8]):
            p.setBrush(QColor(PALETTE[i % len(PALETTE)]))
            p.setPen(Qt.NoPen)
            p.drawRect(int(side) + 28, y, 12, 12)
            p.setPen(QColor("#17243a"))
            p.drawText(int(side) + 46, y + 11, f"{name}: {n} ({n / total:.0%})")
            y += 20
