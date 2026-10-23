"""Переиспользуемые виджеты: карточки, переключатели, бейджи, щит, тосты."""
from __future__ import annotations

import math
from typing import Iterable

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPointF,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    QTimer,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import (
    QAbstractButton,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from . import theme


class Card(QFrame):
    """Панель с рамкой и внутренним layout."""

    def __init__(self, parent: QWidget | None = None, padding: int = 18, spacing: int = 10, accent: bool = False) -> None:
        super().__init__(parent)
        self.setObjectName("CardAccent" if accent else "Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(padding, padding, padding, padding)
        self.body.setSpacing(spacing)

    def add_header(self, title: str, caption: str = "") -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)
        title_label = QLabel(title)
        title_label.setObjectName("CardTitle")
        row.addWidget(title_label)
        row.addStretch(1)
        if caption:
            caption_label = QLabel(caption)
            caption_label.setObjectName("CardCaption")
            row.addWidget(caption_label)
        self.body.addLayout(row)
        return row


class StatCard(Card):
    def __init__(
        self,
        title: str,
        value: str = "0",
        caption: str = "",
        color: str = theme.TEXT,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent, padding=16, spacing=4)
        self.title = title
        self.color = color
        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("CardCaption")
        self.value_label = QLabel(value)
        self.value_label.setObjectName("StatValue")
        self.value_label.setStyleSheet(f"color: {color};")
        self.caption_label = QLabel(caption)
        self.caption_label.setObjectName("Faint")
        self.value_label.setMinimumHeight(34)
        self.value_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.body.addWidget(self.title_label)
        self.body.addWidget(self.value_label)
        self.body.addWidget(self.caption_label)
        self.setMinimumHeight(104)

    def set_value(self, value: str, caption: str | None = None) -> None:
        self.value_label.setText(str(value))
        if caption is not None:
            self.caption_label.setText(caption)


class Badge(QLabel):
    def __init__(self, text: str = "", color: str = theme.TEXT_DIM, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("Badge")
        self.set_color(color)
        self.setAlignment(Qt.AlignCenter)

    def set_color(self, color: str) -> None:
        self.setStyleSheet(
            f"background-color: {theme.rgba(color, 0.16)}; color: {color};"
            f" border: 1px solid {theme.rgba(color, 0.42)};"
            " border-radius: 9px; padding: 3px 9px; font-size: 11px; font-weight: 600;"
        )

    def set_state(self, text: str, color: str) -> None:
        self.setText(text)
        self.set_color(color)


class ToggleSwitch(QAbstractButton):
    """Аккуратный переключатель вместо стандартного чекбокса."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self._offset = 0.0
        self._anim = QPropertyAnimation(self, b"offset", self)
        self._anim.setDuration(160)
        self._anim.setEasingCurve(QEasingCurve.InOutQuad)
        self.toggled.connect(self._animate)
        self.setFixedSize(QSize(42, 24))

    def _animate(self, checked: bool) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._offset)
        self._anim.setEndValue(1.0 if checked else 0.0)
        self._anim.start()

    def setChecked(self, checked: bool) -> None:  # noqa: N802 - Qt API
        self._anim.stop()
        super().setChecked(checked)
        self._offset = 1.0 if checked else 0.0
        self.update()

    def get_offset(self) -> float:
        return self._offset

    def set_offset(self, value: float) -> None:
        self._offset = value
        self.update()

    offset = Property(float, get_offset, set_offset)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(0.5, 0.5, self.width() - 1, self.height() - 1)
        track_off = QColor("#232A35")
        track_on = QColor(theme.ACCENT)
        track = QColor(
            int(track_off.red() + (track_on.red() - track_off.red()) * self._offset),
            int(track_off.green() + (track_on.green() - track_off.green()) * self._offset),
            int(track_off.blue() + (track_on.blue() - track_off.blue()) * self._offset),
        )
        painter.setPen(Qt.NoPen)
        painter.setBrush(track)
        painter.drawRoundedRect(rect, rect.height() / 2, rect.height() / 2)

        knob_r = rect.height() / 2 - 3
        x = rect.left() + 3 + knob_r + (rect.width() - 6 - knob_r * 2) * self._offset
        painter.setBrush(QColor("#FFFFFF" if self._offset > 0.5 else "#8B95A5"))
        painter.drawEllipse(QPointF(x, rect.center().y()), knob_r, knob_r)


class ShieldWidget(QWidget):
    """Главный визуальный элемент: щит со статусом и анимацией сканирования."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(190, 210)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._state = "ok"
        self._pulse = 0.0
        self._scan_pos = -1.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)
        self._phase = 0.0

    def set_state(self, state: str) -> None:
        self._state = state
        self.update()

    @property
    def state(self) -> str:
        return self._state

    def _tick(self) -> None:
        self._phase += 0.05
        if self._state == "scanning":
            self._scan_pos += 0.03
            if self._scan_pos > 1.2:
                self._scan_pos = -0.2
        self._pulse = (math.sin(self._phase) + 1) / 2
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        side = min(w, h) * 0.82
        cx, cy = w / 2, h / 2
        color = {
            "ok": QColor(theme.OK),
            "warn": QColor(theme.WARN),
            "danger": QColor(theme.DANGER),
            "scanning": QColor(theme.ACCENT),
            "idle": QColor(theme.TEXT_DIM),
        }.get(self._state, QColor(theme.ACCENT))

        # внешнее свечение
        glow = QRadialGradient(QPointF(cx, cy), side * 0.85)
        glow.setColorAt(0.0, QColor(color.red(), color.green(), color.blue(), int(60 + 40 * self._pulse)))
        glow.setColorAt(0.55, QColor(color.red(), color.green(), color.blue(), 18))
        glow.setColorAt(1.0, QColor(color.red(), color.green(), color.blue(), 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(QPointF(cx, cy), side * 0.85, side * 0.85)

        # контур щита
        shield = self._shield_path(cx, cy, side * 0.62)
        fill = QLinearGradient(cx, cy - side / 2, cx, cy + side / 2)
        fill.setColorAt(0.0, QColor(color.red(), color.green(), color.blue(), 46))
        fill.setColorAt(1.0, QColor(color.red(), color.green(), color.blue(), 8))
        painter.setBrush(fill)
        painter.setPen(QPen(QColor(color.red(), color.green(), color.blue(), 190), 2.0))
        painter.drawPath(shield)

        # внутренняя линия
        inner = self._shield_path(cx, cy, side * 0.50)
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor(color.red(), color.green(), color.blue(), 70), 1.2))
        painter.drawPath(inner)

        # символ
        painter.setPen(QPen(color, 5.0, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.setBrush(Qt.NoBrush)
        glyph = self._glyph(cx, cy + side * 0.02, side * 0.34)
        painter.drawPath(glyph)

        # сканирующая полоса
        if self._state == "scanning":
            y = cy - side / 2 + (side * 0.95) * self._scan_pos
            band = QLinearGradient(cx - side / 2, y - 18, cx + side / 2, y + 18)
            band.setColorAt(0.0, QColor(255, 255, 255, 0))
            band.setColorAt(0.5, QColor(120, 180, 255, 200))
            band.setColorAt(1.0, QColor(255, 255, 255, 0))
            painter.setPen(QPen(QBrush(band), 2.0))
            painter.drawLine(QPointF(cx - side * 0.36, y), QPointF(cx + side * 0.36, y))

    @staticmethod
    def _shield_path(cx: float, cy: float, size: float) -> QPainterPath:
        w = size
        h = size * 1.12
        top = cy - h / 2
        path = QPainterPath()
        path.moveTo(cx, top)
        path.cubicTo(cx + w * 0.42, top + h * 0.06, cx + w * 0.52, top + h * 0.08, cx + w * 0.52, top + h * 0.08)
        path.lineTo(cx + w * 0.52, top + h * 0.52)
        path.cubicTo(cx + w * 0.52, top + h * 0.82, cx + w * 0.24, top + h * 0.95, cx, top + h)
        path.cubicTo(cx - w * 0.24, top + h * 0.95, cx - w * 0.52, top + h * 0.82, cx - w * 0.52, top + h * 0.52)
        path.lineTo(cx - w * 0.52, top + h * 0.08)
        path.cubicTo(cx - w * 0.52, top + h * 0.08, cx - w * 0.42, top + h * 0.06, cx, top)
        return path

    def _glyph(self, cx: float, cy: float, size: float) -> QPainterPath:
        path = QPainterPath()
        if self._state in ("danger", "warn"):
            # восклицательный знак
            pen_w = size * 0.16
            path.addRoundedRect(QRectF(cx - pen_w / 2, cy - size * 0.42, pen_w, size * 0.5), pen_w / 2, pen_w / 2)
            path.addEllipse(QPointF(cx, cy + size * 0.30), pen_w * 0.62, pen_w * 0.62)
            return path
        # галочка
        path.moveTo(cx - size * 0.30, cy + size * 0.02)
        path.lineTo(cx - size * 0.08, cy + size * 0.24)
        path.lineTo(cx + size * 0.32, cy - size * 0.24)
        return path


class WrenchIcon(QWidget):
    """Небольшая иконка гаечного ключа для логотипа/заголовков."""

    def __init__(self, size: int = 22, color: str = theme.ACCENT, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._color = QColor(color)
        self.setFixedSize(size, size)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        s = min(self.width(), self.height())
        painter.translate(self.width() / 2, self.height() / 2)
        painter.rotate(-40)
        pen = QPen(self._color, s * 0.16, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawLine(QPointF(0, s * 0.08), QPointF(0, s * 0.34))
        # головка ключа
        path = QPainterPath()
        r = s * 0.22
        center = QPointF(0, -s * 0.12)
        path.moveTo(center.x() - r, center.y() - r * 0.4)
        path.arcTo(QRectF(center.x() - r, center.y() - r, r * 2, r * 2), 150, 240)
        path.lineTo(center.x() + r * 0.15, center.y() + r * 0.25)
        path.lineTo(center.x() - r * 0.25, center.y() + r * 0.25)
        path.closeSubpath()
        painter.setPen(Qt.NoPen)
        painter.setBrush(self._color)
        painter.drawPath(path)


class NavButton(QPushButton):
    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("NavButton")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(36)


class TileButton(QPushButton):
    def __init__(self, text: str, description: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("Tile")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(50)
        self.setToolTip(description)
        self.description = description


class Toast(QLabel):
    """Всплывающее уведомление в правом верхнем углу окна."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        self.setWordWrap(True)
        self.hide()
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

    def show_message(self, text: str, color: str = theme.ACCENT, msec: int = 4200) -> None:
        self.setText(text)
        self.setStyleSheet(
            f"background-color: {theme.PANEL}; color: {theme.TEXT};"
            f"border: 1px solid {color}; border-left: 3px solid {color};"
            "border-radius: 8px; padding: 10px 14px; font-size: 12px;"
        )
        self.setFixedWidth(min(380, max(240, self.parent().width() // 3)))
        self.adjustSize()
        self._reposition()
        self.raise_()
        self.show()
        self._timer.start(msec)
        self.raise_()

    def _reposition(self) -> None:
        parent = self.parent()
        if parent is None:
            return
        self.move(parent.width() - self.width() - 28, parent.height() - self.height() - 24)


class FlowGrid(QWidget):
    """Сетка плиток с автоматическим числом колонок."""

    def __init__(self, columns: int = 2, spacing: int = 10, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        from PySide6.QtWidgets import QGridLayout

        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(spacing)
        self.columns = columns

    def add_widgets(self, widgets: Iterable[QWidget]) -> None:
        for index, widget in enumerate(widgets):
            self.grid.addWidget(widget, index // self.columns, index % self.columns)


def clear_layout(layout) -> None:
    """Полностью убирает виджеты из layout (без «призраков» до deleteLater)."""
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.hide()
            widget.setParent(None)
            widget.deleteLater()
        child = item.layout()
        if child is not None:
            clear_layout(child)


def hline() -> QFrame:
    line = QFrame()
    line.setFixedHeight(1)
    line.setStyleSheet(f"background-color: {theme.BORDER_SOFT}; border: none;")
    return line


def shadow(widget: QWidget, blur: int = 28, alpha: int = 90) -> None:
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setColor(QColor(0, 0, 0, alpha))
    effect.setOffset(0, 6)
    widget.setGraphicsEffect(effect)


def make_button(text: str, kind: str = "Ghost", parent: QWidget | None = None) -> QPushButton:
    button = QPushButton(text, parent)
    button.setObjectName(kind)
    button.setCursor(Qt.PointingHandCursor)
    return button
