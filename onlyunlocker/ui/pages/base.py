"""Базовая страница и общие элементы разметки."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..context import AppContext


class Page(QWidget):
    title = "Страница"
    subtitle = ""

    def __init__(self, ctx: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(28, 24, 28, 24)
        self.root.setSpacing(18)

        header = QHBoxLayout()
        header.setSpacing(12)
        text_column = QVBoxLayout()
        text_column.setSpacing(2)
        self.title_label = QLabel(self.title)
        self.title_label.setObjectName("PageTitle")
        self.subtitle_label = QLabel(self.subtitle)
        self.subtitle_label.setObjectName("PageSubtitle")
        text_column.addWidget(self.title_label)
        text_column.addWidget(self.subtitle_label)
        header.addLayout(text_column)
        header.addStretch(1)
        self.header_actions = QHBoxLayout()
        self.header_actions.setSpacing(8)
        header.addLayout(self.header_actions)
        self.root.addLayout(header)

        self.content = QVBoxLayout()
        self.content.setSpacing(16)
        self.root.addLayout(self.content, 1)

    def add_scrollable(self) -> QVBoxLayout:
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(0, 0, 6, 0)
        layout.setSpacing(16)
        area.setWidget(inner)
        self.content.addWidget(area, 1)
        return layout

    def on_show(self) -> None:  # переопределяется страницами
        pass


def muted(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("Muted")
    label.setWordWrap(True)
    return label


def faint(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("Faint")
    label.setWordWrap(True)
    return label


def key_value(key: str, value: str) -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(10)
    key_label = QLabel(key)
    key_label.setObjectName("Faint")
    key_label.setMinimumWidth(150)
    value_label = QLabel(value)
    value_label.setObjectName("Muted")
    value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
    layout.addWidget(key_label)
    layout.addWidget(value_label, 1)
    return row
