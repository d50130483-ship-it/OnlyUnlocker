"""Журнал проверок."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
)

from ...core.utils import human_size, human_time, shorten_path
from .. import theme
from ..dialogs import ConfirmDialog
from ..widgets import Card, StatCard, make_button
from .base import Page, faint

MODE_LABELS = {"quick": "Быстрая", "full": "Полная", "system": "Системные папки", "custom": "Своя папка"}


class HistoryPage(Page):
    title = "Журнал"
    subtitle = "Все завершённые проверки и их результаты"

    def __init__(self, ctx, parent=None) -> None:
        super().__init__(ctx, parent)
        self.entries: list[dict] = []
        self._build()
        self.ctx.signals.scan_finished.connect(lambda _s: self.refresh())

    def _build(self) -> None:
        clear = make_button("Очистить журнал", "Danger")
        clear.clicked.connect(self._clear)
        self.header_actions.addWidget(clear)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self.scans_card = StatCard("Проверок", "0", "всего", theme.ACCENT)
        self.threats_card = StatCard("Найдено угроз", "0", "за всё время", theme.DANGER)
        self.files_card = StatCard("Проверено файлов", "0", "за всё время", theme.OK)
        stats_row.addWidget(self.scans_card)
        stats_row.addWidget(self.threats_card)
        stats_row.addWidget(self.files_card)
        self.content.addLayout(stats_row)

        card = Card(padding=16, spacing=10)
        card.add_header("История", "двойной клик по строке — находки проверки")
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Дата", "Тип", "Проверено", "Угрозы", "Подозрения", "Длительность"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.doubleClicked.connect(self._open_entry)
        card.body.addWidget(self.table, 1)
        self.empty = faint("Журнал пуст: запустите первую проверку.")
        card.body.addWidget(self.empty)
        self.content.addWidget(card, 1)
        self.refresh()

    def refresh(self) -> None:
        self.entries = self.ctx.history.entries()
        stats = self.ctx.history.stats()
        self.scans_card.set_value(str(stats["scans"]), "всего")
        self.threats_card.set_value(str(stats["infected"]), "за всё время")
        self.files_card.set_value(f"{stats['scanned']:,}".replace(",", " "), "за всё время")
        self.table.setRowCount(len(self.entries))
        for row, entry in enumerate(self.entries):
            started = float(entry.get("started_at", 0))
            date = time.strftime("%d.%m.%Y %H:%M", time.localtime(started)) if started else "—"
            values = [
                date,
                MODE_LABELS.get(entry.get("mode", ""), entry.get("mode", "—")),
                str(entry.get("scanned", 0)),
                str(entry.get("infected", 0)),
                str(entry.get("suspicious", 0)),
                human_time(float(entry.get("finished_at", 0)) - started),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setTextAlignment(Qt.AlignCenter if column > 1 else Qt.AlignLeft | Qt.AlignVCenter)
                if column == 3 and value != "0":
                    item.setForeground(Qt.GlobalColor.white)
                self.table.setItem(row, column, item)
        self.empty.setVisible(not self.entries)

    def _open_entry(self, index) -> None:
        row = index.row()
        if row >= len(self.entries):
            return
        entry = self.entries[row]
        threats = entry.get("threats") or []
        from ..dialogs import TableDialog

        if not threats:
            TableDialog(
                "Находок нет",
                "Эта проверка завершилась без угроз.",
                ["Показатель", "Значение"],
                [
                    ["Проверено файлов", str(entry.get("scanned", 0))],
                    ["Ошибок", str(entry.get("errors", 0))],
                    ["Объём", human_size(int(entry.get("bytes", 0) or 0))],
                    ["Цель", shorten_path(str(entry.get("target", "")), 80)],
                ],
                self,
            ).exec()
            return
        TableDialog(
            "Находки проверки",
            f"Найдено объектов: {len(threats)}",
            ["Файл", "Вердикт", "Риск", "Обнаружение"],
            [
                [
                    threat.get("name", ""),
                    "Угроза" if threat.get("verdict") == "malicious" else "Подозрение",
                    str(threat.get("score", 0)),
                    ", ".join(d.get("title", "") for d in threat.get("detections", [])[:2]),
                ]
                for threat in threats
            ],
            self,
        ).exec()

    def _clear(self) -> None:
        if not self.entries:
            return
        dialog = ConfirmDialog(
            "Очистить журнал",
            "Удалить всю историю проверок? Отчёты в карантине и настройки останутся.",
            "Очистить",
            danger=True,
            parent=self,
        )
        if dialog.exec() != dialog.Accepted:
            return
        self.ctx.history.clear()
        self.ctx.signals.toast.emit("Журнал очищен", theme.OK)
        self.refresh()

    def on_show(self) -> None:
        self.refresh()
