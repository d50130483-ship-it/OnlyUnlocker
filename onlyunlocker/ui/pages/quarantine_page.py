"""Карантин: изолированные файлы, восстановление и удаление."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
)

from ...core.utils import human_size
from .. import theme
from ..dialogs import ConfirmDialog
from ..widgets import Card, make_button
from .base import Page, faint


class QuarantinePage(Page):
    title = "Карантин"
    subtitle = "Изолированные файлы хранятся в закодированном виде"

    def __init__(self, ctx, parent=None) -> None:
        super().__init__(ctx, parent)
        self.items = []
        self._build()
        self.ctx.signals.quarantine_changed.connect(self.refresh)

    def _build(self) -> None:
        self.count_badge = QLabel("0 файлов")
        self.count_badge.setObjectName("Faint")
        self.header_actions.addWidget(self.count_badge)

        export_button = make_button("Экспорт списка")
        export_button.clicked.connect(self._export)
        self.header_actions.addWidget(export_button)

        clear_button = make_button("Очистить всё", "Danger")
        clear_button.clicked.connect(self._purge)
        self.header_actions.addWidget(clear_button)

        card = Card(padding=16, spacing=10)
        card.add_header("Содержимое карантина", "файлы закодированы уникальным ключом машины")
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Дата", "Файл", "Обнаружение", "Размер", "ID"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        card.body.addWidget(self.table, 1)

        self.empty = faint("Карантин пуст. Файлы, которые вы изолируете, появятся здесь.")
        card.body.addWidget(self.empty)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addStretch(1)
        self.restore_button = make_button("Восстановить")
        self.restore_button.setEnabled(False)
        self.restore_button.clicked.connect(self._restore)
        self.delete_button = make_button("Удалить", "Danger")
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self._delete)
        self.details_button = make_button("Свойства")
        self.details_button.setEnabled(False)
        self.details_button.clicked.connect(self._details)
        buttons.addWidget(self.details_button)
        buttons.addWidget(self.restore_button)
        buttons.addWidget(self.delete_button)
        card.body.addLayout(buttons)
        self.content.addWidget(card, 1)

        self.refresh()

    # --- данные ------------------------------------------------------------
    def refresh(self) -> None:
        self.items = self.ctx.quarantine.items()
        self.table.setRowCount(len(self.items))
        for row, item in enumerate(self.items):
            values = [item.added_str, item.original_path, ", ".join(item.detections) or "—", human_size(item.size), item.id]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setToolTip(str(value))
                if column == 4:
                    cell.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, column, cell)
        self.empty.setVisible(not self.items)
        self.count_badge.setText(
            f"{len(self.items)} файлов · {human_size(self.ctx.quarantine.total_size())}"
        )
        self._update_buttons()

    def _selected_ids(self) -> list[str]:
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        return [self.items[row].id for row in rows if row < len(self.items)]

    def _update_buttons(self) -> None:
        has_selection = bool(self._selected_ids())
        self.restore_button.setEnabled(has_selection)
        self.delete_button.setEnabled(has_selection)
        self.details_button.setEnabled(len(self._selected_ids()) == 1)

    # --- действия ----------------------------------------------------------
    def _restore(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        restored = 0
        for item_id in ids:
            try:
                self.ctx.quarantine.restore(item_id)
                restored += 1
            except (OSError, KeyError, ValueError) as exc:
                self.ctx.signals.toast.emit(f"Не удалось восстановить: {exc}", theme.DANGER)
        if restored:
            self.ctx.signals.toast.emit(f"Восстановлено файлов: {restored}", theme.WARN)
        self.ctx.signals.quarantine_changed.emit()

    def _delete(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        dialog = ConfirmDialog(
            "Удалить файлы",
            f"Удалить безвозвратно {len(ids)} файл(ов) из карантина? Восстановить их будет невозможно.",
            "Удалить",
            danger=True,
            parent=self,
        )
        if dialog.exec() != dialog.Accepted:
            return
        for item_id in ids:
            self.ctx.quarantine.delete(item_id)
        self.ctx.signals.toast.emit("Файлы удалены из карантина", theme.OK)
        self.ctx.signals.quarantine_changed.emit()

    def _purge(self) -> None:
        if not self.items:
            return
        dialog = ConfirmDialog(
            "Очистить карантин",
            f"Будет безвозвратно удалено {len(self.items)} файл(ов). Продолжить?",
            "Очистить",
            danger=True,
            parent=self,
        )
        if dialog.exec() != dialog.Accepted:
            return
        count = self.ctx.quarantine.purge()
        self.ctx.signals.toast.emit(f"Карантин очищен: {count} файл(ов)", theme.OK)
        self.ctx.signals.quarantine_changed.emit()

    def _export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить список", "quarantine.json", "JSON (*.json)")
        if not path:
            return
        try:
            self.ctx.quarantine.export_report(path)
            self.ctx.signals.toast.emit("Список сохранён", theme.OK)
        except OSError as exc:
            self.ctx.signals.toast.emit(f"Ошибка сохранения: {exc}", theme.DANGER)

    def _details(self) -> None:
        ids = self._selected_ids()
        if len(ids) != 1:
            return
        item = next((i for i in self.items if i.id == ids[0]), None)
        if not item:
            return
        from ..dialogs import TableDialog

        TableDialog(
            "Свойства объекта",
            item.original_path,
            ["Поле", "Значение"],
            [
                ["ID", item.id],
                ["Исходный путь", item.original_path],
                ["SHA-256", item.sha256],
                ["Размер", human_size(item.size)],
                ["Добавлен", item.added_str],
                ["Вердикт", item.verdict],
                ["Обнаружения", ", ".join(item.detections) or "—"],
                ["Файл в карантине", item.stored_name],
            ],
            self,
        ).exec()

    def on_show(self) -> None:
        self.refresh()
