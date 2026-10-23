"""Страница проверки: выбор цели, прогресс, живой список находок."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from ...core.models import FileReport, ScanSummary, Verdict
from ...core.scanner import default_targets
from ...core.utils import human_size, human_time, shorten_path
from .. import theme
from ..dialogs import ThreatDetailDialog
from ..widgets import Badge, Card, make_button
from ..workers import ScanWorker
from .base import Page, faint


class ScanPage(Page):
    title = "Проверка"
    subtitle = "Сигнатуры, PE-эвристика и поведенческие правила"

    def __init__(self, ctx, parent=None) -> None:
        super().__init__(ctx, parent)
        self.worker: ScanWorker | None = None
        self.mode = "quick"
        self.custom_target: str | None = None
        self.summary: ScanSummary | None = None
        self.reports: list[FileReport] = []
        self._started_at = 0.0
        self._build()

    # --- разметка ----------------------------------------------------------
    def _build(self) -> None:
        self.export_button = make_button("Экспорт отчёта")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export)
        self.header_actions.addWidget(self.export_button)

        target_card = Card(padding=16, spacing=12)
        target_card.add_header("Что проверяем")
        modes = QHBoxLayout()
        modes.setSpacing(8)
        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)
        for key, label in (("quick", "Быстрая"), ("full", "Полная"), ("system", "Системные"), ("custom", "Своя папка")):
            button = make_button(label, "Ghost")
            button.setCheckable(True)
            button.setProperty("mode", key)
            button.clicked.connect(lambda _checked=False, m=key: self._select_mode(m))
            self.mode_group.addButton(button)
            modes.addWidget(button)
            if key == "quick":
                button.setChecked(True)
        self.path_label = QLabel("")
        self.path_label.setObjectName("Faint")
        self.path_label.setWordWrap(True)
        modes.addStretch(1)
        target_card.body.addLayout(modes)
        target_card.body.addWidget(self.path_label)
        self.content.addWidget(target_card)

        progress_card = Card(padding=16, spacing=12, accent=True)
        status_row = QHBoxLayout()
        self.status_label = QLabel("Готов к проверке")
        self.status_label.setStyleSheet("font-size: 15px; font-weight: 600;")
        self.state_badge = Badge("ОЖИДАНИЕ", theme.TEXT_DIM)
        status_row.addWidget(self.status_label)
        status_row.addStretch(1)
        status_row.addWidget(self.state_badge)
        progress_card.body.addLayout(status_row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(10)
        progress_card.body.addWidget(self.progress)

        counters = QHBoxLayout()
        counters.setSpacing(26)
        self.counter_labels: dict[str, QLabel] = {}
        for key, title in (
            ("scanned", "Проверено"),
            ("threats", "Угроз"),
            ("speed", "Скорость"),
            ("time", "Время"),
        ):
            block = QVBoxLayout()
            block.setSpacing(1)
            caption = QLabel(title.upper())
            caption.setObjectName("CardCaption")
            value = QLabel("—")
            value.setStyleSheet("font-size: 16px; font-weight: 600;")
            block.addWidget(caption)
            block.addWidget(value)
            counters.addLayout(block)
            self.counter_labels[key] = value
        counters.addStretch(1)

        self.start_button = make_button("Начать проверку", "Primary")
        self.start_button.clicked.connect(self._start_clicked)
        counters.addWidget(self.start_button)
        self.stop_button = make_button("Стоп", "Danger")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._stop)
        counters.addWidget(self.stop_button)
        progress_card.body.addLayout(counters)
        self.content.addWidget(progress_card)

        results_card = Card(padding=16, spacing=10)
        header_row = results_card.add_header("Результаты", "двойной клик открывает детали")
        self.quarantine_all_button = make_button("В карантин всё", "Danger")
        self.quarantine_all_button.setEnabled(False)
        self.quarantine_all_button.clicked.connect(self._quarantine_all)
        header_row.addWidget(self.quarantine_all_button)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Файл", "Вердикт", "Риск", "Обнаружение", "Путь"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.doubleClicked.connect(self._open_details)
        results_card.body.addWidget(self.table, 1)

        self.empty_label = faint("Находки появятся здесь во время проверки.")
        results_card.body.addWidget(self.empty_label)
        self.content.addWidget(results_card, 1)

        self._select_mode("quick")

    # --- выбор цели --------------------------------------------------------
    def _select_mode(self, mode: str) -> None:
        self.mode = mode
        for button in self.mode_group.buttons():
            if button.property("mode") == mode:
                button.setChecked(True)
        if mode == "custom":
            self.path_label.setText(self.custom_target or "Папка не выбрана — нажмите «Своя папка», чтобы изменить.")
        else:
            targets = default_targets(mode)
            self.path_label.setText("Цели: " + " · ".join(shorten_path(t, 56) for t in targets) if targets else "Цели не найдены")

    def _start_clicked(self) -> None:
        if self.mode == "custom":
            folder = QFileDialog.getExistingDirectory(self, "Выберите папку для проверки", self.custom_target or str(Path.home()))
            if not folder:
                return
            self.custom_target = folder
            self.path_label.setText(folder)
            self.start("custom", folder)
        else:
            self.start(self.mode)

    # --- запуск ------------------------------------------------------------
    def start(self, mode: str, target: str | None = None) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        self.mode = mode
        self._select_mode(mode)
        targets = [target] if target else ([self.custom_target] if mode == "custom" and self.custom_target else default_targets(mode))
        targets = [t for t in targets if t and os.path.exists(t)]
        if not targets:
            self.status_label.setText("Не найдено существующих папок для проверки")
            self.ctx.signals.toast.emit("Нет доступных целей для проверки", theme.WARN)
            return

        self.reports.clear()
        self.summary = None
        self.table.setRowCount(0)
        self.empty_label.show()
        self.progress.setValue(0)
        self.export_button.setEnabled(False)
        self.quarantine_all_button.setEnabled(False)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText("Подготовка списка файлов…")
        self.state_badge.set_state("ПОДГОТОВКА", theme.ACCENT)
        for key in self.counter_labels:
            self.counter_labels[key].setText("—")
        self._started_at = time.monotonic()

        self.worker = ScanWorker(self.ctx.engine, targets, mode, self)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished_scan.connect(self._on_finished)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()
        self.ctx.signals.scan_started.emit(mode)

    def _stop(self) -> None:
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.stop_button.setEnabled(False)
            self.status_label.setText("Останавливаю проверку…")

    # --- события воркера ---------------------------------------------------
    def _on_progress(self, payload: dict) -> None:
        scanned = payload["scanned"]
        total = payload["total"] or 0
        if total:
            percent = min(100, int(scanned / total * 100))
            self.progress.setValue(percent)
            self.progress.setFormat(f"{percent}%")
        elapsed = max(0.001, payload["elapsed"])
        speed = payload["bytes"] / elapsed
        self.counter_labels["scanned"].setText(f"{scanned} / {total or '?'}")
        self.counter_labels["threats"].setText(str(payload["infected"] + payload["suspicious"]))
        self.counter_labels["speed"].setText(f"{human_size(speed)}/с")
        self.counter_labels["time"].setText(human_time(elapsed))
        self.status_label.setText(f"Проверяется: {shorten_path(payload['report'].path, 70)}")

        report: FileReport = payload["report"]
        if report.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            self._add_report(report)

    def _add_report(self, report: FileReport) -> None:
        self.reports.append(report)
        self.empty_label.hide()
        row = self.table.rowCount()
        self.table.insertRow(row)
        color = theme.DANGER if report.verdict == Verdict.MALICIOUS else theme.WARN
        name_item = QTableWidgetItem(report.name)
        name_item.setToolTip(report.path)
        self.table.setItem(row, 0, name_item)
        verdict_item = QTableWidgetItem(report.verdict.label)
        verdict_item.setForeground(Qt.GlobalColor.white)
        self.table.setItem(row, 1, verdict_item)
        score_item = QTableWidgetItem(str(report.score))
        score_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 2, score_item)
        top = report.top_detection
        detection_item = QTableWidgetItem(top.title if top else "—")
        detection_item.setToolTip("\n".join(d.title for d in report.detections))
        self.table.setItem(row, 3, detection_item)
        path_item = QTableWidgetItem(shorten_path(report.path, 70))
        path_item.setToolTip(report.path)
        self.table.setItem(row, 4, path_item)
        self.table.item(row, 0).setData(Qt.UserRole, report)
        # подсветка строки
        from PySide6.QtGui import QColor

        for column in range(5):
            item = self.table.item(row, column)
            item.setBackground(QColor(color).darker(360))
        self.table.item(row, 0).setForeground(QColor(color))

    def _on_finished(self, summary: ScanSummary) -> None:
        self.summary = summary
        self.worker = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.export_button.setEnabled(True)
        self.quarantine_all_button.setEnabled(bool(self.reports))
        self.progress.setValue(100 if not summary.cancelled else self.progress.value())
        elapsed = summary.elapsed

        if summary.cancelled:
            self.state_badge.set_state("ОСТАНОВЛЕНО", theme.WARN)
            self.status_label.setText(f"Проверка остановлена · проверено {summary.scanned} файлов")
        elif summary.infected:
            self.state_badge.set_state(f"УГРОЗЫ: {summary.infected}", theme.DANGER)
            self.status_label.setText(f"Проверка завершена · найдено угроз: {summary.infected}, подозрительных: {summary.suspicious}")
        elif summary.suspicious:
            self.state_badge.set_state(f"ПОДОЗРЕНИЯ: {summary.suspicious}", theme.WARN)
            self.status_label.setText("Проверка завершена · есть подозрительные файлы")
        else:
            self.state_badge.set_state("ЧИСТО", theme.OK)
            self.status_label.setText("Проверка завершена · угроз не найдено")

        self.counter_labels["scanned"].setText(str(summary.scanned))
        self.counter_labels["threats"].setText(str(summary.infected + summary.suspicious))
        self.counter_labels["time"].setText(human_time(elapsed))
        speed = summary.bytes_scanned / elapsed if elapsed else 0
        self.counter_labels["speed"].setText(f"{human_size(speed)}/с")

        self.ctx.history.add(summary)
        self.ctx.signals.scan_finished.emit(summary)

        if self.ctx.settings.get("quarantine_automatically", False) and self.reports:
            self._quarantine_all(silent=True)

        if summary.infected:
            self.ctx.signals.toast.emit(f"Найдено угроз: {summary.infected}. Рекомендуем карантин.", theme.DANGER)
        elif summary.cancelled:
            self.ctx.signals.toast.emit("Проверка остановлена", theme.WARN)
        else:
            self.ctx.signals.toast.emit("Проверка завершена: угроз не найдено", theme.OK)

    def _on_failed(self, message: str) -> None:
        self.worker = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.state_badge.set_state("ОШИБКА", theme.DANGER)
        self.status_label.setText(f"Ошибка проверки: {message}")

    # --- действия ----------------------------------------------------------
    def _open_details(self, index) -> None:
        item = self.table.item(index.row(), 0)
        if not item:
            return
        report = item.data(Qt.UserRole)
        if report:
            ThreatDetailDialog(report, self.ctx, self).exec()

    def _quarantine_all(self, silent: bool = False) -> None:
        moved = 0
        errors = 0
        for report in list(self.reports):
            if not os.path.exists(report.path):
                continue
            try:
                self.ctx.quarantine.add(report)
                moved += 1
            except OSError:
                errors += 1
        if moved:
            self.reports = [r for r in self.reports if os.path.exists(r.path)]
            self.ctx.signals.quarantine_changed.emit()
            self.table.setRowCount(0)
            for report in self.reports:
                self._add_report(report)
            self.quarantine_all_button.setEnabled(bool(self.reports))
        if not silent:
            text = f"Изолировано файлов: {moved}"
            if errors:
                text += f", не удалось: {errors}"
            self.ctx.signals.toast.emit(text, theme.OK if moved else theme.WARN)

    def _export(self) -> None:
        if not self.summary:
            return
        default = f"onlyunlocker-report-{time.strftime('%Y%m%d-%H%M')}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", str(Path.home() / default), "JSON (*.json)")
        if not path:
            return
        try:
            Path(path).write_text(json.dumps(self.summary.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc:
            self.ctx.signals.toast.emit(f"Не удалось сохранить: {exc}", theme.DANGER)
            return
        self.ctx.signals.toast.emit("Отчёт сохранён", theme.OK)

    def on_show(self) -> None:
        if not (self.worker and self.worker.isRunning()):
            self._select_mode(self.mode)
