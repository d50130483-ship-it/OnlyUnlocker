"""Диалоги: детали находки, таблицы системы, выполнение команд."""
from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from ..core.models import FileReport
from ..core.utils import human_size
from . import theme
from .widgets import Badge, Card, make_button


class BaseDialog(QDialog):
    def __init__(self, title: str, subtitle: str = "", width: int = 720, height: int = 520, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(width, height)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(12)
        title_label = QLabel(title)
        title_label.setObjectName("PageTitle")
        layout.addWidget(title_label)
        if subtitle:
            sub = QLabel(subtitle)
            sub.setObjectName("PageSubtitle")
            sub.setWordWrap(True)
            layout.addWidget(sub)
        self.body = QVBoxLayout()
        self.body.setSpacing(12)
        layout.addLayout(self.body, 1)
        self.buttons = QHBoxLayout()
        self.buttons.setSpacing(8)
        self.buttons.addStretch(1)
        layout.addLayout(self.buttons)

    def add_close(self, text: str = "Закрыть") -> QPushButton:
        button = make_button(text, "Ghost")
        button.clicked.connect(self.accept)
        self.buttons.addWidget(button)
        return button


class ThreatDetailDialog(BaseDialog):
    """Полная карточка находки."""

    def __init__(self, report: FileReport, ctx=None, parent=None) -> None:
        super().__init__("Детали находки", report.path, 760, 640, parent)
        self.report = report
        self.ctx = ctx

        header = Card(padding=16, spacing=8)
        row = QHBoxLayout()
        verdict_color = theme.DANGER if report.verdict.value == "malicious" else theme.WARN
        if report.verdict.value == "clean":
            verdict_color = theme.OK
        badge = Badge(report.verdict.label.upper(), verdict_color)
        row.addWidget(badge)
        score = QLabel(f"Уровень риска: {report.score}/100")
        score.setStyleSheet(f"color: {verdict_color}; font-weight: 600;")
        row.addWidget(score)
        row.addStretch(1)
        row.addWidget(QLabel(f"{human_size(report.size)}"))
        header.body.addLayout(row)

        from .pages.base import key_value

        header.body.addWidget(key_value("Файл", report.name))
        header.body.addWidget(key_value("Размер", human_size(report.size)))
        header.body.addWidget(key_value("Изменён", time.strftime("%d.%m.%Y %H:%M", time.localtime(report.modified)) if report.modified else "—"))
        header.body.addWidget(key_value("SHA-256", report.sha256 or "—"))
        if report.meta:
            header.body.addWidget(key_value("Формат", str(report.meta.get("format", "—"))))
            if report.meta.get("format") == "PE":
                header.body.addWidget(
                    key_value(
                        "PE",
                        f"{report.meta.get('architecture')} · {report.meta.get('subsystem')} · "
                        f"секций {report.meta.get('sections')} · импортов {report.meta.get('imports')}",
                    )
                )
                header.body.addWidget(key_value("Упаковщик", str(report.meta.get("packer", "нет"))))
                header.body.addWidget(key_value("Подпись", "есть" if report.meta.get("signed") else "нет"))
                header.body.addWidget(key_value("Компиляция", str(report.meta.get("compile_time") or "—")))
        self.body.addWidget(header)

        title = QLabel("Сработавшие проверки")
        title.setObjectName("CardTitle")
        self.body.addWidget(title)

        table = QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(["Риск", "Проверка", "Описание"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        table.setRowCount(len(report.detections))
        for row_index, detection in enumerate(report.detections):
            severity = QTableWidgetItem({"critical": "критично", "high": "высокий", "medium": "средний", "low": "низкий"}.get(detection.severity, detection.severity))
            severity.setForeground(Qt.GlobalColor.white)
            table.setItem(row_index, 0, severity)
            table.setItem(row_index, 1, QTableWidgetItem(detection.title))
            table.setItem(row_index, 2, QTableWidgetItem(detection.description or detection.rule))
        self.body.addWidget(table, 1)

        copy = make_button("Копировать SHA-256")
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(report.sha256))
        self.buttons.addWidget(copy)

        open_folder = make_button("Открыть папку")
        open_folder.clicked.connect(lambda: self._open_folder(report.path))
        self.buttons.addWidget(open_folder)

        if ctx is not None and report.verdict.value in ("malicious", "suspicious") and Path(report.path).exists():
            quarantine = make_button("В карантин", "Primary")
            quarantine.clicked.connect(self._quarantine)
            self.buttons.addWidget(quarantine)

        self.add_close()

    def _open_folder(self, path: str) -> None:
        folder = str(Path(path).parent)
        QDesktopServices.openUrl(QUrl.fromLocalFile(folder))

    def _quarantine(self) -> None:
        if not self.ctx:
            return
        try:
            item = self.ctx.quarantine.add(self.report)
        except OSError as exc:
            self.ctx.signals.toast.emit(f"Не удалось изолировать: {exc}", theme.DANGER)
            return
        self.ctx.signals.quarantine_changed.emit()
        self.ctx.signals.toast.emit(f"Файл изолирован: {item.id}", theme.OK)
        self.accept()


class TableDialog(BaseDialog):
    """Универсальный диалог со списком строк."""

    def __init__(self, title: str, subtitle: str, headers: list[str], rows: list[list[str]], parent=None) -> None:
        super().__init__(title, subtitle, 860, 620, parent)
        self.table = QTableWidget(0, len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.table.setItem(r, c, item)
        self.body.addWidget(self.table, 1)
        self.add_close()


class TerminalDialog(BaseDialog):
    """Окно выполнения команды с живым выводом."""

    def __init__(self, title: str, subtitle: str, program: str, arguments: list[str], warning: str = "", parent=None) -> None:
        super().__init__(title, subtitle, 820, 560, parent)
        from .workers import ProcessRunner

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("font-family: 'DejaVu Sans Mono', 'Consolas', monospace; font-size: 12px;")
        self.body.addWidget(self.output, 1)

        self.status = QLabel("Готово к запуску")
        self.status.setObjectName("Faint")
        self.body.addWidget(self.status)

        self.runner = ProcessRunner(self)
        self.runner.line.connect(self._append)
        self.runner.done.connect(self._finished)

        self.start_button = make_button("Выполнить" if not warning else "Выполнить с риском", "Primary")
        self.start_button.clicked.connect(lambda: self.start(program, arguments))
        self.buttons.addWidget(self.start_button)

        self.stop_button = make_button("Остановить", "Danger")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.runner.stop)
        self.buttons.addWidget(self.stop_button)
        self.add_close()

        if warning:
            label = QLabel(warning)
            label.setWordWrap(True)
            label.setStyleSheet(f"color: {theme.WARN};")
            self.body.insertWidget(0, label)

    def start(self, program: str, arguments: list[str]) -> None:
        self.output.clear()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status.setText("Выполняется…")
        self.runner.start(program, arguments)

    def _append(self, line: str) -> None:
        self.output.appendPlainText(line)

    def _finished(self, code: int) -> None:
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status.setText(f"Завершено с кодом {code}")


class ConfirmDialog(BaseDialog):
    def __init__(self, title: str, message: str, confirm_text: str = "Подтвердить", danger: bool = False, parent=None) -> None:
        super().__init__(title, "", 520, 220, parent)
        label = QLabel(message)
        label.setWordWrap(True)
        self.body.addWidget(label)
        self.body.addStretch(1)
        cancel = make_button("Отмена", "Ghost")
        cancel.clicked.connect(self.reject)
        self.buttons.addWidget(cancel)
        confirm = make_button(confirm_text, "Danger" if danger else "Primary")
        confirm.clicked.connect(self.accept)
        self.buttons.addWidget(confirm)


class AboutDialog(BaseDialog):
    def __init__(self, ctx, parent=None) -> None:
        from .. import __version__
        from ..core.utils import app_data_dir

        super().__init__("О программе", "OnlyUnlocker — антивирусный сканер на Python", 620, 460, parent)
        db = ctx.engine.db
        text = QLabel(
            f"<p><b>OnlyUnlocker {__version__}</b></p>"
            "<p>Собственный движок: хеш-сигнатуры, байтовые шаблоны, текстовые правила, "
            "разбор PE (секции, импорты, упаковщики, оверлей) и поведенческие эвристики.</p>"
            f"<p>База сигнатур: <b>{db.version}</b> · правил: <b>{db.total}</b><br>"
            f"Данные приложения: {app_data_dir()}</p>"
            "<p style='color:#8B95A5'>Программа не заменяет полноценный антивирус с облачной "
            "репутацией и драйвером фильтрации. Используйте как дополнительный инструмент "
            "и для обучения.</p>"
        )
        text.setWordWrap(True)
        text.setTextFormat(Qt.RichText)
        self.body.addWidget(text)
        self.body.addStretch(1)
        self.add_close()


class PathScanDialog(BaseDialog):
    """Проверка набора файлов с прогрессом и итоговой таблицей."""

    def __init__(self, engine, paths: list[str], title: str = "Проверка объектов", parent=None) -> None:
        super().__init__(title, f"Объектов к проверке: {len(paths)}", 860, 600, parent)
        from PySide6.QtWidgets import QProgressBar

        from .workers import ScanWorker

        self.engine = engine
        self.worker = ScanWorker(engine, paths, "custom", self)
        self.worker.finished_scan.connect(self._done)
        self.worker.progress.connect(self._progress)

        self.status = QLabel("Проверка…")
        self.body.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedHeight(10)
        self.body.addWidget(self.progress)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Файл", "Вердикт", "Риск", "Обнаружение"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.body.addWidget(self.table, 1)

        self.add_close()
        self.worker.start()

    def _progress(self, payload: dict) -> None:
        report = payload["report"]
        if report.verdict.value in ("malicious", "suspicious"):
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(report.path))
            self.table.setItem(row, 1, QTableWidgetItem(report.verdict.label))
            self.table.setItem(row, 2, QTableWidgetItem(str(report.score)))
            top = report.top_detection
            self.table.setItem(row, 3, QTableWidgetItem(top.title if top else "—"))

    def _done(self, summary) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.status.setText(
            f"Проверено: {summary.scanned} · угроз: {summary.infected} · подозрительных: {summary.suspicious}"
        )

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(3000)
        super().closeEvent(event)
