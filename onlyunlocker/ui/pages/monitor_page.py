"""Защита в реальном времени: наблюдение за папками и реакция на новые файлы."""
from __future__ import annotations

import os
import time
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.monitor import default_watch_dirs
from ...core.utils import human_time, shorten_path
from .. import theme
from ..dialogs import ThreatDetailDialog
from ..widgets import Badge, Card, StatCard, make_button
from .base import Page, faint, muted


class MonitorBridge(QObject):
    threat = Signal(object)


class MonitorPage(Page):
    title = "Мониторинг"
    subtitle = "Проверка новых файлов в выбранных папках"

    def __init__(self, ctx, parent=None) -> None:
        super().__init__(ctx, parent)
        self.bridge = MonitorBridge()
        self.bridge.threat.connect(self._on_threat)
        self.events: list = []
        self.monitor = ctx.monitor
        self.monitor.on_threat(self.bridge.threat.emit)
        self._build()
        self._refresh_dirs()
        self._sync_state()

    # --- разметка ----------------------------------------------------------
    def _build(self) -> None:
        self.state_badge = Badge("ОСТАНОВЛЕН", theme.TEXT_DIM)
        self.header_actions.addWidget(self.state_badge)
        self.toggle_button = make_button("Запустить", "Primary")
        self.toggle_button.clicked.connect(self._toggle)
        self.header_actions.addWidget(self.toggle_button)

        row = QHBoxLayout()
        row.setSpacing(16)

        stats = QVBoxLayout()
        stats.setSpacing(12)
        self.checked_card = StatCard("Проверено файлов", "0", "с момента запуска", theme.ACCENT)
        self.threat_card = StatCard("Обнаружено", "0", "угроз и подозрений", theme.DANGER)
        self.uptime_card = StatCard("Время работы", "0 с", "мониторинг", theme.OK)
        stats.addWidget(self.checked_card)
        stats.addWidget(self.threat_card)
        stats.addWidget(self.uptime_card)
        stats.addStretch(1)
        row.addLayout(stats, 1)

        watch_card = Card(padding=18, spacing=10)
        watch_card.add_header("Наблюдаемые папки")
        self.dirs_layout = QVBoxLayout()
        self.dirs_layout.setSpacing(6)
        watch_card.body.addLayout(self.dirs_layout)
        watch_card.body.addStretch(1)
        buttons = QHBoxLayout()
        add_button = make_button("Добавить папку")
        add_button.clicked.connect(self._add_dir)
        reset_button = make_button("Сбросить")
        reset_button.clicked.connect(self._reset_dirs)
        buttons.addWidget(add_button)
        buttons.addWidget(reset_button)
        buttons.addStretch(1)
        watch_card.body.addLayout(buttons)
        row.addWidget(watch_card, 2)
        self.content.addLayout(row, 0)

        events_card = Card(padding=18, spacing=10)
        events_card.add_header("События", "новые файлы с вердиктом")
        self.events_list = QListWidget()
        self.events_list.setAlternatingRowColors(True)
        self.events_list.itemDoubleClicked.connect(self._open_event)
        events_card.body.addWidget(self.events_list, 1)
        self.empty = faint("Пока тихо. Новые подозрительные файлы появятся здесь.")
        events_card.body.addWidget(self.empty)
        self.content.addWidget(events_card, 1)

        self.realtime_hint = muted(
            "Мониторинг работает на опросе папок: новые и изменённые исполняемые файлы проверяются автоматически. "
            "При обнаружении угрозы файл можно сразу отправить в карантин."
        )
        self.content.addWidget(self.realtime_hint)

    # --- папки -------------------------------------------------------------
    def _watched(self) -> list[str]:
        dirs = self.ctx.settings.get("watched_dirs") or []
        if not dirs:
            dirs = default_watch_dirs()
        return [d for d in dirs if d]

    def _save_watched(self, dirs: list[str]) -> None:
        self.ctx.settings.set("watched_dirs", dirs)
        self.monitor.directories = dirs

    def _refresh_dirs(self) -> None:
        while self.dirs_layout.count():
            item = self.dirs_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        for folder in self._watched():
            row = QWidget()
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 2, 0, 2)
            layout.setSpacing(8)
            label = QLabel(shorten_path(folder, 60))
            label.setToolTip(folder)
            label.setObjectName("Muted")
            exists = os.path.isdir(folder)
            status = Badge("активна" if exists else "нет доступа", theme.OK if exists else theme.TEXT_FAINT)
            remove = make_button("Убрать", "Ghost")
            remove.setFixedHeight(26)
            remove.clicked.connect(lambda _c=False, f=folder: self._remove_dir(f))
            layout.addWidget(label, 1)
            layout.addWidget(status)
            layout.addWidget(remove)
            self.dirs_layout.addWidget(row)

    def _add_dir(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Папка для наблюдения", str(Path.home()))
        if not folder:
            return
        dirs = self._watched()
        if folder not in dirs:
            dirs.append(folder)
            self._save_watched(dirs)
            self._refresh_dirs()
            self._sync_state()
            self.ctx.signals.toast.emit("Папка добавлена в наблюдение", theme.OK)

    def _remove_dir(self, folder: str) -> None:
        dirs = [d for d in self._watched() if d != folder]
        self._save_watched(dirs)
        self._refresh_dirs()
        if self.monitor.running:
            self.monitor.stop()
            self.monitor.start()
        self._sync_state()

    def _reset_dirs(self) -> None:
        self._save_watched(default_watch_dirs())
        self._refresh_dirs()
        if self.monitor.running:
            self.monitor.stop()
            self.monitor.start()
        self._sync_state()

    # --- запуск/останов ----------------------------------------------------
    def _toggle(self) -> None:
        self.set_running(not self.monitor.running)

    def set_running(self, running: bool, silent: bool = False) -> None:
        dirs = self._watched()
        if running:
            if not dirs:
                self.ctx.signals.toast.emit("Добавьте хотя бы одну папку для наблюдения", theme.WARN)
                return
            self.monitor.directories = [d for d in dirs if os.path.isdir(d)]
            if not self.monitor.directories:
                self.ctx.signals.toast.emit("Наблюдаемые папки недоступны", theme.DANGER)
                return
            self.monitor.start()
            self.ctx.settings.set("realtime", True)
            if not silent:
                self.ctx.signals.toast.emit("Мониторинг запущен", theme.OK)
        else:
            self.monitor.stop()
            self.ctx.settings.set("realtime", False)
            if not silent:
                self.ctx.signals.toast.emit("Мониторинг остановлен", theme.WARN)
        self._sync_state()

    def _sync_state(self) -> None:
        running = self.monitor.running
        self.toggle_button.setText("Остановить" if running else "Запустить")
        self.toggle_button.setObjectName("Danger" if running else "Primary")
        self.toggle_button.style().unpolish(self.toggle_button)
        self.toggle_button.style().polish(self.toggle_button)
        self.state_badge.set_state("АКТИВЕН" if running else "ОСТАНОВЛЕН", theme.OK if running else theme.TEXT_DIM)
        self.threat_card.set_value(str(self.monitor.stats.threats), "угроз и подозрений")
        self.checked_card.set_value(str(self.monitor.stats.checked), "с момента запуска")

    # --- события -----------------------------------------------------------
    def _on_threat(self, report) -> None:
        self.events.insert(0, report)
        self.events = self.events[:50]
        self.empty.hide()
        color = theme.DANGER if report.verdict.value == "malicious" else theme.WARN
        top = report.top_detection
        item = QListWidgetItem(
            f"{time.strftime('%H:%M:%S')}   {report.name}   —   {top.title if top else 'подозрительный файл'}"
        )
        item.setData(Qt.UserRole, report)
        item.setForeground(Qt.GlobalColor.white)
        item.setToolTip(report.path + "\nДвойной клик — подробности")
        self.events_list.insertItem(0, item)
        if self.events_list.count() > 200:
            self.events_list.takeItem(self.events_list.count() - 1)
        self.threat_card.set_value(str(self.monitor.stats.threats), "угроз и подозрений")
        self.ctx.signals.toast.emit(
            f"Обнаружен {report.verdict.label.lower()}ый файл: {report.name}", color
        )

    def _open_event(self, item: QListWidgetItem) -> None:
        report = item.data(Qt.UserRole)
        if report:
            ThreatDetailDialog(report, self.ctx, self).exec()

    def refresh_stats(self) -> None:
        self.checked_card.set_value(str(self.monitor.stats.checked), "с момента запуска")
        self.threat_card.set_value(str(self.monitor.stats.threats), "угроз и подозрений")
        self.uptime_card.set_value(human_time(self.monitor.stats.uptime) if self.monitor.running else "0 с", "мониторинг")

    def on_show(self) -> None:
        self.refresh_stats()
        self._sync_state()
