"""Главная страница: состояние защиты и быстрые действия."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ...core.utils import human_time, is_admin
from .. import theme
from ..widgets import Badge, Card, ShieldWidget, StatCard, ToggleSwitch, clear_layout, hline, make_button
from .base import Page, faint, muted


class DashboardPage(Page):
    title = "Защита"
    subtitle = "Обзор состояния OnlyUnlocker"

    def __init__(self, ctx, parent=None) -> None:
        super().__init__(ctx, parent)
        self._build()
        self.ctx.signals.scan_finished.connect(lambda _summary: self.refresh())
        self.ctx.signals.quarantine_changed.connect(self.refresh)

    # --- разметка ----------------------------------------------------------
    def _build(self) -> None:
        top = QHBoxLayout()
        top.setSpacing(16)

        hero = Card(padding=20, spacing=14, accent=True)
        hero_row = QHBoxLayout()
        hero_row.setSpacing(18)
        self.shield = ShieldWidget()
        self.shield.setFixedWidth(186)
        hero_row.addWidget(self.shield)

        column = QVBoxLayout()
        column.setSpacing(8)
        self.status_badge = Badge("ПРОВЕРКА НЕ ЗАПУСКАЛАСЬ", theme.TEXT_DIM)
        badge_row = QHBoxLayout()
        badge_row.addWidget(self.status_badge)
        badge_row.addStretch(1)
        column.addLayout(badge_row)

        self.status_title = QLabel("Защита активна")
        self.status_title.setStyleSheet("font-size: 26px; font-weight: 700; color: #FFFFFF;")
        column.addWidget(self.status_title)
        self.status_text = muted("Все ключевые зоны под наблюдением. Запустите проверку, чтобы убедиться, что на диске нет угроз.")
        self.status_text.setMinimumHeight(40)
        column.addWidget(self.status_text)

        buttons = QHBoxLayout()
        buttons.setSpacing(10)
        self.quick_button = make_button("Быстрая", "Primary")
        self.quick_button.clicked.connect(lambda: self._start("quick"))
        self.full_button = make_button("Полная")
        self.full_button.clicked.connect(lambda: self._start("full"))
        self.custom_button = make_button("Своя папка")
        self.custom_button.clicked.connect(self._pick_folder)
        buttons.addWidget(self.quick_button)
        buttons.addWidget(self.full_button)
        buttons.addWidget(self.custom_button)
        buttons.addStretch(1)
        column.addLayout(buttons)

        self.last_scan_label = faint("Проверок ещё не было")
        column.addWidget(self.last_scan_label)
        hero_row.addLayout(column, 1)
        hero.body.addLayout(hero_row)
        top.addWidget(hero, 3)

        stats = QGridLayout()
        stats.setSpacing(12)
        self.threat_card = StatCard("Угрозы", "0", "за последнюю проверку", theme.DANGER)
        self.quarantine_card = StatCard("Карантин", "0", "изолировано файлов", theme.WARN)
        self.scanned_card = StatCard("Проверено", "0", "файлов за всё время", theme.ACCENT)
        self.db_card = StatCard("База сигнатур", "—", "правил", theme.OK)
        stats.addWidget(self.threat_card, 0, 0)
        stats.addWidget(self.quarantine_card, 0, 1)
        stats.addWidget(self.scanned_card, 1, 0)
        stats.addWidget(self.db_card, 1, 1)
        stats_widget = QWidget()
        stats_widget.setLayout(stats)
        top.addWidget(stats_widget, 2)
        self.content.addLayout(top, 0)

        bottom = QHBoxLayout()
        bottom.setSpacing(16)

        self.findings_card = Card(padding=18, spacing=10)
        self.findings_card.add_header("Последние находки", "журнал")
        self.findings_body = QVBoxLayout()
        self.findings_body.setSpacing(6)
        self.findings_card.body.addLayout(self.findings_body)
        self.findings_card.body.addStretch(1)
        bottom.addWidget(self.findings_card, 3)

        status_card = Card(padding=18, spacing=12)
        status_card.add_header("Состояние защиты")
        self.realtime_row = QWidget()
        rt_layout = QHBoxLayout(self.realtime_row)
        rt_layout.setContentsMargins(0, 0, 0, 0)
        rt_text = QVBoxLayout()
        rt_text.setSpacing(1)
        rt_title = QLabel("Защита в реальном времени")
        rt_title.setObjectName("CardTitle")
        rt_caption = faint("Следит за папками и проверяет новые файлы")
        rt_text.addWidget(rt_title)
        rt_text.addWidget(rt_caption)
        self.realtime_toggle = ToggleSwitch()
        self.realtime_toggle.setChecked(bool(self.ctx.settings.get("realtime", False)))
        self.realtime_toggle.toggled.connect(self._toggle_realtime)
        rt_layout.addLayout(rt_text, 1)
        rt_layout.addWidget(self.realtime_toggle)
        status_card.body.addWidget(self.realtime_row)
        status_card.body.addWidget(hline())

        self.info_rows = QVBoxLayout()
        self.info_rows.setSpacing(6)
        status_card.body.addLayout(self.info_rows)
        status_card.body.addStretch(1)
        bottom.addWidget(status_card, 2)
        self.content.addLayout(bottom, 1)

        self.refresh()

    # --- логика ------------------------------------------------------------
    def _start(self, mode: str) -> None:
        self.ctx.navigate("scan")
        page = self.ctx.scan_page
        if page is not None:
            page.start(mode)

    def _pick_folder(self) -> None:
        from PySide6.QtWidgets import QFileDialog

        folder = QFileDialog.getExistingDirectory(self, "Выберите папку для проверки")
        if folder:
            self.ctx.navigate("scan")
            if self.ctx.scan_page is not None:
                self.ctx.scan_page.start("custom", folder)

    def _toggle_realtime(self, checked: bool) -> None:
        self.ctx.settings.set("realtime", checked)
        self.ctx.navigate("monitor")
        if self.ctx.monitor_page is not None:
            self.ctx.monitor_page.set_running(checked)
        self.refresh()
        self.ctx.signals.settings_changed.emit()

    def refresh(self) -> None:
        stats = self.ctx.history.stats()
        q_count = self.ctx.quarantine.count
        db = self.ctx.engine.db

        self.threat_card.set_value(
            str(stats["infected"]),
            "за последнюю проверку" if stats["last"] else "угроз не найдено",
        )
        self.quarantine_card.set_value(str(q_count), "изолировано файлов")
        self.scanned_card.set_value(f"{stats['scanned']:,}".replace(",", " "), "файлов за всё время")
        self.db_card.set_value(str(db.total), f"версия {db.version}")

        last = stats["last"]
        if last:
            when = time.strftime("%d.%m.%Y %H:%M", time.localtime(last.get("finished_at", 0)))
            infected = int(last.get("infected", 0))
            suspicious = int(last.get("suspicious", 0))
            scanned = int(last.get("scanned", 0))
            elapsed = max(0.0, float(last.get("finished_at", 0)) - float(last.get("started_at", 0)))
            self.last_scan_label.setText(
                f"Последняя проверка: {when} · {scanned} файлов · {human_time(elapsed)}"
            )
            if infected:
                self.shield.set_state("danger")
                self.status_badge.set_state(f"НАЙДЕНО УГРОЗ: {infected}", theme.DANGER)
                self.status_title.setText("Требуется внимание")
                self.status_text.setText(
                    f"Обнаружено {infected} угрожающих и {suspicious} подозрительных файлов. "
                    "Откройте результаты проверки и переместите их в карантин."
                )
            elif suspicious:
                self.shield.set_state("warn")
                self.status_badge.set_state(f"ПОДОЗРИТЕЛЬНЫХ: {suspicious}", theme.WARN)
                self.status_title.setText("Есть подозрительные файлы")
                self.status_text.setText(
                    "Проверка завершена, но часть файлов выглядит нетипично. "
                    "Просмотрите отчёт, чтобы решить, что с ними делать."
                )
            else:
                self.shield.set_state("ok")
                self.status_badge.set_state("УГРОЗ НЕ ОБНАРУЖЕНО", theme.OK)
                self.status_title.setText("Всё чисто")
                self.status_text.setText("Проверка завершена, вредоносных объектов не найдено. Защита работает в штатном режиме.")
        else:
            self.shield.set_state("idle")
            self.status_badge.set_state("ПРОВЕРКА НЕ ЗАПУСКАЛАСЬ", theme.TEXT_DIM)
            self.status_title.setText("Защита активна")
            self.status_text.setText(
                "Все ключевые зоны под наблюдением. Запустите проверку, чтобы убедиться, что на диске нет угроз."
            )

        self._refresh_findings(stats)
        self._refresh_status_card(db)

    def _refresh_findings(self, stats: dict) -> None:
        clear_layout(self.findings_body)

        threats = []
        if stats["last"]:
            threats = list(stats["last"].get("threats", []))[:5]

        if not threats:
            empty = QWidget()
            layout = QVBoxLayout(empty)
            layout.setContentsMargins(0, 18, 0, 18)
            layout.setSpacing(6)
            icon = QLabel("OK")
            icon.setAlignment(Qt.AlignCenter)
            icon.setStyleSheet(
                f"color: {theme.OK}; border: 1px solid {theme.rgba(theme.OK, 0.4)}; border-radius: 22px;"
                "font-size: 12px; font-weight: 700;"
            )
            icon.setFixedSize(44, 44)
            title = QLabel("Угроз не найдено")
            title.setAlignment(Qt.AlignCenter)
            title.setStyleSheet("font-size: 14px; font-weight: 600;")
            hint = faint("После проверки здесь появятся найденные объекты.")
            hint.setAlignment(Qt.AlignCenter)
            layout.addWidget(icon, 0, Qt.AlignHCenter)
            layout.addWidget(title)
            layout.addWidget(hint)
            self.findings_body.addWidget(empty)
            return

        for threat in threats:
            self.findings_body.addWidget(self._finding_row(threat))

    def _finding_row(self, threat: dict) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(10)
        verdict = threat.get("verdict", "suspicious")
        color = theme.DANGER if verdict == "malicious" else theme.WARN
        marker = QLabel()
        marker.setFixedSize(6, 26)
        marker.setStyleSheet(f"background-color: {color}; border-radius: 3px;")
        layout.addWidget(marker)

        text = QVBoxLayout()
        text.setSpacing(0)
        name = QLabel(threat.get("name") or threat.get("path", ""))
        name.setStyleSheet("font-weight: 600;")
        detections = threat.get("detections") or []
        detail = detections[0]["title"] if detections else "Подозрительный файл"
        path = QLabel(detail)
        path.setObjectName("Faint")
        text.addWidget(name)
        text.addWidget(path)
        layout.addLayout(text, 1)

        badge = Badge("УГРОЗА" if verdict == "malicious" else "ПОДОЗРЕНИЕ", color)
        layout.addWidget(badge)
        return row

    def _refresh_status_card(self, db) -> None:
        clear_layout(self.info_rows)

        from .base import key_value

        self.info_rows.addWidget(key_value("База сигнатур", f"версия {db.version}"))
        self.info_rows.addWidget(key_value("Правил в базе", f"{db.total}"))
        self.info_rows.addWidget(key_value("Движок", "сигнатуры + PE-эвристика" if self.ctx.settings.get("deep_heuristics", True) else "только сигнатуры"))
        self.info_rows.addWidget(key_value("Права администратора", "да" if is_admin() else "нет (часть функций ограничена)"))
        self.info_rows.addWidget(key_value("Обновления", "автоматически" if self.ctx.settings.get("auto_update", True) else "вручную"))

    def on_show(self) -> None:
        self.refresh()
