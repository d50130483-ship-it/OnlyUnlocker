"""Настройки приложения и обновление базы сигнатур."""
from __future__ import annotations

from PySide6.QtCore import QObject, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ...core import updater
from ...core.utils import app_data_dir
from .. import theme
from ..dialogs import AboutDialog
from ..widgets import Card, ToggleSwitch, hline, make_button
from .base import Page, faint, key_value


class _UpdateBridge(QObject):
    done = Signal(object)


class SettingsPage(Page):
    title = "Настройки"
    subtitle = "Поведение сканера, база сигнатур и данные приложения"

    def __init__(self, ctx, parent=None) -> None:
        super().__init__(ctx, parent)
        self.bridge = _UpdateBridge()
        self.bridge.done.connect(self._on_update_result)
        self._build()

    # --- разметка ----------------------------------------------------------
    def _build(self) -> None:
        about_button = make_button("О программе")
        about_button.clicked.connect(lambda: AboutDialog(self.ctx, self).exec())
        self.header_actions.addWidget(about_button)

        layout = self.add_scrollable()

        protection = Card(padding=18, spacing=12)
        protection.add_header("Защита")
        self.realtime = self._toggle_row(
            protection,
            "Защита в реальном времени",
            "Проверять новые файлы в наблюдаемых папках",
            bool(self.ctx.settings.get("realtime", False)),
            self._set_realtime,
        )
        protection.body.addWidget(hline())
        self.auto_quarantine = self._toggle_row(
            protection,
            "Автоматический карантин",
            "Изолировать найденные угрозы сразу после проверки",
            bool(self.ctx.settings.get("quarantine_automatically", False)),
            lambda value: self.ctx.settings.set("quarantine_automatically", value),
        )
        protection.body.addWidget(hline())
        self.notifications = self._toggle_row(
            protection,
            "Уведомления",
            "Показывать всплывающие сообщения о находках",
            bool(self.ctx.settings.get("notify_on_threat", True)),
            lambda value: self.ctx.settings.set("notify_on_threat", value),
        )
        protection.body.addWidget(hline())
        self.deep = self._toggle_row(
            protection,
            "Глубокая эвристика",
            "Разбор PE-заголовков, импортов и упаковщиков (медленнее, но точнее)",
            bool(self.ctx.settings.get("deep_heuristics", True)),
            self._set_deep,
        )
        layout.addWidget(protection)

        performance = Card(padding=18, spacing=12)
        performance.add_header("Производительность")
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        text = QVBoxLayout()
        text.setSpacing(2)
        title = QLabel("Потоков сканирования")
        title.setObjectName("CardTitle")
        text.addWidget(title)
        text.addWidget(faint("Больше потоков — быстрее проверка диска, но выше нагрузка"))
        row_layout.addLayout(text, 1)
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 16)
        self.workers_spin.setValue(int(self.ctx.settings.get("workers", 4)))
        self.workers_spin.valueChanged.connect(self._set_workers)
        row_layout.addWidget(self.workers_spin)
        performance.body.addWidget(row)
        performance.body.addWidget(hline())
        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(1, 4096)
        self.max_size_spin.setSuffix(" МБ")
        self.max_size_spin.setValue(int(self.ctx.settings.get("scan_max_size_mb", 256)))
        self.max_size_spin.valueChanged.connect(self._set_max_size)
        size_row = QWidget()
        size_layout = QHBoxLayout(size_row)
        size_layout.setContentsMargins(0, 0, 0, 0)
        size_text = QVBoxLayout()
        size_text.setSpacing(2)
        size_title = QLabel("Максимальный размер файла")
        size_title.setObjectName("CardTitle")
        size_text.addWidget(size_title)
        size_text.addWidget(faint("Файлы больше лимита проверяются только по хешу"))
        size_layout.addLayout(size_text, 1)
        size_layout.addWidget(self.max_size_spin)
        performance.body.addWidget(size_row)
        layout.addWidget(performance)

        signatures = Card(padding=18, spacing=12)
        signatures.add_header("База сигнатур", "обновление по HTTPS")
        self.db_version_label = QLabel()
        self.db_version_label.setObjectName("Muted")
        signatures.body.addWidget(self.db_version_label)
        url_row = QWidget()
        url_layout = QHBoxLayout(url_row)
        url_layout.setContentsMargins(0, 0, 0, 0)
        url_layout.setSpacing(8)
        self.url_edit = QLineEdit(str(self.ctx.settings.get("signature_url", "")))
        self.url_edit.setPlaceholderText("https://…/signatures.json")
        url_layout.addWidget(self.url_edit, 1)
        save_url = make_button("Сохранить адрес")
        save_url.clicked.connect(self._save_url)
        url_layout.addWidget(save_url)
        signatures.body.addWidget(url_row)
        actions = QHBoxLayout()
        self.update_button = make_button("Проверить обновления", "Primary")
        self.update_button.clicked.connect(self._check_updates)
        actions.addWidget(self.update_button)
        self.update_status = QLabel("")
        self.update_status.setObjectName("Faint")
        self.update_status.setWordWrap(True)
        actions.addWidget(self.update_status, 1)
        signatures.body.addLayout(actions)
        self.auto_update = self._toggle_row(
            signatures,
            "Автоматически проверять при запуске",
            "Тихо обновлять базу, если доступна новая версия",
            bool(self.ctx.settings.get("auto_update", True)),
            lambda value: self.ctx.settings.set("auto_update", value),
        )
        layout.addWidget(signatures)

        data_card = Card(padding=18, spacing=10)
        data_card.add_header("Данные приложения")
        data_card.body.addWidget(key_value("Каталог данных", str(app_data_dir())))
        data_card.body.addWidget(key_value("Карантин", str(self.ctx.quarantine.folder)))
        data_card.body.addWidget(key_value("Журнал", str(self.ctx.history.path)))
        row_buttons = QHBoxLayout()
        open_folder = make_button("Открыть каталог")
        open_folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(app_data_dir()))))
        clear_history = make_button("Очистить журнал", "Danger")
        clear_history.clicked.connect(self._clear_history)
        row_buttons.addWidget(open_folder)
        row_buttons.addWidget(clear_history)
        row_buttons.addStretch(1)
        data_card.body.addLayout(row_buttons)
        layout.addWidget(data_card)
        layout.addStretch(1)

        self._refresh_versions()

    def _toggle_row(self, card: Card, title: str, caption: str, value: bool, on_change) -> ToggleSwitch:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        text = QVBoxLayout()
        text.setSpacing(2)
        title_label = QLabel(title)
        title_label.setObjectName("CardTitle")
        text.addWidget(title_label)
        text.addWidget(faint(caption))
        layout.addLayout(text, 1)
        toggle = ToggleSwitch()
        toggle.setChecked(value)
        toggle.toggled.connect(on_change)
        layout.addWidget(toggle)
        card.body.addWidget(row)
        return toggle

    # --- обработчики -------------------------------------------------------
    def _set_realtime(self, value: bool) -> None:
        self.ctx.settings.set("realtime", value)
        if self.ctx.monitor_page is not None:
            self.ctx.monitor_page.set_running(value, silent=True)

    def _set_deep(self, value: bool) -> None:
        self.ctx.settings.set("deep_heuristics", value)
        self.ctx.engine.settings.deep = value

    def _set_workers(self, value: int) -> None:
        self.ctx.settings.set("workers", value)
        self.ctx.engine.settings.workers = value

    def _set_max_size(self, value: int) -> None:
        self.ctx.settings.set("scan_max_size_mb", value)
        self.ctx.engine.settings.max_file_size = value * 1024 * 1024

    def _save_url(self) -> None:
        self.ctx.settings.set("signature_url", self.url_edit.text().strip())
        self.ctx.signals.toast.emit("Адрес обновления сохранён", theme.OK)

    def _check_updates(self) -> None:
        url = self.url_edit.text().strip()
        if not url:
            self.ctx.signals.toast.emit("Укажите адрес базы сигнатур", theme.WARN)
            return
        self.update_button.setEnabled(False)
        self.update_status.setText("Загрузка базы…")
        updater.update_async(url, self.bridge.done.emit)

    def _on_update_result(self, result) -> None:
        self.update_button.setEnabled(True)
        if result.ok:
            self.ctx.engine.db = updater.load_database()
            self.update_status.setText(f"Обновлено до версии {result.version} · правил {result.rules}")
            self.ctx.signals.toast.emit("База сигнатур обновлена", theme.OK)
            self._refresh_versions()
            self.ctx.signals.settings_changed.emit()
        else:
            self.update_status.setText(result.message)
            self.ctx.signals.toast.emit(result.message, theme.DANGER)

    def _refresh_versions(self) -> None:
        db = self.ctx.engine.db
        bundled = updater.bundled_version()
        self.db_version_label.setText(
            f"Активная база: версия {db.version} · {db.total} правил. Встроенная: {bundled}."
        )

    def _clear_history(self) -> None:
        self.ctx.history.clear()
        self.ctx.signals.toast.emit("Журнал очищен", theme.OK)

    def on_show(self) -> None:
        self.realtime.setChecked(bool(self.ctx.settings.get("realtime", False)))
        self._refresh_versions()
