"""Главное окно: боковая панель, стек страниц, уведомления."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QIcon, QPixmap, QShortcut, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..core.utils import resource_path
from . import theme
from .context import AppContext
from .pages.dashboard import DashboardPage
from .pages.history_page import HistoryPage
from .pages.monitor_page import MonitorPage
from .pages.quarantine_page import QuarantinePage
from .pages.scan import ScanPage
from .pages.settings_page import SettingsPage
from .pages.tools import ToolsPage
from .theme import apply_theme
from .widgets import NavButton, Toast

NAV_ITEMS = [
    ("dashboard", "Защита"),
    ("scan", "Проверка"),
    ("quarantine", "Карантин"),
    ("monitor", "Мониторинг"),
    ("history", "Журнал"),
    ("tools", "Инструменты"),
    ("settings", "Настройки"),
]


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("OnlyUnlocker — антивирус")
        self.resize(1280, 840)
        self.setMinimumSize(1080, 700)
        self._apply_icon()

        self.ctx = AppContext.create()
        self.ctx.navigate = self.navigate

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.buttons: dict[str, NavButton] = {}
        self.pages: dict[str, QWidget] = {}
        layout.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        self._register_pages()
        self.ctx.scan_page = self.pages["scan"]
        self.ctx.monitor_page = self.pages["monitor"]

        self.toast = Toast(root)
        self.ctx.signals.toast.connect(self._show_toast)
        self.ctx.signals.scan_finished.connect(lambda _s: self._refresh_sidebar_status())
        self.ctx.signals.settings_changed.connect(self._refresh_sidebar_status)
        self.ctx.signals.quarantine_changed.connect(self._refresh_sidebar_status)

        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._refresh_sidebar_status)
        self._status_timer.start(4000)

        self.navigate("dashboard")
        self._refresh_sidebar_status()
        self._bind_shortcuts()

        if self.ctx.settings.get("realtime", False):
            QTimer.singleShot(600, lambda: self.pages["monitor"].set_running(True, silent=True))

    @staticmethod
    def _icon_path():
        for name in ("logo.png", "logo.ico", "logo.svg"):
            candidate = resource_path("assets", name)
            if candidate.exists():
                return candidate
        return None

    def _apply_icon(self) -> None:
        path = self._icon_path()
        if path is not None:
            self.setWindowIcon(QIcon(str(path)))

    # --- каркас ------------------------------------------------------------
    def _build_sidebar(self) -> QWidget:
        from .widgets import hline

        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setAttribute(Qt.WA_StyledBackground, True)
        sidebar.setFixedWidth(238)
        sidebar.setStyleSheet(f"background-color: {theme.SIDEBAR}; border-right: 1px solid {theme.BORDER_SOFT};")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 20, 16, 16)
        layout.setSpacing(6)

        brand_row = QHBoxLayout()
        brand_row.setSpacing(10)
        logo = QLabel()
        logo_path = self._icon_path() or Path("")
        if logo_path.exists():
            pixmap = QPixmap(str(logo_path))
            if not pixmap.isNull():
                logo.setPixmap(pixmap.scaled(QSize(34, 34), Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setFixedSize(34, 34)
        brand_row.addWidget(logo)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        brand = QLabel("ONLYUNLOCKER")
        brand.setObjectName("BrandMark")
        brand.setStyleSheet("font-size: 15px; font-weight: 800; letter-spacing: 1.4px;")
        sub = QLabel("SECURITY SUITE")
        sub.setObjectName("BrandSub")
        brand_text.addWidget(brand)
        brand_text.addWidget(sub)
        brand_row.addLayout(brand_text)
        brand_row.addStretch(1)
        layout.addLayout(brand_row)
        layout.addSpacing(18)

        section = QLabel("МЕНЮ")
        section.setObjectName("SidebarSection")
        layout.addWidget(section)
        layout.addSpacing(4)

        for key, title in NAV_ITEMS:
            button = NavButton(title)
            button.clicked.connect(lambda _checked=False, k=key: self.navigate(k))
            layout.addWidget(button)
            self.buttons[key] = button

        layout.addStretch(1)
        layout.addWidget(hline())
        layout.addSpacing(6)

        self.sidebar_status = QLabel("Защита активна")
        self.sidebar_status.setObjectName("Faint")
        self.sidebar_status.setStyleSheet(f"color: {theme.OK}; font-size: 11px;")
        layout.addWidget(self.sidebar_status)

        version = QLabel(f"v{__version__} · база {self.ctx.engine.db.version}")
        version.setObjectName("Faint")
        layout.addWidget(version)
        return sidebar

    def _register_pages(self) -> None:
        pages = {
            "dashboard": DashboardPage(self.ctx),
            "scan": ScanPage(self.ctx),
            "quarantine": QuarantinePage(self.ctx),
            "monitor": MonitorPage(self.ctx),
            "history": HistoryPage(self.ctx),
            "tools": ToolsPage(self.ctx),
            "settings": SettingsPage(self.ctx),
        }
        for key, page in pages.items():
            self.pages[key] = page
            self.stack.addWidget(page)

    def _bind_shortcuts(self) -> None:
        for index, (key, _title) in enumerate(NAV_ITEMS, start=1):
            shortcut = QShortcut(QKeySequence(f"Ctrl+{index}"), self)
            shortcut.activated.connect(lambda k=key: self.navigate(k))

    # --- навигация ---------------------------------------------------------
    def navigate(self, key: str) -> None:
        page = self.pages.get(key)
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        for name, button in self.buttons.items():
            button.setChecked(name == key)
        if hasattr(page, "on_show"):
            page.on_show()

    def _show_toast(self, text: str, color: str) -> None:
        if not self.ctx.settings.get("notify_on_threat", True) and color == theme.DANGER:
            # уведомления отключены — всё равно показываем критичное в статусе
            pass
        self.toast.show_message(text, color)

    def _refresh_sidebar_status(self) -> None:
        stats = self.ctx.history.stats()
        if self.ctx.monitor.running:
            text, color = "Мониторинг включён", theme.OK
        elif stats["infected"]:
            text, color = f"Найдено угроз: {stats['infected']}", theme.DANGER
        else:
            text, color = "Защита активна", theme.OK
        self.sidebar_status.setText(text)
        self.sidebar_status.setStyleSheet(f"color: {color}; font-size: 11px;")

    # --- события окна ------------------------------------------------------
    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        if hasattr(self, "toast") and self.toast.isVisible():
            self.toast._reposition()

    def closeEvent(self, event) -> None:  # noqa: N802
        try:
            self.ctx.monitor.stop()
        except Exception:
            pass
        super().closeEvent(event)


def run() -> int:
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True) if hasattr(Qt, "AA_EnableHighDpiScaling") else None
    app = QApplication(sys.argv)
    app.setApplicationName("OnlyUnlocker")
    app.setOrganizationName("OnlyUnlocker")
    icon_path = MainWindow._icon_path()
    if icon_path is not None:
        app.setWindowIcon(QIcon(str(icon_path)))
    apply_theme(app)

    window = MainWindow()
    window.show()
    return app.exec()
