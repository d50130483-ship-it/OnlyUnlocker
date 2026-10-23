"""Инструменты: обслуживание системы и быстрые проверки в один клик."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QLabel, QVBoxLayout

from ...core import system_tools
from ...core.utils import human_size, is_admin, shorten_path
from .. import theme
from ..dialogs import ConfirmDialog, PathScanDialog, TableDialog, TerminalDialog
from ..widgets import Card, TileButton, hline
from .base import Page, faint

IS_WINDOWS = sys.platform == "win32"


class ToolsPage(Page):
    title = "Инструменты"
    subtitle = "Обслуживание системы и проверки без лишних кликов"

    def __init__(self, ctx, parent=None) -> None:
        super().__init__(ctx, parent)
        self._build()

    # --- разметка ----------------------------------------------------------
    def _build(self) -> None:
        admin_badge = QLabel("АДМИНИСТРАТОР" if is_admin() else "БЕЗ ПРАВ АДМИНИСТРАТОРА")
        admin_color = theme.OK if is_admin() else theme.WARN
        admin_badge.setStyleSheet(
            f"color: {admin_color}; border: 1px solid {theme.rgba(admin_color, 0.42)};"
            " border-radius: 9px; padding: 3px 9px; font-size: 11px;"
        )
        self.header_actions.addWidget(admin_badge)

        targets = self.add_scrollable()

        maintenance = Card(padding=18, spacing=10)
        maintenance.add_header("Обслуживание", "Windows")
        grid = QVBoxLayout()
        grid.setSpacing(8)
        grid.addLayout(
            self._grid(
                [
                    ("sfc /scannow", self._sfc, "Проверка и восстановление системных файлов", True),
                    ("DISM RestoreHealth", self._dism, "Восстановление образа системы", True),
                    ("Сброс Windows Update", self._reset_wu, "Перезапуск служб и очистка кеша обновлений", True),
                    ("Сброс сети", self._reset_network, "Сброс DNS-кеша и адаптера", True),
                    ("chkdsk C: /scan", self._chkdsk, "Онлайн-проверка диска без перезагрузки", True),
                    ("Очистка Temp", self._clean_temp, "Удаление временных файлов пользователя", False),
                ]
            )
        )
        maintenance.body.addLayout(grid)
        targets.addWidget(maintenance)

        tools_card = Card(padding=18, spacing=10)
        tools_card.add_header("Настройки системы", "Windows")
        tools_card.body.addLayout(
            self._grid(
                [
                    ("Гибернация ВЫКЛ", self._disable_hibernate, "powercfg /h off — экономит место на диске", True),
                    ("Сброс кеша иконок", self._icon_cache, "Перестроение кеша значков проводника", True),
                    ("Включить UAC", self._enable_uac, "Включает контроль учётных записей", True),
                    ("Отключить тестовый режим", self._disable_testsigning, "bcdedit /set testsigning off", True),
                    ("Активация Windows", self._activation, "Открывает официальный раздел настроек", True),
                    ("Перезагрузка", self._reboot, "Обычная перезагрузка компьютера", True),
                ]
            )
        )
        tools_card.body.addWidget(hline())
        tools_card.body.addWidget(
            faint("Команды запускаются от имени текущего пользователя. Для части операций нужны права администратора.")
        )
        targets.addWidget(tools_card)

        diag = Card(padding=18, spacing=10)
        diag.add_header("Диагностика", "работает на всех платформах")
        diag.body.addLayout(
            self._grid(
                [
                    ("Информация о системе", self._system_info, "ОС, процессор, версия Python", False),
                    ("Процессы", self._processes, "Запущенные процессы и их файлы", False),
                    ("Автозагрузка", self._autoruns, "Точки автозапуска Windows и Linux", False),
                    ("Диски", self._disks, "Занятое и свободное место", False),
                    ("Пользователи", self._users, "Текущая учётная запись и права", False),
                ]
            )
        )
        diag.body.addWidget(hline())
        quick_row = self._grid(
            [
                ("Проверить процессы", self._scan_processes, "Просканировать файлы запущенных процессов", False),
                ("Проверить автозагрузку", self._scan_autoruns, "Проверить программы из автозапуска", False),
                ("Перезагрузка в WinRE", self._reboot_recovery, "Загрузка в среду восстановления", True),
            ]
        )
        diag.body.addLayout(quick_row)
        targets.addWidget(diag)
        targets.addStretch(1)

    def _grid(self, items) -> "QVBoxLayout":
        from PySide6.QtWidgets import QHBoxLayout

        outer = QVBoxLayout()
        outer.setSpacing(8)
        row: QHBoxLayout | None = None
        for index, (label, slot, description, windows_only) in enumerate(items):
            if index % 2 == 0:
                row = QHBoxLayout()
                row.setSpacing(8)
                outer.addLayout(row)
            button = TileButton(label, description)
            button.clicked.connect(lambda _checked=False, s=slot: s())
            if windows_only and not IS_WINDOWS:
                button.setEnabled(False)
                button.setToolTip("Доступно только в Windows")
            row.addWidget(button)
        return outer

    # --- Windows: обслуживание --------------------------------------------
    def _run(self, title: str, subtitle: str, program: str, arguments: list[str], warning: str = "") -> None:
        TerminalDialog(title, subtitle, program, arguments, warning, self).exec()

    def _run_cmd(self, title: str, subtitle: str, command: str, warning: str = "") -> None:
        self._run(title, subtitle, "cmd.exe", ["/c", command], warning)

    def _sfc(self) -> None:
        self._run(
            "Проверка системных файлов",
            "sfc /scannow проверяет целостность системных файлов Windows.",
            "sfc.exe",
            ["/scannow"],
            "Операция может занять 10–20 минут и требует прав администратора.",
        )

    def _dism(self) -> None:
        self._run(
            "Восстановление образа системы",
            "DISM /Online /Cleanup-Image /RestoreHealth исправляет повреждения компонентов.",
            "dism.exe",
            ["/Online", "/Cleanup-Image", "/RestoreHealth"],
            "Требуется подключение к интернету и права администратора.",
        )

    def _reset_wu(self) -> None:
        self._run_cmd(
            "Сброс Windows Update",
            "Остановка служб, переименование кеша и повторный запуск.",
            "net stop wuauserv & net stop bits & ren %systemroot%\\SoftwareDistribution SoftwareDistribution.old & net start wuauserv & net start bits",
            "Требуются права администратора. Обновления будут скачаны заново.",
        )

    def _reset_network(self) -> None:
        self._run_cmd(
            "Сброс сети",
            "ipconfig /flushdns, release и renew для всех адаптеров.",
            "ipconfig /flushdns & ipconfig /release & ipconfig /renew",
            "Соединение может прерваться на несколько секунд.",
        )

    def _chkdsk(self) -> None:
        self._run(
            "Проверка диска",
            "chkdsk C: /scan — онлайн-проверка без блокировки тома.",
            "chkdsk.exe",
            ["C:", "/scan"],
            "Требуются права администратора.",
        )

    def _clean_temp(self) -> None:
        folders = {tempfile.gettempdir()}
        if IS_WINDOWS:
            folders.add(os.environ.get("TEMP", ""))
            folders.add(os.environ.get("TMP", ""))
            folders.add(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"))
        folders = {f for f in folders if f and os.path.isdir(f)}
        dialog = ConfirmDialog(
            "Очистка временных файлов",
            "Будут удалены файлы из папок:\n" + "\n".join(shorten_path(f, 70) for f in folders) +
            "\n\nЗакрытые приложения не пострадают, но незавершённые загрузки могут пропасть.",
            "Очистить",
            danger=True,
            parent=self,
        )
        if dialog.exec() != dialog.Accepted:
            return
        freed = 0
        removed = 0
        for folder in folders:
            for root, dirs, files in os.walk(folder):
                for name in files:
                    path = os.path.join(root, name)
                    try:
                        size = os.path.getsize(path)
                        os.remove(path)
                        freed += size
                        removed += 1
                    except OSError:
                        continue
                if os.path.normcase(root) != os.path.normcase(folder):
                    for name in dirs:
                        try:
                            os.rmdir(os.path.join(root, name))
                        except OSError:
                            pass
        self.ctx.signals.toast.emit(
            f"Удалено файлов: {removed}, освобождено {human_size(freed)}", theme.OK
        )

    # --- Windows: настройки ------------------------------------------------
    def _disable_hibernate(self) -> None:
        self._run(
            "Отключение гибернации",
            "powercfg /h off удаляет файл hiberfil.sys и освобождает место.",
            "powercfg.exe",
            ["/h", "off"],
            "Требуются права администратора. Быстрый запуск Windows тоже отключится.",
        )

    def _icon_cache(self) -> None:
        self._run_cmd(
            "Сброс кеша иконок",
            "Перестроение кеша значков проводника.",
            "ie4uinit.exe -show & taskkill /f /im explorer.exe & start explorer.exe",
            "Проводник будет перезапущен: открытые окна закроются.",
        )

    def _enable_uac(self) -> None:
        self._run(
            "Включение UAC",
            "Устанавливает EnableLUA=1 в реестре.",
            "reg.exe",
            ["add", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "1", "/f"],
            "Изменение вступит в силу после перезагрузки. Требуются права администратора.",
        )

    def _disable_testsigning(self) -> None:
        self._run(
            "Отключение тестового режима",
            "bcdedit /set testsigning off убирает надпись на рабочем столе.",
            "bcdedit.exe",
            ["/set", "testsigning", "off"],
            "Требуются права администратора и перезагрузка.",
        )

    def _activation(self) -> None:
        QDesktopServices.openUrl(QUrl("ms-settings:activation"))

    def _reboot(self) -> None:
        dialog = ConfirmDialog(
            "Перезагрузка компьютера",
            "Система будет перезагружена немедленно. Сохраните открытые документы.",
            "Перезагрузить",
            danger=True,
            parent=self,
        )
        if dialog.exec() == dialog.Accepted:
            self._run("Перезагрузка", "shutdown /r /t 5", "shutdown.exe", ["/r", "/t", "5"])

    def _reboot_recovery(self) -> None:
        dialog = ConfirmDialog(
            "Загрузка в WinRE",
            "Компьютер перезагрузится в среду восстановления Windows. Продолжить?",
            "Перезагрузить в WinRE",
            danger=True,
            parent=self,
        )
        if dialog.exec() == dialog.Accepted:
            self._run("Перезагрузка в WinRE", "shutdown /r /o", "shutdown.exe", ["/r", "/o", "/t", "5"])

    # --- диагностика -------------------------------------------------------
    def _system_info(self) -> None:
        summary = system_tools.system_summary()
        db = self.ctx.engine.db
        rows = [[key, value] for key, value in summary.items()]
        rows += [
            ["Права администратора", "да" if is_admin() else "нет"],
            ["База сигнатур", f"{db.version} · правил {db.total}"],
            ["Карантин", f"{self.ctx.quarantine.count} файл(ов)"],
        ]
        TableDialog("Информация о системе", "Данные текущей среды", ["Параметр", "Значение"], rows, self).exec()

    def _processes(self) -> None:
        processes = system_tools.list_processes()
        rows = [[str(p.pid), p.name, p.memory_str, p.path or "—"] for p in processes]
        TableDialog(
            "Процессы",
            f"Всего процессов: {len(processes)}",
            ["PID", "Имя", "Память", "Файл"],
            rows,
            self,
        ).exec()

    def _autoruns(self) -> None:
        entries = system_tools.list_autoruns()
        rows = [[e.location, e.name, e.command] for e in entries]
        TableDialog(
            "Автозагрузка",
            f"Найдено записей: {len(entries)}",
            ["Расположение", "Имя", "Команда"],
            rows,
            self,
        ).exec()

    def _disks(self) -> None:
        disks = system_tools.list_disks()
        rows = [
            [d.mount, human_size(d.total), human_size(d.used), human_size(d.free), f"{d.percent:.0f}%"]
            for d in disks
        ]
        TableDialog(
            "Диски",
            "Занятое и свободное пространство",
            ["Том", "Всего", "Занято", "Свободно", "Заполнение"],
            rows,
            self,
        ).exec()

    def _users(self) -> None:
        users = system_tools.list_users()
        rows = [[u.name, "администратор" if u.admin else "пользователь", u.home] for u in users]
        TableDialog("Пользователи", "Текущая учётная запись", ["Имя", "Уровень", "Домашний каталог"], rows, self).exec()

    # --- проверки ----------------------------------------------------------
    def _scan_processes(self) -> None:
        paths = sorted({p.path for p in system_tools.list_processes() if p.path and os.path.isfile(p.path)})
        if not paths:
            self.ctx.signals.toast.emit("Не удалось получить пути процессов", theme.WARN)
            return
        PathScanDialog(self.ctx.engine, paths, "Проверка файлов процессов", self).exec()

    def _scan_autoruns(self) -> None:
        paths: list[str] = []
        for entry in system_tools.list_autoruns():
            command = entry.command.strip().strip('"')
            if not command:
                continue
            first = command.split('"')[1] if command.startswith('"') and '"' in command[1:] else command.split(" ")[0]
            candidate = Path(os.path.expandvars(first))
            if candidate.is_file():
                paths.append(str(candidate))
        paths = sorted(set(paths))
        if not paths:
            self.ctx.signals.toast.emit("Исполняемые файлы автозагрузки не найдены", theme.WARN)
            return
        PathScanDialog(self.ctx.engine, paths, "Проверка автозагрузки", self).exec()
