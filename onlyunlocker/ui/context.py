"""Общий контекст приложения: сервисы, настройки, база."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from PySide6.QtCore import QObject, Signal

from ..core.monitor import RealTimeMonitor
from ..core.quarantine import Quarantine
from ..core.scanner import ScanEngine, ScanSettings
from ..core.storage import History, Settings
from ..core.updater import load_database


class Signals(QObject):
    """Единая шина событий между страницами."""

    scan_started = Signal(str)
    scan_finished = Signal(object)
    quarantine_changed = Signal()
    settings_changed = Signal()
    toast = Signal(str, str)
    open_path = Signal(str)


@dataclass
class AppContext:
    settings: Settings
    history: History
    quarantine: Quarantine
    engine: ScanEngine
    monitor: RealTimeMonitor
    signals: Signals = field(default_factory=Signals)
    navigate: Callable[[str], None] = lambda name: None

    @classmethod
    def create(cls) -> "AppContext":
        settings = Settings()
        db = load_database()
        engine = ScanEngine(
            db,
            ScanSettings(
                workers=int(settings.get("workers", 4)),
                deep=bool(settings.get("deep_heuristics", True)),
                max_file_size=int(settings.get("scan_max_size_mb", 256)) * 1024 * 1024,
            ),
        )
        quarantine = Quarantine()
        history = History()
        monitor = RealTimeMonitor(engine)
        return cls(settings=settings, history=history, quarantine=quarantine, engine=engine, monitor=monitor)
