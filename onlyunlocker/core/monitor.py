"""Мониторинг в реальном времени: следит за папками и проверяет новые файлы.

Реализовано на опросе (без внешних зависимостей), поэтому одинаково
работает на Windows, Linux и macOS.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from .models import FileReport, Verdict
from .scanner import ScanEngine

ThreatCallback = Callable[[FileReport], None]


@dataclass
class MonitorStats:
    started_at: float = field(default_factory=time.time)
    checked: int = 0
    threats: int = 0
    errors: int = 0

    @property
    def uptime(self) -> float:
        return max(0.0, time.time() - self.started_at)


def default_watch_dirs() -> list[str]:
    home = Path.home()
    candidates = [home / "Downloads", home / "Desktop", Path(os.environ.get("TEMP", "/tmp"))]
    return [str(p) for p in candidates if p.exists()]


class RealTimeMonitor:
    """Фоновый поток. Колбэк вызывается из потока монитора."""

    def __init__(
        self,
        engine: ScanEngine,
        directories: Iterable[str] | None = None,
        interval: float = 3.0,
    ) -> None:
        self.engine = engine
        self.directories = list(directories or default_watch_dirs())
        self.interval = interval
        self.stats = MonitorStats()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._known: dict[str, tuple[int, int]] = {}
        self._listeners: list[ThreatCallback] = []

    # --- управление --------------------------------------------------------
    def on_threat(self, callback: ThreatCallback) -> None:
        self._listeners.append(callback)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._prime()
        self._thread = threading.Thread(target=self._loop, name="ou-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None

    # --- внутреннее --------------------------------------------------------
    def _iter_files(self):
        for folder in self.directories:
            if not os.path.isdir(folder):
                continue
            for root, dirs, files in os.walk(folder):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for name in files:
                    path = os.path.join(root, name)
                    try:
                        st = os.stat(path)
                    except OSError:
                        continue
                    yield path, (st.st_mtime_ns, st.st_size)

    def _prime(self) -> None:
        self._known = dict(self._iter_files())

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self._tick()
            except Exception:
                self.stats.errors += 1

    def _tick(self) -> None:
        for path, signature in self._iter_files():
            if self._stop.is_set():
                return
            previous = self._known.get(path)
            self._known[path] = signature
            if previous == signature:
                continue  # старый файл
            suffix = Path(path).suffix.lower()
            if suffix not in {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".sys", ".com", ".pif", ".lnk"}:
                continue
            report = self.engine.scan_file(path)
            self.stats.checked += 1
            if report.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
                self.stats.threats += 1
                for listener in self._listeners:
                    try:
                        listener(report)
                    except Exception:
                        pass
