"""Фоновые задачи Qt: сканирование, обновление базы, системные команды."""
from __future__ import annotations

import threading
import time

from PySide6.QtCore import QObject, QProcess, QThread, Signal

from ..core.models import FileReport, ScanSummary
from ..core.scanner import ScanEngine


class ScanWorker(QThread):
    progress = Signal(dict)
    finished_scan = Signal(object)
    failed = Signal(str)

    def __init__(self, engine: ScanEngine, targets: list[str], mode: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.engine = engine
        self.targets = targets
        self.mode = mode
        self.cancel_event = threading.Event()
        self._last_emit = 0.0

    def cancel(self) -> None:
        self.cancel_event.set()

    def _on_progress(self, report: FileReport, summary: ScanSummary) -> None:
        now = time.monotonic()
        threat = report.verdict.value in ("malicious", "suspicious")
        if not threat and now - self._last_emit < 0.08:
            return
        self._last_emit = now
        self.progress.emit(
            {
                "report": report,
                "scanned": summary.scanned,
                "infected": summary.infected,
                "suspicious": summary.suspicious,
                "errors": summary.errors,
                "total": summary.total_candidates,
                "elapsed": summary.elapsed,
                "bytes": summary.bytes_scanned,
            }
        )

    def run(self) -> None:  # noqa: D401 - Qt API
        try:
            summary = self.engine.scan(self.targets, self.mode, self._on_progress, self.cancel_event)
        except Exception as exc:  # pragma: no cover - защитный код
            self.failed.emit(str(exc))
            return
        self.finished_scan.emit(summary)


class ProcessRunner(QObject):
    """Запуск системной команды с потоковым выводом (без shell-инъекций)."""

    line = Signal(str)
    done = Signal(int)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.process: QProcess | None = None

    def running(self) -> bool:
        return self.process is not None and self.process.state() != QProcess.NotRunning

    def start(self, program: str, arguments: list[str]) -> None:
        if self.running():
            return
        process = QProcess(self)
        process.setProgram(program)
        process.setArguments(arguments)
        process.setProcessChannelMode(QProcess.MergedChannels)
        process.readyReadStandardOutput.connect(self._read)
        process.finished.connect(self._finished)
        process.errorOccurred.connect(lambda _err: self.line.emit("Не удалось запустить процесс."))
        self.process = process
        self.line.emit("$ " + " ".join([program, *arguments]))
        process.start()

    def _read(self) -> None:
        if not self.process:
            return
        chunk = bytes(self.process.readAllStandardOutput()).decode("utf-8", "replace")
        for line in chunk.splitlines():
            if line.strip():
                self.line.emit(line)

    def _finished(self, code: int, _status) -> None:
        self.done.emit(code)

    def stop(self) -> None:
        if self.process and self.running():
            self.process.kill()
