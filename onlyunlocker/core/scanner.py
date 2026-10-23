"""Движок сканирования: обход файловой системы, быстрая проверка, отчёты."""
from __future__ import annotations

import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator

from . import heuristics
from .heuristics import EXECUTABLE_SUFFIXES, SCRIPT_SUFFIXES, ScanContext
from .models import FileReport, ScanSummary, Verdict, MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD
from .pe import analyze as analyze_pe
from .signatures import SignatureDatabase
from .utils import entropy, is_probably_text, sha256_file

ProgressCallback = Callable[[FileReport, ScanSummary], None]

# расширения, которые вообще имеют смысл проверять
SCAN_EXTENSIONS = EXECUTABLE_SUFFIXES | SCRIPT_SUFFIXES | {
    ".zip", ".rar", ".7z", ".iso", ".img", ".doc", ".docm", ".xls", ".xlsm",
    ".ppt", ".pptm", ".js", ".json", ".xml", ".html", ".htm", ".php", ".txt",
}
# мусор, который только замедляет скан
SKIP_EXTENSIONS = {
    ".log", ".tmp", ".bak", ".sys", ".ttf", ".otf", ".woff", ".woff2", ".db",
    ".sqlite", ".pak", ".bin", ".dat", ".idx", ".pyc", ".pyd", ".so", ".dylib",
}
if sys.platform == "win32":
    SKIP_EXTENSIONS.discard(".sys")
    SKIP_EXTENSIONS.discard(".pyd")
JUNK_DIRS = {
    "$recycle.bin", "system volume information", "node_modules", ".git", "__pycache__",
    ".cache", "winsxs", "installer", "assembly", ".venv", "site-packages", ".npm",
    "temp", "tmp", "logs", ".gradle", ".m2", "dist-packages", "vendor",
}


@dataclass
class ScanSettings:
    max_file_size: int = 256 * 1024 * 1024  # больше — только хеш
    read_limit: int = 8 * 1024 * 1024       # сколько читаем в память для анализа
    follow_symlinks: bool = False
    deep: bool = True                        # False — быстрый режим (только хеш/паттерны)
    workers: int = 4
    exclusions: list[str] = field(default_factory=list)


def default_targets(mode: str = "quick") -> list[str]:
    home = Path.home()
    if sys.platform == "win32":
        windir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        user = Path(os.environ.get("USERPROFILE", home))
        common = [
            user / "Downloads",
            user / "Desktop",
            user / "Documents",
            Path(os.environ.get("TEMP", str(user / "AppData" / "Local" / "Temp"))),
            user / "AppData" / "Roaming",
            user / "AppData" / "Local" / "Temp",
            windir / "Temp",
        ]
        quick = common[:4]
        if mode == "full":
            return [str(user)] + [str(windir / "Temp")]
        if mode == "system":
            return [str(windir / "System32"), str(windir / "SysWOW64")]
        return [str(p) for p in quick if p.exists()]
    else:
        common = [home / "Downloads", home / "Desktop", home / "Documents", Path("/tmp"), Path("/var/tmp")]
        if mode == "full":
            return [str(home)]
        if mode == "system":
            return ["/etc", "/usr/local/bin", "/opt"]
        return [str(p) for p in common if p.exists()]


class ScanEngine:
    """Потокобезопасный движок: база сигнатур только читается."""

    def __init__(self, db: SignatureDatabase | None = None, settings: ScanSettings | None = None) -> None:
        self.db = db or SignatureDatabase.load()
        self.settings = settings or ScanSettings()

    # --- один файл ---------------------------------------------------------
    def scan_file(self, path: str) -> FileReport:
        started = time.perf_counter()
        report = FileReport(path=path)
        try:
            st = os.stat(path)
            report.size = st.st_size
            report.modified = st.st_mtime
        except OSError as exc:
            report.verdict = Verdict.ERROR
            report.error = str(exc)
            return report

        try:
            report.sha256 = sha256_file(path)
        except (OSError, PermissionError) as exc:
            report.verdict = Verdict.ERROR
            report.error = str(exc)
            return report

        try:
            with open(path, "rb") as fh:
                data = fh.read(self.settings.read_limit)
        except (OSError, PermissionError) as exc:
            report.verdict = Verdict.ERROR
            report.error = str(exc)
            return report

        suffix = Path(path).suffix.lower()
        head = data[:65536]
        file_entropy = entropy(data[: 1024 * 1024])

        pe_info = None
        if len(data) >= 64 and data[:2] == b"MZ" and self.settings.deep:
            pe_info = analyze_pe(data, report.size)

        ctx = ScanContext(
            path=path,
            size=report.size,
            data=data,
            head=head,
            sha256=report.sha256,
            suffix=suffix,
            db=self.db,
            pe=pe_info,
            is_text=is_probably_text(data),
            file_entropy=file_entropy,
        )
        if pe_info and pe_info.is_pe:
            report.meta = {
                "format": "PE",
                "architecture": pe_info.machine,
                "subsystem": pe_info.subsystem,
                "compile_time": pe_info.compile_time,
                "sections": len(pe_info.sections),
                "packer": pe_info.packer or "нет",
                "signed": pe_info.has_signature,
                "dotnet": pe_info.is_dotnet,
                "imports": len(pe_info.imports),
                "overlay": pe_info.overlay_size,
            }
        elif suffix:
            report.meta = {"format": suffix.lstrip(".").upper() or "—"}

        detections = heuristics.run_all(ctx)
        report.detections = detections
        report.score = min(100, sum(d.score for d in detections))
        if not self.settings.deep:
            # быстрый режим: оставляем только сигнатурные совпадения
            report.detections = [d for d in detections if d.category in ("signature", "pattern")]
            report.score = min(100, sum(d.score for d in report.detections))

        definitive = any(d.category in ("signature", "pattern") or d.severity == "critical" for d in report.detections)
        if report.score >= MALICIOUS_THRESHOLD or definitive:
            report.verdict = Verdict.MALICIOUS
        elif report.score >= SUSPICIOUS_THRESHOLD:
            report.verdict = Verdict.SUSPICIOUS
        report.duration_ms = int((time.perf_counter() - started) * 1000)
        return report

    # --- обход -------------------------------------------------------------
    def iter_candidates(self, targets: Iterable[str]) -> Iterator[str]:
        seen: set[str] = set()
        exclusions = [os.path.normcase(os.path.abspath(p)) for p in self.settings.exclusions]
        for target in targets:
            target = os.path.abspath(os.path.expanduser(target))
            if os.path.isfile(target):
                if target not in seen:
                    seen.add(target)
                    yield target
                continue
            if not os.path.isdir(target):
                continue
            for root, dirs, files in os.walk(target, followlinks=self.settings.follow_symlinks):
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in JUNK_DIRS
                    and not any(os.path.normcase(os.path.join(root, d)).startswith(ex) for ex in exclusions)
                    and not os.path.islink(os.path.join(root, d))
                ]
                for name in files:
                    path = os.path.join(root, name)
                    suffix = os.path.splitext(name)[1].lower()
                    if suffix in SKIP_EXTENSIONS and suffix not in SCRIPT_SUFFIXES:
                        continue
                    if suffix and suffix not in SCAN_EXTENSIONS:
                        continue
                    if not suffix:
                        continue
                    if path in seen:
                        continue
                    seen.add(path)
                    yield path

    # --- пакетный скан -----------------------------------------------------
    def scan(
        self,
        targets: Iterable[str],
        mode: str = "quick",
        progress: ProgressCallback | None = None,
        cancel: threading.Event | None = None,
    ) -> ScanSummary:
        summary = ScanSummary(mode=mode, target=", ".join(targets) if isinstance(targets, (list, tuple)) else str(targets))
        summary.started_at = time.time()
        cancel = cancel or threading.Event()

        candidates = list(self.iter_candidates(targets))
        summary.total_candidates = len(candidates)

        def worker(path: str) -> FileReport:
            if cancel.is_set():
                return FileReport(path=path, verdict=Verdict.SKIPPED)
            try:
                return self.scan_file(path)
            except Exception as exc:  # защита от неожиданностей в разборе
                return FileReport(path=path, verdict=Verdict.ERROR, error=str(exc))

        workers = max(1, min(self.settings.workers, 16))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(worker, path): path for path in candidates}
            for future in as_completed(futures):
                if cancel.is_set():
                    for f in futures:
                        f.cancel()
                    summary.cancelled = True
                    break
                report = future.result()
                if report.verdict == Verdict.SKIPPED:
                    continue
                summary.scanned += 1
                summary.bytes_scanned += report.size
                if report.verdict == Verdict.MALICIOUS:
                    summary.infected += 1
                    summary.reports.append(report)
                elif report.verdict == Verdict.SUSPICIOUS:
                    summary.suspicious += 1
                    summary.reports.append(report)
                elif report.verdict == Verdict.ERROR:
                    summary.errors += 1
                if progress:
                    progress(report, summary)

        summary.finished_at = time.time()
        return summary

    def scan_folder(
        self,
        folder: str,
        progress: ProgressCallback | None = None,
        cancel: threading.Event | None = None,
    ) -> ScanSummary:
        return self.scan([folder], mode="custom", progress=progress, cancel=cancel)
