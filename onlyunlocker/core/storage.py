"""Настройки и журнал проверок (JSON + JSONL)."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from .models import ScanSummary
from .utils import app_data_dir

DEFAULTS: dict[str, Any] = {
    "theme": "dark",
    "realtime": False,
    "quarantine_automatically": False,
    "notify_on_threat": True,
    "workers": 4,
    "scan_archives": True,
    "scan_max_size_mb": 256,
    "deep_heuristics": True,
    "watched_dirs": [],
    "signature_url": "https://raw.githubusercontent.com/d50130483-ship-it/OnlyUnlocker/main/onlyunlocker/data/signatures.json",
    "auto_update": True,
    "last_quick_scan": 0.0,
    "last_full_scan": 0.0,
}


class Settings:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (app_data_dir() / "settings.json")
        self._lock = threading.Lock()
        self._data = dict(DEFAULTS)
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if isinstance(raw, dict):
            for key, value in raw.items():
                if key in DEFAULTS:
                    self._data[key] = value

    def save(self) -> None:
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, DEFAULTS.get(key, default))

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        self.save()

    def as_dict(self) -> dict[str, Any]:
        return dict(self._data)


class History:
    """Журнал завершённых проверок — одна JSON-строка на скан."""

    def __init__(self, path: Path | None = None, limit: int = 500) -> None:
        self.path = path or (app_data_dir() / "history.jsonl")
        self.limit = limit
        self._lock = threading.Lock()

    def add(self, summary: ScanSummary) -> None:
        payload = summary.to_dict()
        payload["finished_at"] = payload["finished_at"] or time.time()
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
                self._trim()
            except OSError:
                pass

    def _trim(self) -> None:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        if len(lines) <= self.limit:
            return
        self.path.write_text("\n".join(lines[-self.limit :]) + "\n", encoding="utf-8")

    def entries(self) -> list[dict[str, Any]]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        result: list[dict[str, Any]] = []
        for line in lines:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return list(reversed(result))

    def stats(self) -> dict[str, Any]:
        entries = self.entries()
        infected = sum(int(e.get("infected", 0)) for e in entries)
        suspicious = sum(int(e.get("suspicious", 0)) for e in entries)
        scanned = sum(int(e.get("scanned", 0)) for e in entries)
        return {
            "scans": len(entries),
            "infected": infected,
            "suspicious": suspicious,
            "scanned": scanned,
            "last": entries[0] if entries else None,
        }

    def clear(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass
