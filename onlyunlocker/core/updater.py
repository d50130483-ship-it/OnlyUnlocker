"""Обновление базы сигнатур из сети (GitHub raw / любой HTTP)."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .signatures import SignatureDatabase
from .utils import app_data_dir, resource_path

USER_DB = "signatures.json"


def user_db_path() -> Path:
    return app_data_dir() / USER_DB


def load_database() -> SignatureDatabase:
    """Пользовательская база (если обновлялась) важнее встроенной."""
    db = SignatureDatabase.load(user_db_path())
    if db.total == 0:
        db = SignatureDatabase.load(resource_path("onlyunlocker", "data", USER_DB))
    return db


def bundled_version() -> str:
    return SignatureDatabase.load(resource_path("onlyunlocker", "data", USER_DB)).version


@dataclass
class UpdateResult:
    ok: bool
    message: str
    version: str = ""
    rules: int = 0


def _download(url: str, timeout: float = 15.0) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "OnlyUnlocker/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL из настроек
        raw = response.read(8 * 1024 * 1024)
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Ожидался JSON-объект")
    return data


def _validate(data: dict) -> None:
    if "version" not in data:
        raise ValueError("В базе нет поля version")
    for key in ("hashes", "patterns", "rules"):
        if key in data and not isinstance(data[key], list):
            raise ValueError(f"Поле {key} должно быть списком")
    if not any(data.get(key) for key in ("hashes", "patterns", "rules")):
        raise ValueError("База пустая")


def update_from_url(url: str) -> UpdateResult:
    """Синхронное обновление. Вызывать из рабочего потока."""
    if not url:
        return UpdateResult(False, "Не задан адрес обновления")
    try:
        data = _download(url)
        _validate(data)
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return UpdateResult(False, f"Не удалось обновить: {exc}")

    target = user_db_path()
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(target)

    db = SignatureDatabase.load(target)
    if db.total == 0:
        return UpdateResult(False, "Загруженная база не содержит правил")
    return UpdateResult(True, "База обновлена", db.version, db.total)


def update_async(url: str, callback) -> None:
    """Колбэк вызывается из фонового потока."""

    def worker() -> None:
        callback(update_from_url(url))

    threading.Thread(target=worker, name="ou-update", daemon=True).start()
