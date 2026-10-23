"""Общие утилиты: хеши, размеры, энтропия, безопасное чтение файлов."""
from __future__ import annotations

import hashlib
import math
import os
import sys
from collections import Counter
from pathlib import Path

CHUNK = 1024 * 256


def sha256_file(path: str | os.PathLike[str], limit: int | None = None) -> str:
    """SHA-256 файла. limit — прочитать только первые N байт."""
    h = hashlib.sha256()
    read = 0
    with open(path, "rb") as fh:
        while True:
            if limit is not None:
                left = limit - read
                if left <= 0:
                    break
                chunk = fh.read(min(CHUNK, left))
            else:
                chunk = fh.read(CHUNK)
            if not chunk:
                break
            read += len(chunk)
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    """Шенноновская энтропия в битах на байт (0..8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for count in counts.values():
        p = count / total
        ent -= p * math.log2(p)
    return round(ent, 3)


def human_size(num: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(num) < 1024.0 or unit == "ТБ":
            if unit == "Б":
                return f"{int(num)} {unit}"
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} ТБ"


def human_time(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} с"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} мин {sec:02d} с"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} ч {minutes:02d} мин"


def shorten_path(path: str, max_len: int = 64) -> str:
    if len(path) <= max_len:
        return path
    keep = max_len - 3
    head = keep // 3
    tail = keep - head
    return path[:head] + "..." + path[-tail:]


def safe_read(path: str | os.PathLike[str], limit: int) -> bytes:
    """Читает не больше limit байт, не падая на правах доступа и устройствах."""
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except (OSError, PermissionError, ValueError):
        return b""


def is_probably_text(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return False
    sample = data[:8192]
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126 or b >= 0xC0)
    return printable / len(sample) > 0.90


def app_data_dir() -> Path:
    """Каталог для данных приложения (карантин, журнал, настройки).

    Переменная окружения ONLYUNLOCKER_DATA позволяет держать данные рядом
    с программой (portable-режим) или в отдельной папке для тестов.
    """
    override = os.environ.get("ONLYUNLOCKER_DATA")
    if override:
        path = Path(override).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        return path
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    path = base / "OnlyUnlocker"
    path.mkdir(parents=True, exist_ok=True)
    return path


def resource_path(*parts: str) -> Path:
    """Путь к ресурсу, работает и из PyInstaller onefile (sys._MEIPASS)."""
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    else:
        base = Path(__file__).resolve().parent.parent.parent
    return base.joinpath(*parts)


def is_admin() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
