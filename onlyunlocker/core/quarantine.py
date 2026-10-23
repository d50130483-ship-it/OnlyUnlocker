"""Карантин: файл изолируется из системы и хранится в закодированном виде.

Важно: это не криптостойкое шифрование, а обфускация содержимого, чтобы
случайный антивирус/индексатор не тронул образец. Ключ выводится из
идентификатора машины, поэтому карантин не переносится между ПК.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path

from .models import FileReport
from .utils import app_data_dir


def _machine_key() -> bytes:
    seed = f"{uuid.getnode()}:{os.environ.get('COMPUTERNAME') or os.environ.get('HOSTNAME', 'host')}"
    import hashlib

    return hashlib.sha256(seed.encode("utf-8")).digest()


def _keystream_xor(data: bytes, key: bytes) -> bytes:
    import hashlib

    out = bytearray(len(data))
    block = 0
    pos = 0
    while pos < len(data):
        chunk = hashlib.sha256(key + block.to_bytes(8, "little")).digest()
        for byte in chunk:
            if pos >= len(data):
                break
            out[pos] = data[pos] ^ byte
            pos += 1
        block += 1
    return bytes(out)


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    sha256: str
    size: int
    added_at: float
    detections: list[str]
    verdict: str
    stored_name: str = ""

    @property
    def added_str(self) -> str:
        return time.strftime("%d.%m.%Y %H:%M", time.localtime(self.added_at))

    def to_dict(self) -> dict:
        return asdict(self)


class Quarantine:
    def __init__(self, folder: Path | None = None) -> None:
        self.folder = folder or (app_data_dir() / "quarantine")
        self.folder.mkdir(parents=True, exist_ok=True)
        self.index_path = self.folder / "index.json"
        self._lock = threading.Lock()
        self._items: dict[str, QuarantineItem] = {}
        self._load()

    # --- служебное ---------------------------------------------------------
    def _load(self) -> None:
        if not self.index_path.exists():
            return
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for entry in raw.get("items", []):
            try:
                item = QuarantineItem(**entry)
            except TypeError:
                continue
            self._items[item.id] = item

    def _save(self) -> None:
        payload = {"version": 1, "items": [i.to_dict() for i in self._items.values()]}
        tmp = self.index_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.index_path)

    # --- API ---------------------------------------------------------------
    def items(self) -> list[QuarantineItem]:
        with self._lock:
            return sorted(self._items.values(), key=lambda i: i.added_at, reverse=True)

    @property
    def count(self) -> int:
        return len(self._items)

    def total_size(self) -> int:
        return sum(item.size for item in self._items.values())

    def add(self, report: FileReport, copy_only: bool = False) -> QuarantineItem:
        """Изолирует файл. copy_only=True — оставить оригинал (режим «в карантин с копией»)."""
        source = Path(report.path)
        qid = uuid.uuid4().hex[:12]
        stored_name = f"{qid}.qtn"
        target = self.folder / stored_name

        with open(source, "rb") as fh:
            payload = fh.read()
        encoded = _keystream_xor(payload, _machine_key())
        tmp = target.with_suffix(".part")
        with open(tmp, "wb") as fh:
            fh.write(b"OLQ1" + encoded)
        tmp.replace(target)

        if not copy_only:
            try:
                source.unlink()
            except OSError:
                pass  # файл занят или нет прав — копия в карантине всё равно есть

        item = QuarantineItem(
            id=qid,
            original_path=str(source),
            sha256=report.sha256,
            size=report.size,
            added_at=time.time(),
            detections=[d.title for d in report.detections],
            verdict=report.verdict.value,
            stored_name=stored_name,
        )
        with self._lock:
            self._items[qid] = item
            self._save()
        return item

    def restore(self, item_id: str, destination: str | None = None) -> str:
        with self._lock:
            item = self._items.get(item_id)
        if not item:
            raise KeyError("Элемент карантина не найден")
        stored = self.folder / item.stored_name
        if not stored.exists():
            raise FileNotFoundError("Файл карантина повреждён или удалён")
        raw = stored.read_bytes()
        if not raw.startswith(b"OLQ1"):
            raise ValueError("Неизвестный формат карантина")
        payload = _keystream_xor(raw[4:], _machine_key())

        target = Path(destination or item.original_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            stem, suffix = target.stem, target.suffix
            index = 1
            while True:
                candidate = target.with_name(f"{stem}_restored{index}{suffix}")
                if not candidate.exists():
                    target = candidate
                    break
                index += 1
        target.write_bytes(payload)
        try:
            os.chmod(target, 0o644)
        except OSError:
            pass

        with self._lock:
            self._items.pop(item_id, None)
            self._save()
        try:
            stored.unlink()
        except OSError:
            pass
        return str(target)

    def delete(self, item_id: str) -> None:
        with self._lock:
            item = self._items.pop(item_id, None)
            self._save()
        if item:
            try:
                (self.folder / item.stored_name).unlink()
            except OSError:
                pass

    def purge(self) -> int:
        count = 0
        for item in list(self.items()):
            self.delete(item.id)
            count += 1
        return count

    def export_report(self, path: str | Path) -> None:
        data = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "items": [i.to_dict() for i in self.items()],
        }
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
