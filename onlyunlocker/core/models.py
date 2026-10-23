"""Модели данных движка и журнала."""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"
    SKIPPED = "skipped"

    @property
    def label(self) -> str:
        return {
            Verdict.CLEAN: "Чисто",
            Verdict.SUSPICIOUS: "Подозрительно",
            Verdict.MALICIOUS: "Угроза",
            Verdict.ERROR: "Ошибка",
            Verdict.SKIPPED: "Пропущено",
        }[self]


SEVERITY_SCORE = {"low": 10, "medium": 25, "high": 45, "critical": 80}
SEVERITY_LABEL = {"low": "низкая", "medium": "средняя", "high": "высокая", "critical": "критическая"}
MALICIOUS_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 30


@dataclass
class Detection:
    """Одна сработавшая проверка."""

    rule: str
    title: str
    description: str = ""
    severity: str = "medium"
    category: str = "heuristic"  # signature | heuristic | pe | script | macro | pattern | adware | reputation

    @property
    def score(self) -> int:
        return SEVERITY_SCORE.get(self.severity, 10)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["score"] = self.score
        return data


@dataclass
class FileReport:
    path: str
    size: int = 0
    sha256: str = ""
    verdict: Verdict = Verdict.CLEAN
    score: int = 0
    detections: list[Detection] = field(default_factory=list)
    duration_ms: int = 0
    error: str = ""
    modified: float = 0.0
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    @property
    def top_detection(self) -> Detection | None:
        return self.detections[0] if self.detections else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "size": self.size,
            "sha256": self.sha256,
            "verdict": self.verdict.value,
            "score": self.score,
            "error": self.error,
            "modified": self.modified,
            "meta": self.meta,
            "detections": [d.to_dict() for d in self.detections],
        }


@dataclass
class ScanSummary:
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    scanned: int = 0
    infected: int = 0
    suspicious: int = 0
    errors: int = 0
    bytes_scanned: int = 0
    target: str = ""
    mode: str = "quick"
    total_candidates: int = 0
    reports: list[FileReport] = field(default_factory=list)
    cancelled: bool = False

    @property
    def elapsed(self) -> float:
        end = self.finished_at or time.time()
        return max(0.0, end - self.started_at)

    @property
    def threats(self) -> list[FileReport]:
        return [r for r in self.reports if r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "mode": self.mode,
            "target": self.target,
            "scanned": self.scanned,
            "infected": self.infected,
            "suspicious": self.suspicious,
            "errors": self.errors,
            "bytes_scanned": self.bytes_scanned,
            "cancelled": self.cancelled,
            "threats": [r.to_dict() for r in self.threats],
        }
