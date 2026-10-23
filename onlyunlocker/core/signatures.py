"""База сигнатур: хеши, байтовые шаблоны с масками, текстовые правила.

Формат data/signatures.json:
{
  "version": "2026.10.23",
  "hashes":  [{"sha256": "...", "name": "...", "family": "...", "severity": "high"}],
  "patterns": [{"name": "...", "hex": "4D 5A ?? ??", "scope": "head|all", "max_scan": 1048576,
                "severity": "medium", "family": "..."}],
  "rules":   [{"name": "...", "title": "...", "regex": "...", "extensions": [".ps1"],
               "severity": "medium", "flags": "ims"}]
}
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .utils import resource_path


@dataclass(frozen=True)
class HashSignature:
    sha256: str
    name: str
    family: str
    severity: str


@dataclass(frozen=True)
class PatternSignature:
    name: str
    regex: re.Pattern[bytes]
    severity: str
    scope: str = "head"
    max_scan: int = 1024 * 1024
    family: str = ""

    def matches(self, data: bytes) -> bool:
        haystack = data if self.scope == "all" else data[: self.max_scan]
        return self.regex.search(haystack) is not None


@dataclass(frozen=True)
class TextRule:
    name: str
    title: str
    regex: re.Pattern[str]
    description: str = ""
    severity: str = "medium"
    extensions: tuple[str, ...] = ()
    family: str = ""

    def applies_to(self, suffix: str) -> bool:
        return not self.extensions or suffix.lower() in self.extensions


def _hex_to_bytes_regex(pattern: str) -> re.Pattern[bytes]:
    """'4D 5A ?? 00' -> bytes-regex с маской на ?? и *."""
    tokens = pattern.replace(",", " ").split()
    out: list[bytes] = []
    for token in tokens:
        token = token.strip()
        if token in ("??", "?", "*"):
            out.append(b".")
        elif token.startswith("*"):  # *12 = до 12 произвольных байт
            try:
                count = int(token[1:] or 32)
            except ValueError:
                count = 32
            out.append(b".{0,%d}" % min(count, 4096))
        else:
            out.append(re.escape(bytes.fromhex(token)))
    return re.compile(b"".join(out), re.DOTALL)


class SignatureDatabase:
    """Загруженная база. Потокобезопасна для чтения."""

    def __init__(self) -> None:
        self.version = "0"
        self.hashes: dict[str, HashSignature] = {}
        self.families: dict[str, HashSignature] = {}
        self.patterns: list[PatternSignature] = []
        self.rules: list[TextRule] = []
        self.source: Path | None = None

    @classmethod
    def load(cls, path: str | Path | None = None) -> "SignatureDatabase":
        db = cls()
        target = Path(path) if path else resource_path("onlyunlocker", "data", "signatures.json")
        db.source = target
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return db
        db._load_dict(raw)
        return db

    def _load_dict(self, raw: dict) -> None:
        self.version = str(raw.get("version", "0"))
        for item in raw.get("hashes", []):
            digest = str(item.get("sha256", "")).lower().strip()
            if len(digest) != 64:
                continue
            sig = HashSignature(
                sha256=digest,
                name=str(item.get("name", "Unknown")),
                family=str(item.get("family", "Unknown")),
                severity=str(item.get("severity", "high")),
            )
            self.hashes[digest] = sig
        for item in raw.get("patterns", []):
            try:
                regex = _hex_to_bytes_regex(str(item["hex"]))
            except (KeyError, ValueError):
                continue
            self.patterns.append(
                PatternSignature(
                    name=str(item.get("name", "Pattern")),
                    regex=regex,
                    severity=str(item.get("severity", "medium")),
                    scope=str(item.get("scope", "head")),
                    max_scan=int(item.get("max_scan", 1024 * 1024)),
                    family=str(item.get("family", "")),
                )
            )
        for item in raw.get("rules", []):
            try:
                flags = 0
                for ch in str(item.get("flags", "ims")):
                    flags |= {"i": re.I, "m": re.M, "s": re.S}[ch]
                regex = re.compile(str(item["regex"]), flags)
            except (KeyError, re.error):
                continue
            self.rules.append(
                TextRule(
                    name=str(item.get("name", "Rule")),
                    title=str(item.get("title", item.get("name", "Rule"))),
                    regex=regex,
                    description=str(item.get("description", "")),
                    severity=str(item.get("severity", "medium")),
                    extensions=tuple(item.get("extensions", ())),
                    family=str(item.get("family", "")),
                )
            )

    @property
    def total(self) -> int:
        return len(self.hashes) + len(self.patterns) + len(self.rules)

    def lookup_hash(self, digest: str) -> HashSignature | None:
        return self.hashes.get(digest.lower())

    def iter_rules_for(self, suffix: str) -> Iterable[TextRule]:
        for rule in self.rules:
            if rule.applies_to(suffix):
                yield rule
