"""Эвристики: набор независимых правил, которые возвращают Detection.

Каждое правило смотрит на уже собранный контекст файла, поэтому добавление
новой проверки не требует трогать движок сканирования.
"""
from __future__ import annotations

import os
import re
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import Detection
from .pe import PEInfo
from .signatures import SignatureDatabase
from .utils import entropy

EXECUTABLE_SUFFIXES = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".pif",
    ".msi", ".msp", ".hta", ".jar", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".bat", ".cmd", ".lnk", ".reg", ".msh", ".msh1", ".msh2",
    ".py", ".pyw", ".sh", ".apk", ".dmg", ".scr", ".gadget",
}
SCRIPT_SUFFIXES = {
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".bat", ".cmd", ".hta", ".py", ".pyw", ".sh", ".reg", ".bas", ".vba",
}
DOUBLE_EXT = re.compile(r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp[34]|avi|rtf|zip|rar)\s*\.(exe|scr|com|pif|bat|cmd|js|vbs|ps1|lnk|hta)$", re.I)
URL_RE = re.compile(rb"https?://[^\s\"'<>]{6,200}")
SCRIPT_MARKERS = (b"powershell", b"cmd.exe", b"wscript", b"cscript", b"rundll32", b"regsvr32", b"mshta")


@dataclass
class ScanContext:
    path: str
    size: int
    data: bytes
    head: bytes
    sha256: str
    suffix: str
    db: SignatureDatabase
    pe: PEInfo | None = None
    strings: list[str] = field(default_factory=list)
    is_text: bool = False
    file_entropy: float = 0.0
    in_app_dir: bool = False

    @property
    def name(self) -> str:
        return os.path.basename(self.path)


def run_all(ctx: ScanContext) -> list[Detection]:
    checks = (
        check_hash,
        check_patterns,
        check_pe,
        check_packer,
        check_text_rules,
        check_script_markers,
        check_double_extension,
        check_hidden_behaviour,
        check_high_entropy,
        check_unsigned_with_network,
        check_masquerade,
        check_lnk,
        check_recent_mass_writes,
    )
    found: list[Detection] = []
    for check in checks:
        try:
            found.extend(check(ctx) or [])
        except Exception:  # одна сломанная эвристика не должна валить скан
            continue
    found.sort(key=lambda d: d.score, reverse=True)
    return found


def _det(rule: str, title: str, desc: str, severity: str, category: str) -> Detection:
    return Detection(rule=rule, title=title, description=desc, severity=severity, category=category)


# --- отдельные правила -------------------------------------------------------


def check_hash(ctx: ScanContext) -> list[Detection]:
    hit = ctx.db.lookup_hash(ctx.sha256)
    if not hit:
        return []
    return [
        _det(
            f"VH:{hit.name}",
            f"Сигнатура базы: {hit.name}",
            f"Совпал SHA-256 с записью базы (семейство {hit.family}).",
            hit.severity if hit.severity in ("low", "medium", "high", "critical") else "high",
            "signature",
        )
    ]


def check_patterns(ctx: ScanContext) -> list[Detection]:
    out: list[Detection] = []
    for pattern in ctx.db.patterns:
        if pattern.matches(ctx.data):
            out.append(
                _det(
                    f"PAT:{pattern.name}",
                    pattern.name,
                    "Совпал байтовый шаблон базы сигнатур.",
                    pattern.severity,
                    "pattern",
                )
            )
    return out


def check_pe(ctx: ScanContext) -> list[Detection]:
    info = ctx.pe
    if not info or not info.is_pe:
        return []
    out: list[Detection] = []
    imports = info.imports

    injection = sorted(imports & {"virtualallocex", "writeprocessmemory", "createremotethread", "queueuserapc", "setthreadcontext", "ntcreatethreadex"})
    if len(injection) >= 2:
        out.append(
            _det(
                "HEUR:PE.CodeInjection",
                "Импорт-цепочка для внедрения кода",
                "Файл использует " + ", ".join(injection) + " — классический набор для инъекции в чужой процесс.",
                "critical" if len(injection) >= 3 else "high",
                "pe",
            )
        )

    creds = sorted(imports & {"minidumpwritedump", "cryptunprotectdata", "credreadw"})
    if "minidumpwritedump" in imports and ("lsass" in ctx.data.lower()):
        out.append(
            _det(
                "HEUR:PE.CredentialAccess",
                "Доступ к памяти LSASS",
                "MiniDumpWriteDump вместе со строкой lsass — типовой способ кражи хешей паролей.",
                "critical",
                "pe",
            )
        )
    elif len(creds) >= 2:
        out.append(
            _det(
                "HEUR:PE.CredentialAccess",
                "Работа с учётными данными",
                "Импорты " + ", ".join(creds) + " используются стилерами и дамперами.",
                "high",
                "pe",
            )
        )

    crypto = imports & {"cryptencrypt", "bcryptencrypt", "cryptgenkey", "cryptacquirecontextw"}
    if len(crypto) >= 2 and ctx.file_entropy > 7.0:
        out.append(
            _det(
                "HEUR:PE.RansomCrypto",
                "Шифрование данных",
                "Крипто-API в сочетании с высокоэнтропийными данными — возможный шифровальщик.",
                "medium",
                "pe",
            )
        )

    if info.has_rwx_section:
        names = [s.name for s in info.sections if s.writable and s.executable]
        out.append(
            _det(
                "HEUR:PE.RWXSection",
                "Секция одновременно записываемая и исполняемая",
                f"Секции {', '.join(names) or '?'} имеют права RWX — признак распаковщика в памяти.",
                "medium",
                "pe",
            )
        )

    if info.sections and not info.imports:
        out.append(
            _det(
                "HEUR:PE.NoImports",
                "PE без таблицы импорта",
                "У файла пустой import table. Так выглядят упакованные и самодостаточные загрузчики.",
                "high",
                "pe",
            )
        )

    if info.overlay_size > 0:
        try:
            with open(ctx.path, "rb") as fh:
                fh.seek(-min(info.overlay_size, 4 * 1024 * 1024), os.SEEK_END)
                tail = fh.read()
            overlay_ent = entropy(tail)
        except OSError:
            overlay_ent = 0.0
        if info.overlay_size > 256 * 1024 and overlay_ent > 7.3:
            out.append(
                _det(
                    "HEUR:PE.PackedOverlay",
                    "Плотный оверлей в PE-файле",
                    f"За секциями лежат {info.overlay_size // 1024} КБ данных с энтропией {overlay_ent}. Обычно так прячут доп. нагрузку.",
                    "high",
                    "pe",
                )
            )
        elif info.overlay_size > 0 and b"MZ" in ctx.data[-min(len(ctx.data), 2 * 1024 * 1024):][-1024:]:
            out.append(
                _det(
                    "HEUR:PE.DroppedPE",
                    "Вложенный исполняемый файл в оверлее",
                    "В хвосте PE найден ещё один MZ-заголовок.",
                    "high",
                    "pe",
                )
            )

    if info.entry_section and info.entry_section.lower() not in (".text", "code", ".code"):
        out.append(
            _det(
                "HEUR:PE.UntypicalEntry",
                "Точка входа вне кода",
                f"Entry point находится в секции {info.entry_section}, а не в коде — так делают упаковщики.",
                "medium",
                "pe",
            )
        )

    if info.compile_time:
        try:
            ts = datetime.strptime(info.compile_time, "%Y-%m-%d %H:%M UTC")
            if ts > datetime.utcnow() + timedelta(days=2):
                out.append(
                    _det(
                        "HEUR:PE.FutureTimestamp",
                        "Дата компиляции в будущем",
                        f"Метка времени {info.compile_time} — признак подделанных заголовков.",
                        "medium",
                        "pe",
                    )
                )
        except ValueError:
            pass

    return out


def check_packer(ctx: ScanContext) -> list[Detection]:
    info = ctx.pe
    if not info or not info.packer:
        return []
    severity = "medium"
    return [
        _det(
            "HEUR:Packed",
            f"Упаковщик/протектор: {info.packer}",
            "Файл упакован. Само по себе это не вирус, но такие файлы проверяют на VirusTotal.",
            severity,
            "heuristic",
        )
    ]


def check_text_rules(ctx: ScanContext) -> list[Detection]:
    if not ctx.is_text or ctx.size > 8 * 1024 * 1024:
        return []
    try:
        text = ctx.data.decode("utf-8", "replace")
    except Exception:
        return []
    lowered = text.lower()
    out: list[Detection] = []
    for rule in ctx.db.iter_rules_for(ctx.suffix):
        if rule.regex.search(text):
            out.append(
                _det(
                    f"RULE:{rule.name}",
                    rule.title,
                    rule.description or f"Сработало правило {rule.name}.",
                    rule.severity,
                    "script",
                )
            )
    # если правило по расширению не подошло, но текст похож на скрипт — проверяем общие правила
    if not out:
        for rule in ctx.db.iter_rules_for(""):
            if rule.regex.search(lowered):
                out.append(
                    _det(
                        f"RULE:{rule.name}",
                        rule.title,
                        rule.description or f"Сработало правило {rule.name}.",
                        rule.severity,
                        "script",
                    )
                )
    return out


def check_script_markers(ctx: ScanContext) -> list[Detection]:
    if ctx.suffix in (".exe", ".dll", ".sys"):
        return []
    haystack = ctx.head.lower()
    markers = [m for m in SCRIPT_MARKERS if m in haystack]
    if ctx.suffix in SCRIPT_SUFFIXES and len(markers) >= 3 and ctx.size < 64 * 1024:
        return [
            _det(
                "HEUR:Script.Dropper",
                "Короткий скрипт с запуском процессов",
                "Маленький файл вызывает " + ", ".join(m.decode() for m in markers) + ".",
                "high",
                "script",
            )
        ]
    return []


def check_double_extension(ctx: ScanContext) -> list[Detection]:
    if DOUBLE_EXT.search(ctx.name):
        return [
            _det(
                "HEUR:DoubleExtension",
                "Двойное расширение",
                "Имя файла маскирует исполняемый файл под документ или картинку.",
                "high",
                "heuristic",
            )
        ]
    return []


def check_hidden_behaviour(ctx: ScanContext) -> list[Detection]:
    if sys.platform != "win32":
        return []
    try:
        attrs = os.stat(ctx.path).st_file_attributes
    except (AttributeError, OSError):
        return []
    hidden = bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
    system = bool(attrs & stat.FILE_ATTRIBUTE_SYSTEM)
    if hidden and system and ctx.suffix in EXECUTABLE_SUFFIXES:
        return [
            _det(
                "HEUR:HiddenExecutable",
                "Скрытый системный исполняемый файл",
                "Атрибуты Hidden + System у EXE/DLL вне системных каталогов — типичное поведение малвари.",
                "medium",
                "heuristic",
            )
        ]
    return []


def check_high_entropy(ctx: ScanContext) -> list[Detection]:
    if ctx.suffix in (".exe", ".dll", ".sys"):
        return []
    if ctx.size < 64 * 1024:
        return []
    if ctx.file_entropy > 7.6 and not ctx.is_text:
        return [
            _det(
                "HEUR:HighEntropy",
                "Высокая энтропия данных",
                f"Энтропия {ctx.file_entropy} — содержимое зашифровано или сжато. Проверьте происхождение файла.",
                "low",
                "heuristic",
            )
        ]
    return []


def check_unsigned_with_network(ctx: ScanContext) -> list[Detection]:
    info = ctx.pe
    if not info or not info.is_pe or info.has_signature:
        return []
    net = info.imports & {"urldownloadtofilew", "internetopenurlw", "winhttpopen", "winhttpconnect", "wsastartup", "winexec", "shellexecutew"}
    loader = info.imports & {"virtualalloc", "virtualprotect", "loadlibrarya", "getprocaddress", "createremotethread"}
    if len(net) >= 2 and len(loader) >= 2:
        return [
            _det(
                "HEUR:Unsigned.Loader",
                "Неподписанный загрузчик с сетевыми функциями",
                "Нет цифровой подписи, но есть загрузка из сети и работа с памятью.",
                "high",
                "pe",
            )
        ]
    return []


def check_masquerade(ctx: ScanContext) -> list[Detection]:
    name = ctx.name.lower()
    system_names = {
        "svchost.exe", "lsass.exe", "explorer.exe", "csrss.exe", "winlogon.exe",
        "services.exe", "smss.exe", "wininit.exe", "taskhostw.exe", "conhost.exe",
    }
    if name in system_names and sys.platform == "win32":
        system_root = os.environ.get("SystemRoot", "C:\\Windows").lower()
        if not ctx.path.lower().startswith(os.path.join(system_root, "system32").lower()):
            return [
                _det(
                    "HEUR:Masquerade",
                    "Подмена системного процесса",
                    f"Файл называется {ctx.name}, но лежит вне System32.",
                    "high",
                    "heuristic",
                )
            ]
    return []


def check_lnk(ctx: ScanContext) -> list[Detection]:
    if ctx.suffix != ".lnk" or len(ctx.data) < 128:
        return []
    blob = ctx.data.lower()
    suspicious = any(token in blob for token in (b"powershell", b"cmd.exe", b"mshta", b"wscript", b"http://", b"https://"))
    if suspicious:
        return [
            _det(
                "HEUR:Lnk.SuspiciousTarget",
                "Ярлык запускает команду или ссылку",
                "LNK-файл содержит вызов интерпретатора или URL.",
                "medium",
                "heuristic",
            )
        ]
    return []


def check_recent_mass_writes(ctx: ScanContext) -> list[Detection]:  # зарезервировано под поведенческий блок
    return []
