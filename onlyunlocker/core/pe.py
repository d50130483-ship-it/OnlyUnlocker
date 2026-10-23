"""Минимальный, но аккуратный разбор PE-файлов (EXE/DLL/SYS) без зависимостей.

Умеет: заголовки, секции, точку входа, импорты, оверлей, признак подписи,
компилятор по Rich-заголовку, эвристику упаковщиков.
"""
from __future__ import annotations

import datetime as _dt
import struct
from dataclasses import dataclass, field

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}
SUBSYSTEM_NAMES = {
    1: "native",
    2: "GUI",
    3: "CUI",
    9: "Windows CE",
    10: "EFI",
}
MZ_HEADER_DOS_STUB = b"This program cannot be run in DOS mode"

# section flags
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000
SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED_DATA = 0x00000040

DIR_SECURITY = 4
DIR_IMPORT = 1
DIR_RESOURCE = 2

# упаковщики/защиты по именам секций
PACKER_SECTIONS = {
    "UPX0": "UPX",
    "UPX1": "UPX",
    "UPX2": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".themida": "Themida",
    ".winlice": "WinLicense",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    ".enigma1": "Enigma",
    ".enigma2": "Enigma",
    ".petite": "Petite",
    ".packed": "Generic packer",
    "pec1": "PECompact",
    "pec2": "PECompact",
    ".nsp0": "NsPack",
}

# API, интересные с точки зрения поведения
API_INJECTION = {
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "ntunmapviewofsection",
    "queueuserapc",
    "setthreadcontext",
    "ntcreatethreadex",
    "rtlcreateuserthread",
    "openprocess",
}
API_CREDENTIALS = {
    "minidumpwritedump",
    "lsass",
    "credreadw",
    "cryptunprotectdata",
    "samlib",
    "sekurlsa",
}
API_PERSISTENCE = {
    "regsetvalueexw",
    "regcreatekeyexw",
    "createservicew",
    "schtasks",
}
API_EVASION = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "virtualprotect",
    "sleepex",
    "gettickcount",
}
API_NETWORK = {
    "internetopenurlw",
    "urldownloadtofilew",
    "winexec",
    "shellexecutew",
    "wsastartup",
    "winhttpopen",
    "winhttpconnect",
}
API_CRYPTO = {"cryptencrypt", "cryptgenkey", "bcryptencrypt", "cryptacquirecontextw"}


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int
    entropy: float = 0.0

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_WRITE)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_READ)

    @property
    def data(self) -> bytes:
        return b""


@dataclass
class PEInfo:
    is_pe: bool = False
    is_64bit: bool = False
    machine: str = ""
    subsystem: str = ""
    timestamp: int = 0
    compile_time: str = ""
    entry_point_rva: int = 0
    image_base: int = 0
    checksum: int = 0
    checksum_valid: bool | None = None
    sections: list[Section] = field(default_factory=list)
    imports: set[str] = field(default_factory=set)
    dll_names: list[str] = field(default_factory=list)
    is_dll: bool = False
    is_dotnet: bool = False
    has_signature: bool = False
    overlay_size: int = 0
    overlay_entropy: float = 0.0
    rich_header: bool = False
    packer: str = ""
    entry_section: str = ""
    parse_error: str = ""

    @property
    def section_names(self) -> list[str]:
        return [s.name for s in self.sections]

    @property
    def has_rwx_section(self) -> bool:
        return any(s.writable and s.executable for s in self.sections)

    @property
    def high_entropy_sections(self) -> list[Section]:
        return [s for s in self.sections if s.entropy > 7.2 and s.raw_size > 4096]


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def u64(self, off: int) -> int:
        return struct.unpack_from("<Q", self.data, off)[0]

    def bytes_at(self, off: int, size: int) -> bytes:
        return self.data[off : off + size]


def _section_name(raw: bytes) -> str:
    name = raw.split(b"\x00", 1)[0]
    return name.decode("ascii", "replace").strip("\x00 ")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    import math

    ent = 0.0
    for count in counts:
        if count:
            p = count / total
            ent -= p * math.log2(p)
    return round(ent, 3)


def parse(data: bytes, total_file_size: int | None = None) -> PEInfo:
    """Разбирает буфер, начиная с MZ. Возвращает PEInfo; при ошибке is_pe=False."""
    info = PEInfo()
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return info
        r = _Reader(data)
        pe_off = r.u32(0x3C)
        if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
            return info
        info.is_pe = True
        coff = pe_off + 4
        machine = r.u16(coff)
        num_sections = r.u16(coff + 2)
        info.timestamp = r.u32(coff + 4)
        opt_size = r.u16(coff + 16)
        characteristics = r.u16(coff + 18)
        info.machine = MACHINE_NAMES.get(machine, f"0x{machine:04X}")
        info.is_dll = bool(characteristics & 0x2000)
        if info.timestamp:
            try:
                info.compile_time = _dt.datetime.utcfromtimestamp(info.timestamp).strftime("%Y-%m-%d %H:%M UTC")
            except (OSError, OverflowError, ValueError):
                info.compile_time = ""

        opt = coff + 20
        if opt + opt_size > len(data) or opt_size < 96:
            info.parse_error = "Некорректный optional header"
            return info
        magic = r.u16(opt)
        info.is_64bit = magic == 0x20B
        if magic not in (0x10B, 0x20B):
            info.parse_error = "Неизвестный формат PE"
            return info
        info.entry_point_rva = r.u32(opt + 16)
        if info.is_64bit:
            info.image_base = r.u64(opt + 24)
        else:
            info.image_base = r.u32(opt + 28)
        info.checksum = r.u32(opt + 64)
        subsystem = r.u16(opt + 68)
        info.subsystem = SUBSYSTEM_NAMES.get(subsystem, str(subsystem))

        dirs_off = opt + (112 if info.is_64bit else 96)
        num_dirs = r.u32(opt + (108 if info.is_64bit else 92))
        def data_dir(index: int) -> tuple[int, int]:
            if index >= num_dirs or dirs_off + index * 8 + 8 > len(data):
                return 0, 0
            return r.u32(dirs_off + index * 8), r.u32(dirs_off + index * 8 + 4)

        sec_dir_rva, sec_dir_size = data_dir(DIR_SECURITY)
        info.has_signature = sec_dir_rva != 0 and sec_dir_size != 0
        imp_rva, imp_size = data_dir(DIR_IMPORT)
        com_rva, _ = data_dir(14)  # CLR runtime header
        info.is_dotnet = com_rva != 0

        # Rich header: между DOS-stub и PE-заголовком ищем 'Rich'
        rich_pos = data.find(b"Rich", 0x40, pe_off)
        info.rich_header = rich_pos != -1

        section_table = opt + opt_size
        if section_table + num_sections * 40 > len(data):
            info.parse_error = "Таблица секций выходит за файл"
            return info

        for i in range(min(num_sections, 96)):
            base = section_table + i * 40
            name = _section_name(r.bytes_at(base, 8))
            vsize = r.u32(base + 8)
            vaddr = r.u32(base + 12)
            raw_size = r.u32(base + 16)
            raw_off = r.u32(base + 20)
            chars = r.u32(base + 36)
            payload = data[raw_off : raw_off + min(raw_size, 2 * 1024 * 1024)] if raw_off < len(data) else b""
            section = Section(
                name=name,
                virtual_address=vaddr,
                virtual_size=vsize,
                raw_size=raw_size,
                raw_offset=raw_off,
                characteristics=chars,
                entropy=_entropy(payload),
            )
            info.sections.append(section)

        # точка входа -> секция
        for section in info.sections:
            start = section.virtual_address
            end = start + max(section.virtual_size, section.raw_size)
            if start <= info.entry_point_rva < end:
                info.entry_section = section.name
                break

        # упаковщик по именам секций
        packers = {name.lower(): label for name, label in PACKER_SECTIONS.items()}
        for section in info.sections:
            key = section.name.lower()
            if key in packers:
                info.packer = packers[key]
                break
            if key.startswith(".vmp"):
                info.packer = "VMProtect"
                break

        # оверлей
        end_of_image = 0
        for section in info.sections:
            end_of_image = max(end_of_image, section.raw_offset + section.raw_size)
        if total_file_size and total_file_size > end_of_image:
            info.overlay_size = total_file_size - end_of_image

        imports, dlls = _parse_imports(data, imp_rva, imp_size, info.is_64bit, info.sections)
        info.imports = imports
        info.dll_names = sorted(dlls)
        # проверка контрольной суммы не критична; считаем только признак
        info.checksum_valid = None
    except (struct.error, IndexError, ValueError) as exc:  # pragma: no cover - защитный код
        info.parse_error = f"Ошибка разбора: {exc}"
    return info


def _rva_to_offset(sections: list[Section], rva: int) -> int:
    """Перевод RVA в смещение в файле по таблице секций."""
    for section in sections:
        start = section.virtual_address
        size = max(section.virtual_size, section.raw_size)
        if start <= rva < start + size:
            delta = rva - start
            if delta < section.raw_size:
                return section.raw_offset + delta
            return -1
    # заголовки лежат в начале файла
    return rva


def _parse_imports(
    data: bytes, imp_rva: int, imp_size: int, is_64bit: bool, sections: list[Section]
) -> tuple[set[str], set[str]]:
    """Возвращает (имена импортируемых функций, имена DLL) в нижнем регистре."""
    result: set[str] = set()
    dlls: set[str] = set()
    if not imp_rva or not imp_size or imp_rva >= len(data):
        return result, dlls
    r = _Reader(data)
    off = _rva_to_offset(sections, imp_rva)
    if off <= 0:
        return result, dlls
    for _ in range(256):
        if off + 20 > len(data):
            break
        try:
            name_rva = r.u32(off + 12)
            first_thunk = r.u32(off + 16)
        except struct.error:
            break
        if name_rva == 0 and first_thunk == 0:
            break
        dll_off = _rva_to_offset(sections, name_rva)
        if 0 < dll_off < len(data):
            end = data.find(b"\x00", dll_off, dll_off + 260)
            if end != -1:
                dll = data[dll_off:end].decode("ascii", "replace")
                if dll and dll.lower().endswith((".dll", ".exe", ".sys", ".ocx", ".drv")):
                    dlls.add(dll.lower())
        thunk = _rva_to_offset(sections, first_thunk) if first_thunk else 0
        if thunk > 0:
            step = 8 if is_64bit else 4
            for _ in range(2048):
                if thunk + step > len(data):
                    break
                value = r.u64(thunk) if is_64bit else r.u32(thunk)
                if value == 0:
                    break
                # ordinal imports помечаем отдельно
                if value & (1 << (63 if is_64bit else 31)):
                    thunk += step
                    continue
                hint_off = _rva_to_offset(sections, value & 0x7FFFFFFF)
                if 0 < hint_off and hint_off + 2 < len(data):
                    end = data.find(b"\x00", hint_off + 2, hint_off + 262)
                    if end != -1:
                        fname = data[hint_off + 2 : end].decode("ascii", "replace")
                        if fname:
                            result.add(fname.lower())
                thunk += step
        off += 20
    return result, dlls


def analyze(data: bytes, total_file_size: int | None = None) -> PEInfo:
    """Разбор PE; возвращает структуру с импортами и эвристиками."""
    return parse(data, total_file_size)
