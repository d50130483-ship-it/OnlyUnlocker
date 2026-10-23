"""Системные данные для страниц «Процессы», «Автозагрузка», «Диски», «Пользователи».

Всё максимально переносимо: где нет системного API, используется то, что
доступно в стандартной библиотеке.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProcessInfo:
    pid: int
    name: str
    path: str = ""
    user: str = ""
    memory_kb: int = 0

    @property
    def memory_str(self) -> str:
        if self.memory_kb >= 1024:
            return f"{self.memory_kb / 1024:.1f} МБ"
        return f"{self.memory_kb} КБ"


def list_processes() -> list[ProcessInfo]:
    if sys.platform == "win32":
        return _processes_windows()
    return _processes_proc()


def _processes_proc() -> list[ProcessInfo]:
    result: list[ProcessInfo] = []
    proc = Path("/proc")
    if not proc.exists():
        return result
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            name = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        path = ""
        try:
            path = os.readlink(entry / "exe")
        except OSError:
            pass
        memory = 0
        try:
            for line in (entry / "status").read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("VmRSS:"):
                    memory = int(line.split()[1])
                    break
        except OSError:
            pass
        result.append(ProcessInfo(pid=pid, name=name, path=path, memory_kb=memory))
    return sorted(result, key=lambda p: p.name.lower())


def _windows_process_path(pid: int) -> str:
    """Путь к образу процесса через ctypes (без прав администратора для своих процессов)."""
    try:
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return ""
        try:
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return buffer.value
            return ""
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return ""


def _processes_windows() -> list[ProcessInfo]:
    result: list[ProcessInfo] = []
    try:
        output = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=15, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return result
    for line in output.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) < 4:
            continue
        name = parts[0]
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        mem = 0
        try:
            mem = int(parts[4].replace("K", "").replace(" ", "").replace(",", "").replace(".", ""))
        except (ValueError, IndexError):
            pass
        result.append(ProcessInfo(pid=pid, name=name, path=_windows_process_path(pid), memory_kb=mem))
    return sorted(result, key=lambda p: p.name.lower())


@dataclass
class AutorunEntry:
    location: str
    name: str
    command: str
    enabled: bool = True


def list_autoruns() -> list[AutorunEntry]:
    entries: list[AutorunEntry] = []
    if sys.platform == "win32":
        entries.extend(_autoruns_windows())
    entries.extend(_autoruns_files())
    return entries


def _autoruns_windows() -> list[AutorunEntry]:
    import winreg  # type: ignore[import-not-found]

    result: list[AutorunEntry] = []
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\WOW6432\\Run"),
    ]
    for hive, path, label in keys:
        try:
            with winreg.OpenKey(hive, path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    result.append(AutorunEntry(location=label, name=name, command=str(value)))
                    index += 1
        except OSError:
            continue
    return result


def _autoruns_files() -> list[AutorunEntry]:
    result: list[AutorunEntry] = []
    if sys.platform == "win32":
        startup_dirs = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        ]
    else:
        startup_dirs = [Path.home() / ".config" / "autostart", Path("/etc/xdg/autostart")]
    for folder in startup_dirs:
        if not folder or not folder.is_dir():
            continue
        for item in sorted(folder.glob("*")):
            if not item.is_file():
                continue
            command = ""
            try:
                if item.suffix.lower() == ".desktop":
                    for line in item.read_text(encoding="utf-8", errors="replace").splitlines():
                        if line.lower().startswith("exec="):
                            command = line.split("=", 1)[1]
                            break
            except OSError:
                pass
            result.append(AutorunEntry(location=str(folder), name=item.name, command=command or str(item)))
    return result


@dataclass
class DiskInfo:
    mount: str
    total: int
    used: int
    free: int
    percent: float


def list_disks() -> list[DiskInfo]:
    mounts: list[str] = []
    if sys.platform == "win32":
        try:
            import ctypes

            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    mounts.append(f"{chr(65 + i)}:\\")
        except Exception:
            mounts = ["C:\\"]
    else:
        try:
            for line in Path("/proc/mounts").read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mount, fstype = parts[0], parts[1], parts[2]
                if fstype in ("proc", "sysfs", "tmpfs", "devtmpfs", "overlay", "squashfs", "cgroup2", "devpts", "ramfs", "mqueue"):
                    continue
                if device.startswith("/dev/") or mount.startswith("/mnt/") or mount.startswith("/media/"):
                    mounts.append(mount)
        except OSError:
            mounts = ["/"]
        if "/" not in mounts:
            mounts.insert(0, "/")
    result: list[DiskInfo] = []
    seen: set[str] = set()
    for mount in mounts:
        if mount in seen:
            continue
        seen.add(mount)
        try:
            usage = shutil.disk_usage(mount)
        except OSError:
            continue
        percent = (usage.used / usage.total * 100) if usage.total else 0.0
        result.append(DiskInfo(mount=mount, total=usage.total, used=usage.used, free=usage.free, percent=percent))
    return result


@dataclass
class UserInfo:
    name: str
    admin: bool
    home: str = ""


def list_users() -> list[UserInfo]:
    from .utils import is_admin

    name = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    home = os.environ.get("USERPROFILE") or str(Path.home())
    return [UserInfo(name=name, admin=is_admin(), home=home)]


def system_summary() -> dict[str, str]:
    return {
        "OS": f"{sys.platform} {os.uname().release if hasattr(os, 'uname') else ''}".strip(),
        "Python": sys.version.split()[0],
        "Компьютер": os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME", "—"),
        "Пользователь": os.environ.get("USERNAME") or os.environ.get("USER", "—"),
        "Архитектура": os.environ.get("PROCESSOR_ARCHITECTURE", os.uname().machine if hasattr(os, "uname") else "—"),
    }
