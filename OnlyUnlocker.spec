# -*- mode: python ; coding: utf-8 -*-
"""Спецификация PyInstaller: собирает один OnlyUnlocker.exe с базой сигнатур и иконкой."""

from pathlib import Path

block_cipher = None
root = Path(SPECPATH)

a = Analysis(
    ["run.py"],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (str(root / "onlyunlocker" / "data" / "signatures.json"), "onlyunlocker/data"),
        (str(root / "assets" / "logo.svg"), "assets"),
        (str(root / "assets" / "logo.png"), "assets"),
        (str(root / "assets" / "logo.ico"), "assets"),
    ],
    hiddenimports=[
        "PySide6.QtSvg",
        "PySide6.QtNetwork",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "tkinter", "numpy", "pandas", "matplotlib", "PySide6.Qt3DAnimation", "PySide6.Qt3DCore",
        "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtQuick3D", "PySide6.QtWebEngineCore",
        "PySide6.QtMultimedia", "PySide6.QtDesigner",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="OnlyUnlocker",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    icon=str(root / "assets" / "logo.ico") if (root / "assets" / "logo.ico").exists() else None,
)
