@echo off
chcp 65001 >nul
title OnlyUnlocker
cd /d "%~dp0"

where pythonw >nul 2>nul
if errorlevel 1 (
    echo Python не найден. Установите Python 3.10+ с python.org и повторите запуск.
    pause
    exit /b 1
)

python -c "import PySide6" >nul 2>nul
if errorlevel 1 (
    echo Первый запуск: устанавливаю PySide6...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo Не удалось установить зависимости.
        pause
        exit /b 1
    )
)

start "" pythonw run.py
