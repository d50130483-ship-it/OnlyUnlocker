@echo off
chcp 65001 >nul
title OnlyUnlocker — сборка exe
cd /d "%~dp0"

echo ================================================
echo   OnlyUnlocker: сборка одного exe
echo ================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [Ошибка] Python не найден в PATH. Установите Python 3.10+ с python.org
    pause
    exit /b 1
)

echo [1/3] Установка зависимостей...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt -r requirements-build.txt
if errorlevel 1 goto fail

echo [2/3] Прогон тестов...
python -m pytest tests -q
if errorlevel 1 (
    echo [Внимание] Тесты не прошли. Сборка остановлена.
    pause
    exit /b 1
)

echo [3/3] Сборка PyInstaller...
python -m PyInstaller --noconfirm --clean OnlyUnlocker.spec
if errorlevel 1 goto fail

echo.
echo Готово: dist\OnlyUnlocker.exe
echo Запуск из исходников: python run.py
pause
exit /b 0

:fail
echo.
echo [Ошибка] Сборка не удалась. Смотрите сообщения выше.
pause
exit /b 1
