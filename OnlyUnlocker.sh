#!/usr/bin/env bash
# Запуск OnlyUnlocker в Linux/macOS: ./OnlyUnlocker.sh [--scan путь]
set -e
cd "$(dirname "$0")"
if ! python3 -c "import PySide6" >/dev/null 2>&1; then
    echo "Устанавливаю PySide6…"
    python3 -m pip install --user -r requirements.txt
fi
exec python3 run.py "$@"
