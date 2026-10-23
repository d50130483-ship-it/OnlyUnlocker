"""Консольный интерфейс: полезен для проверок в CI и на серверах без GUI."""
from __future__ import annotations

import argparse
import json
import sys

from .quarantine import Quarantine
from .scanner import ScanEngine, ScanSettings, default_targets
from .updater import load_database, update_from_url
from .utils import human_size, human_time


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="onlyunlocker", description="OnlyUnlocker — антивирусный сканер")
    parser.add_argument("--version", action="version", version="OnlyUnlocker 1.0")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="проверить файл или папку")
    scan.add_argument("path", nargs="*", help="файлы/папки (по умолчанию — быстрые зоны)")
    scan.add_argument("--quick", action="store_true", help="быстрая проверка стандартных зон")
    scan.add_argument("--full", action="store_true", help="полная проверка домашнего каталога")
    scan.add_argument("--json", action="store_true", help="вывод в JSON")
    scan.add_argument("--quarantine", action="store_true", help="поместить угрозы в карантин")
    scan.add_argument("--workers", type=int, default=4)
    scan.add_argument("--fast", action="store_true", help="только сигнатуры, без эвристик PE")

    info = sub.add_parser("info", help="информация о базе сигнатур")
    info.add_argument("--json", action="store_true")

    upd = sub.add_parser("update", help="обновить базу сигнатур")
    upd.add_argument("--url", default="", help="URL базы (по умолчанию из настроек)")

    q = sub.add_parser("quarantine", help="управление карантином")
    q.add_argument("action", choices=["list", "restore", "delete", "purge"])
    q.add_argument("item", nargs="?", help="id элемента")
    q.add_argument("--to", default=None, help="куда восстановить")
    return parser


def _scan(args) -> int:
    mode = "full" if args.full else "quick"
    targets = args.path or default_targets(mode)
    settings = ScanSettings(workers=max(1, args.workers), deep=not args.fast)
    engine = ScanEngine(load_database(), settings)
    summary = engine.scan(targets, mode=mode)

    if args.json:
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"Проверено файлов: {summary.scanned}")
        print(f"Угроз: {summary.infected}, подозрительных: {summary.suspicious}, ошибок: {summary.errors}")
        print(f"Время: {human_time(summary.elapsed)}, объём: {human_size(summary.bytes_scanned)}")
        for report in summary.threats:
            top = report.top_detection
            print(f"  [{report.verdict.label}] {report.path}")
            if top:
                print(f"      {top.rule}: {top.title}")
    quarantine = Quarantine()
    if args.quarantine:
        moved = 0
        for report in summary.threats:
            item = quarantine.add(report)
            print(f"  -> в карантин: {item.id} ({item.original_path})")
            moved += 1
        if moved:
            print(f"Изолировано файлов: {moved}")
    return 1 if summary.infected else 0


def _info(args) -> int:
    db = load_database()
    data = {
        "version": db.version,
        "hashes": len(db.hashes),
        "patterns": len(db.patterns),
        "rules": len(db.rules),
        "source": str(db.source),
    }
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(f"OnlyUnlocker 1.0 — база {db.version}")
        print(f"  хешей: {data['hashes']}, шаблонов: {data['patterns']}, правил: {data['rules']}")
        print(f"  источник: {data['source']}")
    return 0


def _update(args) -> int:
    from .storage import Settings

    url = args.url or Settings().get("signature_url", "")
    result = update_from_url(url)
    print(result.message + (f" (версия {result.version}, правил {result.rules})" if result.ok else ""))
    return 0 if result.ok else 2


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "info":
        return _info(args)
    if args.command == "update":
        return _update(args)
    if args.command == "quarantine":
        quarantine = Quarantine()
        if args.action == "list":
            for item in quarantine.items():
                print(f"{item.id}  {item.added_str}  {item.original_path}  ({', '.join(item.detections) or '—'})")
            if not quarantine.count:
                print("Карантин пуст")
            return 0
        if args.action == "purge":
            print(f"Удалено: {quarantine.purge()}")
            return 0
        if not args.item:
            parser.error("укажите id элемента карантина")
        if args.action == "restore":
            print("Восстановлено: " + quarantine.restore(args.item, args.to))
            return 0
        quarantine.delete(args.item)
        print("Удалено")
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
