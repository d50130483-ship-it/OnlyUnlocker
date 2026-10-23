"""Точка входа: python -m onlyunlocker [scan|info|update|quarantine]."""
from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) > 1:
        from .core.cli import main as cli_main

        return cli_main()

    from .ui.main_window import run

    return run()


if __name__ == "__main__":
    raise SystemExit(main())
