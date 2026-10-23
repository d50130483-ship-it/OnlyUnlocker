"""Дымовой тест интерфейса. Пропускается, если Qt недоступен (например, в headless CI)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("PySide6")

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:  # Qt может быть установлен без системных библиотек (headless CI)
    import importlib

    importlib.import_module("PySide6.QtWidgets")
except ImportError as exc:  # pragma: no cover
    pytest.skip(f"Qt недоступен: {exc}", allow_module_level=True)


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    from PySide6.QtWidgets import QApplication

    from onlyunlocker.ui.theme import apply_theme

    os.environ["ONLYUNLOCKER_DATA"] = str(tmp_path_factory.mktemp("data"))
    application = QApplication.instance() or QApplication([])
    apply_theme(application)
    return application


def test_window_and_pages(app):
    from onlyunlocker.ui.main_window import MainWindow

    window = MainWindow()
    window.resize(1280, 840)
    window.show()
    app.processEvents()
    keys = ["dashboard", "scan", "quarantine", "monitor", "history", "tools", "settings"]
    for key in keys:
        window.navigate(key)
        app.processEvents()
        assert window.stack.currentWidget() is window.pages[key]
    window.close()


def test_scan_page_handles_threats(app, tmp_path):
    from onlyunlocker.ui.main_window import MainWindow

    sample = tmp_path / "enc.bat"
    sample.write_text("vssadmin delete shadows /all /quiet\n", encoding="utf-8")
    window = MainWindow()
    window.show()
    app.processEvents()
    page = window.pages["scan"]
    summary = window.ctx.engine.scan([str(tmp_path)], mode="custom")
    for report in summary.threats:
        page._add_report(report)
    page._on_finished(summary)
    app.processEvents()
    assert page.table.rowCount() >= 1
    assert page.export_button.isEnabled()
    window.close()


def test_shield_states(app):
    from onlyunlocker.ui.widgets import ShieldWidget

    shield = ShieldWidget()
    for state in ("ok", "warn", "danger", "scanning", "idle"):
        shield.set_state(state)
        assert shield.state == state
    shield.grab()  # отрисовка не должна падать
