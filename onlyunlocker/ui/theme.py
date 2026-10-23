"""Цвета, шрифты и глобальная таблица стилей."""
from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication

# --- палитра ---------------------------------------------------------------
BG = "#0A0B0E"
BG_SOFT = "#0E1014"
SIDEBAR = "#0C0E12"
PANEL = "#10131A"
PANEL_HOVER = "#151A22"
PANEL_ACTIVE = "#18202C"
BORDER = "#232A35"
BORDER_SOFT = "#1A2029"
TEXT = "#D7DDE7"
TEXT_DIM = "#8B95A5"
TEXT_FAINT = "#5C6675"
ACCENT = "#4E8DFF"
ACCENT_SOFT = "#20334F"
OK = "#3FBF87"
WARN = "#E3A33B"
DANGER = "#E2574C"
CRITICAL = "#FF4D4D"

VERDICT_COLORS = {
    "malicious": DANGER,
    "suspicious": WARN,
    "clean": OK,
    "error": TEXT_DIM,
    "skipped": TEXT_FAINT,
}

SEVERITY_COLORS = {
    "critical": CRITICAL,
    "high": DANGER,
    "medium": WARN,
    "low": TEXT_DIM,
}


def pick_font() -> str:
    families = set(QFontDatabase.families())
    for name in ("Segoe UI", "Inter", "SF Pro Display", "Noto Sans", "DejaVu Sans"):
        if name in families:
            return name
    return QApplication.font().family()


def mono_font() -> str:
    families = set(QFontDatabase.families())
    for name in ("Cascadia Mono", "Consolas", "JetBrains Mono", "DejaVu Sans Mono"):
        if name in families:
            return name
    return "monospace"


def rgba(hex_color: str, alpha: float) -> str:
    """'#4E8DFF', 0.2 -> 'rgba(78, 141, 255, 0.2)' — корректный CSS-формат для Qt."""
    color = QColor(hex_color)
    value = max(0.0, min(1.0, alpha))
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {value:.3f})"


def qcolor(hex_color: str, alpha: int | None = None) -> QColor:
    color = QColor(hex_color)
    if alpha is not None:
        color.setAlpha(alpha)
    return color


def build_stylesheet(font: str) -> str:
    return f"""
* {{
    font-family: "{font}";
    outline: none;
}}
QWidget {{
    color: {TEXT};
    font-size: 13px;
}}
QWidget#Root {{
    background-color: {BG};
}}
QFrame#Sidebar {{
    background-color: {SIDEBAR};
    border-right: 1px solid {BORDER_SOFT};
}}
QLabel#BrandMark {{
    color: {TEXT};
    font-size: 20px;
    font-weight: 800;
    letter-spacing: 2px;
}}
QLabel#BrandSub {{
    color: {TEXT_FAINT};
    font-size: 10px;
    letter-spacing: 3px;
}}
QLabel#SidebarSection {{
    color: {TEXT_FAINT};
    font-size: 10px;
    letter-spacing: 2px;
    padding-left: 12px;
}}
QPushButton#NavButton {{
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 8px;
    color: {TEXT_DIM};
    text-align: left;
    padding: 9px 12px 9px 14px;
    font-size: 13px;
    font-style: italic;
}}
QPushButton#NavButton:hover {{
    background-color: {PANEL_HOVER};
    color: {TEXT};
    border: 1px solid {BORDER_SOFT};
}}
QPushButton#NavButton:checked {{
    background-color: {PANEL_ACTIVE};
    color: #FFFFFF;
    border: 1px solid {BORDER};
}}
QPushButton#NavButton:checked {{
    border-left: 2px solid {ACCENT};
}}
QLabel#PageTitle {{
    color: #FFFFFF;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 1px;
}}
QLabel#PageSubtitle {{
    color: {TEXT_FAINT};
    font-size: 12px;
}}
QFrame#Card {{
    background-color: {PANEL};
    border: 1px solid {BORDER_SOFT};
    border-radius: 12px;
}}
QFrame#CardAccent {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
QLabel#CardTitle {{
    color: {TEXT};
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.5px;
}}
QLabel#CardCaption {{
    color: {TEXT_FAINT};
    font-size: 11px;
}}
QLabel#StatValue {{
    color: #FFFFFF;
    font-size: 26px;
    font-weight: 700;
}}
QLabel#Muted {{
    color: {TEXT_DIM};
}}
QLabel#Faint {{
    color: {TEXT_FAINT};
    font-size: 11px;
}}
QPushButton#Primary {{
    background-color: {ACCENT};
    color: #05070B;
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    font-weight: 700;
    letter-spacing: 0.4px;
}}
QPushButton#Primary:hover {{ background-color: #6BA0FF; }}
QPushButton#Primary:pressed {{ background-color: #3F79E0; }}
QPushButton#Primary:disabled {{ background-color: #2A3444; color: {TEXT_FAINT}; }}
QPushButton#Ghost {{
    background-color: transparent;
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 9px 16px;
}}
QPushButton#Ghost:hover {{ background-color: {PANEL_HOVER}; border-color: {ACCENT_SOFT}; }}
QPushButton#Ghost:disabled {{ color: {TEXT_FAINT}; border-color: {BORDER_SOFT}; }}
QPushButton#Danger {{
    background-color: transparent;
    color: {DANGER};
    border: 1px solid #4A2A2C;
    border-radius: 8px;
    padding: 9px 16px;
}}
QPushButton#Danger:hover {{ background-color: #2A1517; border-color: {DANGER}; }}
QPushButton#Tile {{
    background-color: {PANEL};
    border: 1px solid {BORDER_SOFT};
    border-radius: 8px;
    color: {TEXT_DIM};
    padding: 14px 10px;
    font-style: italic;
    font-size: 13px;
    letter-spacing: 0.3px;
}}
QPushButton#Tile:hover {{
    background-color: {PANEL_HOVER};
    border-color: {ACCENT_SOFT};
    color: #FFFFFF;
}}
QPushButton#Tile:disabled {{ color: {TEXT_FAINT}; background-color: {BG_SOFT}; }}
QProgressBar {{
    background-color: {BG_SOFT};
    border: 1px solid {BORDER_SOFT};
    border-radius: 6px;
    height: 12px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 5px;
}}
QTableWidget, QListWidget {{
    background-color: {PANEL};
    border: 1px solid {BORDER_SOFT};
    border-radius: 10px;
    gridline-color: transparent;
    selection-background-color: {PANEL_ACTIVE};
    selection-color: #FFFFFF;
    alternate-background-color: {BG_SOFT};
}}
QTableWidget::item {{
    padding: 6px 8px;
    border-bottom: 1px solid {BORDER_SOFT};
}}
QHeaderView::section {{
    background-color: {BG_SOFT};
    color: {TEXT_FAINT};
    border: none;
    border-bottom: 1px solid {BORDER_SOFT};
    padding: 8px;
    font-size: 11px;
    letter-spacing: 0.6px;
}}
QLineEdit, QComboBox, QSpinBox {{
    background-color: {BG_SOFT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 8px 10px;
    color: {TEXT};
    selection-background-color: {ACCENT};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    selection-background-color: {PANEL_ACTIVE};
    color: {TEXT};
}}
QCheckBox {{ color: {TEXT_DIM}; spacing: 8px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {BORDER};
    border-radius: 4px;
    background-color: {BG_SOFT};
}}
QCheckBox::indicator:checked {{ background-color: {ACCENT}; border-color: {ACCENT}; }}
QScrollBar:vertical {{
    background: transparent; width: 10px; margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: #2A323F; border-radius: 4px; min-height: 28px;
}}
QScrollBar::handle:vertical:hover {{ background: #38414F; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #2A323F; border-radius: 4px; min-width: 28px; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QSplitter::handle {{ background: {BORDER_SOFT}; }}
QToolTip {{
    background-color: {PANEL};
    color: {TEXT};
    border: 1px solid {BORDER};
    padding: 6px;
    border-radius: 6px;
}}
QMenu {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 4px;
}}
QMenu::item {{ padding: 7px 18px; border-radius: 6px; }}
QMenu::item:selected {{ background-color: {PANEL_ACTIVE}; }}
QDialog {{ background-color: {BG}; }}
QPlainTextEdit, QTextEdit {{
    background-color: {BG_SOFT};
    border: 1px solid {BORDER_SOFT};
    border-radius: 10px;
    color: {TEXT};
    font-size: 12px;
    padding: 8px;
}}
QSlider::groove:horizontal {{
    height: 4px; background: {BORDER}; border-radius: 2px;
}}
QSlider::handle:horizontal {{
    background: {ACCENT}; width: 14px; height: 14px; margin: -6px 0; border-radius: 7px;
}}
QLabel#Badge {{
    border-radius: 9px;
    padding: 3px 9px;
    font-size: 11px;
    font-weight: 600;
}}
"""


def apply_theme(app: QApplication) -> str:
    font_family = pick_font()
    font = QFont(font_family)
    font.setPointSize(10)
    font.setHintingPreference(QFont.PreferFullHinting)
    app.setFont(font)
    app.setStyleSheet(build_stylesheet(font_family))

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(BG))
    palette.setColor(QPalette.WindowText, QColor(TEXT))
    palette.setColor(QPalette.Base, QColor(PANEL))
    palette.setColor(QPalette.AlternateBase, QColor(BG_SOFT))
    palette.setColor(QPalette.Text, QColor(TEXT))
    palette.setColor(QPalette.Button, QColor(PANEL))
    palette.setColor(QPalette.ButtonText, QColor(TEXT))
    palette.setColor(QPalette.Highlight, QColor(ACCENT))
    palette.setColor(QPalette.HighlightedText, QColor("#05070B"))
    app.setPalette(palette)
    return font_family
