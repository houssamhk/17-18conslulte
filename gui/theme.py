from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont, QFontDatabase
from PyQt6.QtCore import Qt
import os

# Color Palette
COLORS = {
    "BG_MAIN": "#0b1220",
    "BG_PANEL": "#111c2e",
    "BG_BUTTON": "#1d3553",
    "ACCENT": "#5be0c1",
    "ACCENT_PURPLE": "#29425f",
    "TEXT_PRIMARY": "#e8eff7",
    "TEXT_SECONDARY": "#99a9ba",
    "SUCCESS": "#45c89a",
    "WARNING": "#f3b65d",
    "ERROR": "#f26b78"
}

DARK_STYLESHEET = f"""
QWidget {{
    background-color: {COLORS['BG_MAIN']};
    color: {COLORS['TEXT_PRIMARY']};
    font-size: 13px;
}}

QMainWindow, QDialog {{
    background-color: {COLORS['BG_MAIN']};
}}

QPushButton {{
    background-color: {COLORS['BG_BUTTON']};
    border: 1px solid {COLORS['ACCENT_PURPLE']};
    padding: 8px 16px;
    border-radius: 6px;
    color: {COLORS['TEXT_PRIMARY']};
    font-weight: bold;
}}

QPushButton:hover {{
    background-color: {COLORS['ACCENT_PURPLE']};
    border-color: {COLORS['ACCENT']};
}}

QPushButton:pressed {{
    background-color: {COLORS['ACCENT']};
    color: {COLORS['BG_MAIN']};
}}

QPushButton:disabled {{
    background-color: #2a2a3e;
    color: {COLORS['TEXT_SECONDARY']};
    border-color: #3a3a4e;
}}

QLineEdit, QTextEdit {{
    background-color: {COLORS['BG_PANEL']};
    border: 2px solid {COLORS['BG_BUTTON']};
    border-radius: 4px;
    padding: 8px;
    color: {COLORS['TEXT_PRIMARY']};
    selection-background-color: {COLORS['ACCENT_PURPLE']};
}}

QLineEdit:focus, QTextEdit:focus {{
    border-color: {COLORS['ACCENT']};
}}

QListWidget, QTreeWidget, QTableWidget, QPlainTextEdit {{
    border: 1px solid {COLORS['BG_BUTTON']};
    border-radius: 8px;
    outline: none;
}}

QTableWidget {{
    alternate-background-color: #0e1828;
    gridline-color: #20314a;
    selection-background-color: #235346;
    selection-color: {COLORS['TEXT_PRIMARY']};
}}

QHeaderView::section {{
    border: none;
    border-bottom: 1px solid #29425f;
    padding: 10px 8px;
    font-weight: bold;
}}

QPushButton:focus, QComboBox:focus, QCheckBox:focus {{
    outline: 2px solid {COLORS['ACCENT']};
}}

QTabWidget::pane {{
    border: 1px solid {COLORS['ACCENT_PURPLE']};
    border-radius: 4px;
}}

QTabBar::tab {{
    background-color: {COLORS['BG_MAIN']};
    padding: 8px 16px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    border: 1px solid transparent;
}}

QTabBar::tab:selected {{
    background-color: {COLORS['BG_BUTTON']};
    color: {COLORS['ACCENT']};
    border: 1px solid {COLORS['ACCENT_PURPLE']};
    border-bottom: none;
}}

QProgressBar {{
    border: 1px solid {COLORS['BG_BUTTON']};
    border-radius: 7px;
    min-height: 12px;
    text-align: center;
    background-color: {COLORS['BG_PANEL']};
}}

QProgressBar::chunk {{
    background-color: {COLORS['ACCENT']};
    border-radius: 2px;
}}

QScrollBar:vertical {{
    background: {COLORS['BG_MAIN']};
    width: 12px;
    border-radius: 6px;
    margin: 0px;
}}

QScrollBar::handle:vertical {{
    background: {COLORS['ACCENT_PURPLE']};
    border-radius: 6px;
    min-height: 20px;
    margin: 2px;
}}

QScrollBar::handle:vertical:hover {{
    background: {COLORS['ACCENT']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background: {COLORS['BG_MAIN']};
    height: 12px;
    border-radius: 6px;
}}

QScrollBar::handle:horizontal {{
    background: {COLORS['ACCENT_PURPLE']};
    border-radius: 6px;
    min-width: 20px;
    margin: 2px;
}}

QScrollBar::handle:horizontal:hover {{
    background: {COLORS['ACCENT']};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

QHeaderView::section {{
    background-color: {COLORS['BG_BUTTON']};
    color: {COLORS['ACCENT']};
    padding: 6px;
    border: 1px solid {COLORS['ACCENT_PURPLE']};
}}

QTableWidget {{
    background-color: {COLORS['BG_PANEL']};
    alternate-background-color: {COLORS['BG_MAIN']};
    gridline-color: {COLORS['BG_BUTTON']};
}}

QTableWidget::item {{
    padding: 4px;
}}

QTableWidget::item:selected {{
    background-color: {COLORS['ACCENT_PURPLE']};
}}

QComboBox {{
    background-color: {COLORS['BG_PANEL']};
    border: 2px solid {COLORS['BG_BUTTON']};
    border-radius: 4px;
    padding: 6px;
}}

QComboBox::drop-down {{
    border: none;
}}

QComboBox QAbstractItemView {{
    background-color: {COLORS['BG_PANEL']};
    border: 1px solid {COLORS['ACCENT_PURPLE']};
    selection-background-color: {COLORS['ACCENT_PURPLE']};
}}

QCheckBox {{
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 2px solid {COLORS['BG_BUTTON']};
    background-color: {COLORS['BG_PANEL']};
}}

QCheckBox::indicator:checked {{
    background-color: {COLORS['ACCENT']};
    border-color: {COLORS['ACCENT']};
}}

QGroupBox {{
    border: 1px solid {COLORS['ACCENT_PURPLE']};
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 16px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 5px;
    color: {COLORS['ACCENT']};
}}

QStatusBar {{
    background-color: {COLORS['BG_PANEL']};
    color: {COLORS['TEXT_SECONDARY']};
}}

QMenuBar {{
    background-color: {COLORS['BG_MAIN']};
    border-bottom: 1px solid {COLORS['BG_BUTTON']};
}}

QMenuBar::item {{
    padding: 6px 12px;
    background-color: transparent;
}}

QMenuBar::item:selected {{
    background-color: {COLORS['BG_BUTTON']};
    color: {COLORS['ACCENT']};
}}

QMenu {{
    background-color: {COLORS['BG_PANEL']};
    border: 1px solid {COLORS['ACCENT_PURPLE']};
}}

QMenu::item {{
    padding: 6px 24px 6px 24px;
}}

QMenu::item:selected {{
    background-color: {COLORS['ACCENT_PURPLE']};
}}

QSplitter::handle {{
    background-color: {COLORS['BG_BUTTON']};
    width: 2px;
}}

QLabel {{
    color: {COLORS['TEXT_PRIMARY']};
}}

QToolTip {{
    background-color: {COLORS['BG_PANEL']};
    color: {COLORS['TEXT_PRIMARY']};
    border: 1px solid {COLORS['ACCENT_PURPLE']};
    padding: 4px;
}}

QListWidget {{
    background-color: {COLORS['BG_PANEL']};
    border: 1px solid {COLORS['BG_BUTTON']};
    border-radius: 4px;
}}

QListWidget::item {{
    padding: 6px;
}}

QListWidget::item:selected {{
    background-color: {COLORS['ACCENT_PURPLE']};
}}

QProgressDialog {{
    background-color: {COLORS['BG_MAIN']};
}}
"""

def apply_theme(app: QApplication):
    """Applies the dark theme, RTL layout, and fonts to the application."""
    # 1. Apply Stylesheet
    app.setStyleSheet(DARK_STYLESHEET)
    
    # 2. Global RTL Layout Direction
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    
    # 3. Try loading Arabic fonts with fallback chain
    font_loaded = False
    
    # Try bundled Cairo font first
    cairo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "Cairo-Regular.ttf")
    if os.path.exists(cairo_path):
        font_id = QFontDatabase.addApplicationFont(cairo_path)
        if font_id != -1:
            families = QFontDatabase.applicationFontFamilies(font_id)
            if families:
                app.setFont(QFont(families[0], 10))
                font_loaded = True
    
    if not font_loaded:
        # Fallback chain: try system Arabic fonts
        for font_name in ["Cairo", "Amiri", "Simplified Arabic", "Segoe UI"]:
            font = QFont(font_name, 10)
            if font.exactMatch() or font_name == "Segoe UI":  # Segoe UI is always available on Windows
                app.setFont(font)
                break
