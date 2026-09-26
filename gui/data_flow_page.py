import logging
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, 
    QTableWidgetItem, QHeaderView, QFrame, QSplitter
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
import qtawesome as qta

from storage.secure_db import SecureDatabase
from gui.theme import COLORS
from gui.widgets import AnimatedButton

logger = logging.getLogger(__name__)


class StatCard(QFrame):
    """Dashboard statistic card displaying a metric with title and icon."""

    def __init__(self, title: str, value: str = "0", color: str = COLORS['ACCENT'], icon_name: str = None, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        header_layout = QHBoxLayout()
        if icon_name:
            icon_lbl = QLabel()
            icon_lbl.setPixmap(qta.icon(icon_name, color=color).pixmap(18, 18))
            header_layout.addWidget(icon_lbl)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 12px; font-weight: bold; border: none;")
        header_layout.addWidget(lbl_title)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        self.lbl_val = QLabel(value)
        self.lbl_val.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold; border: none;")
        self.lbl_val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.lbl_val)

    def set_value(self, val: str):
        self.lbl_val.setText(str(val))


class DataFlowPageWidget(QWidget):
    """
    Feature #18: Data Flow Mapping Widget.
    Provides a dashboard visualizing data transfers between departments and data volume by department.
    """

    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self._init_ui()
        self.load_data()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # --- Top Header Section ---
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        header_icon = QLabel()
        header_icon.setPixmap(qta.icon('fa5s.project-diagram', color=COLORS['ACCENT']).pixmap(28, 28))
        header_layout.addWidget(header_icon)

        title_layout = QVBoxLayout()
        title_lbl = QLabel("خريطة تدفق البيانات (Data Flow Mapping)")
        title_lbl.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        subtitle_lbl = QLabel("رصد حركة البيانات الحساسة وفحوصات الامتثال بين الأقسام (Monitor data transfers and compliance volume by department)")
        subtitle_lbl.setStyleSheet(f"font-size: 12px; color: {COLORS['TEXT_SECONDARY']};")
        title_layout.addWidget(title_lbl)
        title_layout.addWidget(subtitle_lbl)
        header_layout.addLayout(title_layout)

        header_layout.addStretch()

        # Refresh Button
        self.refresh_btn = AnimatedButton("تحديث (Refresh)")
        self.refresh_btn.setIcon(qta.icon('fa5s.sync-alt', color='white'))
        self.refresh_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['BG_BUTTON']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                color: {COLORS['TEXT_PRIMARY']};
                padding: 8px 16px;
                border-radius: 6px;
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
        """)
        self.refresh_btn.clicked.connect(self.load_data)
        header_layout.addWidget(self.refresh_btn)

        main_layout.addLayout(header_layout)

        # --- Stat Cards Section ---
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self.card_total_transfers = StatCard(
            "إجمالي عمليات النقل (Total Transfers)", "0", COLORS['ACCENT'], 'fa5s.exchange-alt'
        )
        self.card_active_routes = StatCard(
            "مسارات النقل النشطة (Active Routes)", "0", COLORS['WARNING'], 'fa5s.route'
        )
        self.card_total_scans = StatCard(
            "إجمالي عمليات الفحص (Total Scans)", "0", COLORS['SUCCESS'], 'fa5s.shield-alt'
        )
        self.card_monitored_depts = StatCard(
            "الأقسام المشمولة (Departments)", "0", COLORS['ACCENT_PURPLE'], 'fa5s.building'
        )

        cards_layout.addWidget(self.card_total_transfers)
        cards_layout.addWidget(self.card_active_routes)
        cards_layout.addWidget(self.card_total_scans)
        cards_layout.addWidget(self.card_monitored_depts)

        main_layout.addLayout(cards_layout)

        # --- Main Splitter (Two Tables) ---
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Table Stylesheet
        table_style = f"""
            QTableWidget {{
                background-color: {COLORS['BG_PANEL']};
                alternate-background-color: {COLORS['BG_MAIN']};
                color: {COLORS['TEXT_PRIMARY']};
                gridline-color: {COLORS['BG_BUTTON']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 6px;
                selection-background-color: {COLORS['ACCENT_PURPLE']};
                selection-color: white;
            }}
            QHeaderView::section {{
                background-color: {COLORS['BG_BUTTON']};
                color: {COLORS['ACCENT']};
                padding: 8px;
                font-weight: bold;
                border: 1px solid {COLORS['ACCENT_PURPLE']};
            }}
            QScrollBar:vertical {{
                background: {COLORS['BG_MAIN']};
                width: 10px;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background: {COLORS['ACCENT_PURPLE']};
                border-radius: 5px;
            }}
        """

        # --- Panel 1: Data Transfers between Departments ---
        panel_transfers = QFrame()
        panel_transfers.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 8px;
            }}
        """)
        layout_transfers = QVBoxLayout(panel_transfers)
        layout_transfers.setContentsMargins(12, 12, 12, 12)
        layout_transfers.setSpacing(10)

        transfers_title_layout = QHBoxLayout()
        icon_transfers = QLabel()
        icon_transfers.setPixmap(qta.icon('fa5s.exchange-alt', color=COLORS['ACCENT']).pixmap(18, 18))
        icon_transfers.setStyleSheet("border: none;")
        transfers_title_layout.addWidget(icon_transfers)

        lbl_transfers_title = QLabel("نقل البيانات بين الأقسام (Data Transfers between Departments)")
        lbl_transfers_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']}; border: none;")
        transfers_title_layout.addWidget(lbl_transfers_title)
        transfers_title_layout.addStretch()
        layout_transfers.addLayout(transfers_title_layout)

        self.transfers_table = QTableWidget()
        self.transfers_table.setColumnCount(3)
        self.transfers_table.setHorizontalHeaderLabels([
            "القسم المصدر (Source Dept)",
            "القسم الهدف (Target Dept)",
            "إجمالي عمليات النقل (Total Transfers)"
        ])
        self.transfers_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.transfers_table.verticalHeader().setVisible(False)
        self.transfers_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.transfers_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.transfers_table.setAlternatingRowColors(True)
        self.transfers_table.setStyleSheet(table_style)
        layout_transfers.addWidget(self.transfers_table)

        splitter.addWidget(panel_transfers)

        # --- Panel 2: Data Volume by Department ---
        panel_scans = QFrame()
        panel_scans.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 8px;
            }}
        """)
        layout_scans = QVBoxLayout(panel_scans)
        layout_scans.setContentsMargins(12, 12, 12, 12)
        layout_scans.setSpacing(10)

        scans_title_layout = QHBoxLayout()
        icon_scans = QLabel()
        icon_scans.setPixmap(qta.icon('fa5s.chart-bar', color=COLORS['SUCCESS']).pixmap(18, 18))
        icon_scans.setStyleSheet("border: none;")
        scans_title_layout.addWidget(icon_scans)

        lbl_scans_title = QLabel("حجم البيانات حسب القسم (Data Volume by Department)")
        lbl_scans_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']}; border: none;")
        scans_title_layout.addWidget(lbl_scans_title)
        scans_title_layout.addStretch()
        layout_scans.addLayout(scans_title_layout)

        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(2)
        self.scans_table.setHorizontalHeaderLabels([
            "القسم (Department)",
            "إجمالي عمليات الفحص (Total Scans)"
        ])
        self.scans_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.scans_table.verticalHeader().setVisible(False)
        self.scans_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.scans_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.scans_table.setAlternatingRowColors(True)
        self.scans_table.setStyleSheet(table_style)
        layout_scans.addWidget(self.scans_table)

        splitter.addWidget(panel_scans)

        # Give equal width to both panels
        splitter.setSizes([500, 500])
        main_layout.addWidget(splitter, stretch=1)

    def load_data(self):
        """Fetch stats from database and update tables and dashboard metric cards."""
        try:
            stats = self.db.get_data_flow_stats()
        except Exception as e:
            logger.error(f"Error fetching data flow stats: {e}")
            stats = {"transfers": [], "scans": []}

        transfers = stats.get("transfers") or []
        scans = stats.get("scans") or []

        # Update Summary Stat Cards
        total_transfer_count = sum(t[2] for t in transfers if len(t) > 2 and isinstance(t[2], (int, float)))
        active_routes_count = len(transfers)
        total_scan_count = sum(s[1] for s in scans if len(s) > 1 and isinstance(s[1], (int, float)))

        dept_names = set()
        for t in transfers:
            if len(t) > 0 and t[0]:
                dept_names.add(str(t[0]))
            if len(t) > 1 and t[1]:
                dept_names.add(str(t[1]))
        for s in scans:
            if len(s) > 0 and s[0]:
                dept_names.add(str(s[0]))

        self.card_total_transfers.set_value(f"{total_transfer_count:,}")
        self.card_active_routes.set_value(str(active_routes_count))
        self.card_total_scans.set_value(f"{total_scan_count:,}")
        self.card_monitored_depts.set_value(str(len(dept_names)))

        # --- Populate Transfers Table ---
        self.transfers_table.clearSpans()
        if not transfers:
            self.transfers_table.setRowCount(1)
            empty_item = QTableWidgetItem("لا توجد عمليات نقل بيانات مسجلة حالياً (No data transfers recorded yet)")
            empty_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_item.setForeground(QColor(COLORS['TEXT_SECONDARY']))
            self.transfers_table.setItem(0, 0, empty_item)
            self.transfers_table.setSpan(0, 0, 1, 3)
        else:
            self.transfers_table.setRowCount(len(transfers))
            for i, row in enumerate(transfers):
                src_name = str(row[0]) if len(row) > 0 and row[0] is not None else "-"
                tgt_name = str(row[1]) if len(row) > 1 and row[1] is not None else "-"
                count = str(row[2]) if len(row) > 2 and row[2] is not None else "0"

                src_item = QTableWidgetItem(src_name)
                src_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                src_item.setIcon(qta.icon('fa5s.building', color=COLORS['TEXT_SECONDARY']))

                tgt_item = QTableWidgetItem(tgt_name)
                tgt_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                tgt_item.setIcon(qta.icon('fa5s.building', color=COLORS['TEXT_SECONDARY']))

                count_item = QTableWidgetItem(count)
                count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                count_font = QFont()
                count_font.setBold(True)
                count_item.setFont(count_font)
                count_item.setForeground(QColor(COLORS['ACCENT']))

                self.transfers_table.setItem(i, 0, src_item)
                self.transfers_table.setItem(i, 1, tgt_item)
                self.transfers_table.setItem(i, 2, count_item)

        # --- Populate Scans Table ---
        self.scans_table.clearSpans()
        if not scans:
            self.scans_table.setRowCount(1)
            empty_item = QTableWidgetItem("لا توجد سجلات فحص للأقسام حالياً (No department scans recorded yet)")
            empty_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_item.setForeground(QColor(COLORS['TEXT_SECONDARY']))
            self.scans_table.setItem(0, 0, empty_item)
            self.scans_table.setSpan(0, 0, 1, 2)
        else:
            self.scans_table.setRowCount(len(scans))
            for i, row in enumerate(scans):
                dept_name = str(row[0]) if len(row) > 0 and row[0] is not None else "-"
                count = str(row[1]) if len(row) > 1 and row[1] is not None else "0"

                dept_item = QTableWidgetItem(dept_name)
                dept_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                dept_item.setIcon(qta.icon('fa5s.folder', color=COLORS['TEXT_SECONDARY']))

                count_item = QTableWidgetItem(count)
                count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                count_font = QFont()
                count_font.setBold(True)
                count_item.setFont(count_font)
                count_item.setForeground(QColor(COLORS['SUCCESS']))

                self.scans_table.setItem(i, 0, dept_item)
                self.scans_table.setItem(i, 1, count_item)
