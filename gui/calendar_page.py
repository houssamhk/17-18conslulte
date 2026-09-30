"""
Compliance Calendar Page (Feature #21: Compliance Calendar).
Displays regulatory and compliance deadlines (DSAR SLAs, Incident SLAs) in a dark-themed RTL calendar view with an associated deadlines table.
"""

import logging
import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QCalendarWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QLineEdit, QComboBox,
    QFrame, QDialog, QFormLayout, QDialogButtonBox,
    QSizePolicy, QAbstractItemView
)
from PyQt6.QtCore import Qt, QDate, QTime
from PyQt6.QtGui import QTextCharFormat, QColor, QFont
import qtawesome as qta

from storage.secure_db import SecureDatabase
from gui.theme import COLORS
from gui.widgets import AnimatedButton
from .dialog_utils import configure_dialog_size

logger = logging.getLogger(__name__)


class CalendarStatCard(QFrame):
    """Metric card showing summary counts with icons and bilingual labels."""

    def __init__(self, title: str, value: str = "0", color: str = COLORS['ACCENT'], icon_name: str = None, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 8px;
                padding: 8px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        header_layout = QHBoxLayout()
        if icon_name:
            icon_lbl = QLabel()
            icon_lbl.setPixmap(qta.icon(icon_name, color=color).pixmap(18, 18))
            header_layout.addWidget(icon_lbl)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 11px; font-weight: bold; border: none;")
        header_layout.addWidget(lbl_title)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        self.lbl_val = QLabel(value)
        self.lbl_val.setStyleSheet(f"color: {color}; font-size: 22px; font-weight: bold; border: none;")
        self.lbl_val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.lbl_val)

    def set_value(self, val: str):
        self.lbl_val.setText(str(val))


class DeadlineDetailsDialog(QDialog):
    """Modal dialog displaying comprehensive details about a compliance deadline."""

    def __init__(self, deadline: dict, parent=None):
        super().__init__(parent)
        self.deadline = deadline
        self.setWindowTitle("تفاصيل الموعد النهائي (Deadline Details)")
        configure_dialog_size(self, preferred=(680, 520), minimum=(480, 360))
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['BG_MAIN']};
                color: {COLORS['TEXT_PRIMARY']};
            }}
            QLabel {{
                color: {COLORS['TEXT_PRIMARY']};
                font-size: 13px;
            }}
            QLineEdit, QTextEdit {{
                background-color: {COLORS['BG_PANEL']};
                color: {COLORS['TEXT_PRIMARY']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 4px;
                padding: 6px;
            }}
            QPushButton {{
                background-color: {COLORS['BG_BUTTON']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                color: white;
                padding: 8px 18px;
                border-radius: 6px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['ACCENT_PURPLE']};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Dialog Title Header
        header_layout = QHBoxLayout()
        icon_name = 'fa5s.user-shield' if deadline.get('type') == 'DSAR' else 'fa5s.exclamation-triangle'
        icon_color = COLORS['ACCENT_PURPLE'] if deadline.get('type') == 'DSAR' else COLORS['ACCENT']
        
        icon_lbl = QLabel()
        icon_lbl.setPixmap(qta.icon(icon_name, color=icon_color).pixmap(24, 24))
        header_layout.addWidget(icon_lbl)

        dlg_title = QLabel("معلومات الموعد والالتزام القانوني (Deadline & SLA Information)")
        dlg_title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        header_layout.addWidget(dlg_title)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Form Layout
        form_frame = QFrame()
        form_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 6px;
                padding: 10px;
            }}
        """)
        form_layout = QFormLayout(form_frame)
        form_layout.setSpacing(10)

        # Title
        title_val = QLabel(deadline.get("title", "—"))
        title_val.setStyleSheet("font-weight: bold;")
        title_val.setWordWrap(True)
        form_layout.addRow("العنوان (Title):", title_val)

        # Type
        type_val = deadline.get("type", "—")
        type_label = "طلب وصول بيانات DSAR (DSAR Access Request)" if type_val == "DSAR" else "حادث بيانات أمني (Data Incident SLA)"
        lbl_type = QLabel(type_label)
        lbl_type.setStyleSheet(f"color: {icon_color}; font-weight: bold;")
        form_layout.addRow("النوع (Type):", lbl_type)

        # Deadline Date
        date_str = str(deadline.get("date", "—"))
        lbl_date = QLabel(date_str)
        lbl_date.setStyleSheet(f"font-weight: bold; color: {COLORS['WARNING']};")
        form_layout.addRow("تاريخ الاستحقاق (Deadline):", lbl_date)

        # Status
        status_str = str(deadline.get("status", "OPEN")).upper()
        lbl_status = QLabel(status_str)
        status_color = COLORS['SUCCESS'] if status_str in ("CLOSED", "RESOLVED") else COLORS['WARNING']
        lbl_status.setStyleSheet(f"color: {status_color}; font-weight: bold;")
        form_layout.addRow("الحالة (Status):", lbl_status)

        layout.addWidget(form_frame)

        # Close Button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("إغلاق (Close)")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)


class CalendarPageWidget(QWidget):
    """
    Feature #21: Compliance Calendar Widget.
    Provides an RTL dark-themed compliance calendar tracking legal SLA deadlines
    for DSAR requests and Security Incidents.
    """

    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)

        # Current calendar tracking state
        today = QDate.currentDate()
        self.current_year = today.year()
        self.current_month = today.month()
        self.month_deadlines = []
        self._formatted_dates = []

        self._init_ui()
        self.load_month_data(self.current_year, self.current_month)

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(12)

        # --- 1. Top Header Banner ---
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(qta.icon('fa5s.calendar-alt', color=COLORS['ACCENT']).pixmap(28, 28))
        header_layout.addWidget(icon_lbl)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)
        title_lbl = QLabel("تقويم الامتثال والمواعيد النهائية (Compliance Calendar)")
        title_lbl.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        subtitle_lbl = QLabel(
            "متابعة المواعيد القانونية والتنظيمية لطلبات DSAR وحوادث أمن البيانات (Track legal deadlines for DSAR and Incidents)"
        )
        subtitle_lbl.setStyleSheet(f"font-size: 12px; color: {COLORS['TEXT_SECONDARY']};")
        title_layout.addWidget(title_lbl)
        title_layout.addWidget(subtitle_lbl)
        header_layout.addLayout(title_layout)

        header_layout.addStretch()

        # Action Buttons: Today & Refresh
        self.btn_today = AnimatedButton("اليوم (Today)")
        self.btn_today.setIcon(qta.icon('fa5s.calendar-day', color='white'))
        self.btn_today.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['BG_BUTTON']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                color: {COLORS['TEXT_PRIMARY']};
                padding: 7px 14px;
                border-radius: 6px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['ACCENT_PURPLE']};
                border-color: {COLORS['ACCENT']};
            }}
        """)
        self.btn_today.clicked.connect(self.go_to_today)
        header_layout.addWidget(self.btn_today)

        self.btn_refresh = AnimatedButton("تحديث (Refresh)")
        self.btn_refresh.setIcon(qta.icon('fa5s.sync-alt', color='white'))
        self.btn_refresh.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['BG_BUTTON']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                color: {COLORS['TEXT_PRIMARY']};
                padding: 7px 14px;
                border-radius: 6px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['ACCENT_PURPLE']};
                border-color: {COLORS['ACCENT']};
            }}
        """)
        self.btn_refresh.clicked.connect(self.reload_data)
        header_layout.addWidget(self.btn_refresh)

        main_layout.addLayout(header_layout)

        # --- 2. KPI Summary Cards ---
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)

        self.card_total = CalendarStatCard(
            "إجمالي مواعيد الشهر (Total This Month)", "0", COLORS['ACCENT'], 'fa5s.calendar-check'
        )
        self.card_dsar = CalendarStatCard(
            "طلبات وصول البيانات (DSAR SLAs)", "0", COLORS['ACCENT_PURPLE'], 'fa5s.user-shield'
        )
        self.card_incidents = CalendarStatCard(
            "حوادث البيانات (Incident SLAs)", "0", COLORS['WARNING'], 'fa5s.exclamation-triangle'
        )
        self.card_selected_date = CalendarStatCard(
            "مواعيد اليوم المحدد (Selected Date)", "0", COLORS['SUCCESS'], 'fa5s.clock'
        )

        cards_layout.addWidget(self.card_total)
        cards_layout.addWidget(self.card_dsar)
        cards_layout.addWidget(self.card_incidents)
        cards_layout.addWidget(self.card_selected_date)
        main_layout.addLayout(cards_layout)

        # --- 3. Dark-Themed QCalendarWidget ---
        self.calendar = QCalendarWidget(self)
        self.calendar.setGridVisible(True)
        self.calendar.setVerticalHeaderFormat(QCalendarWidget.VerticalHeaderFormat.NoVerticalHeader)
        self.calendar.setHorizontalHeaderFormat(QCalendarWidget.HorizontalHeaderFormat.ShortDayNames)
        self.calendar.setFirstDayOfWeek(Qt.DayOfWeek.Saturday)
        self.calendar.setFixedHeight(275)

        # CSS Dark Styling for QCalendarWidget
        self.calendar.setStyleSheet(f"""
            QCalendarWidget {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 8px;
                color: {COLORS['TEXT_PRIMARY']};
            }}
            QCalendarWidget QWidget#qt_calendar_navigationbar {{
                background-color: {COLORS['BG_BUTTON']};
                border-bottom: 2px solid {COLORS['ACCENT_PURPLE']};
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                min-height: 42px;
            }}
            QCalendarWidget QToolButton {{
                color: {COLORS['TEXT_PRIMARY']};
                background-color: transparent;
                font-size: 13px;
                font-weight: bold;
                border-radius: 4px;
                margin: 3px;
                padding: 4px 8px;
            }}
            QCalendarWidget QToolButton:hover {{
                background-color: {COLORS['ACCENT_PURPLE']};
                color: #ffffff;
            }}
            QCalendarWidget QToolButton:pressed {{
                background-color: {COLORS['ACCENT']};
                color: #ffffff;
            }}
            QCalendarWidget QMenu {{
                background-color: {COLORS['BG_PANEL']};
                color: {COLORS['TEXT_PRIMARY']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                padding: 4px;
            }}
            QCalendarWidget QMenu::item:selected {{
                background-color: {COLORS['ACCENT_PURPLE']};
                color: #ffffff;
            }}
            QCalendarWidget QSpinBox {{
                background-color: {COLORS['BG_MAIN']};
                color: {COLORS['TEXT_PRIMARY']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 4px;
                padding: 3px 6px;
                font-size: 13px;
                selection-background-color: {COLORS['ACCENT_PURPLE']};
            }}
            QCalendarWidget QTableView {{
                background-color: {COLORS['BG_MAIN']};
                alternate-background-color: {COLORS['BG_PANEL']};
                selection-background-color: {COLORS['ACCENT']};
                selection-color: #ffffff;
                gridline-color: #252b48;
                border: none;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
                outline: none;
            }}
            QCalendarWidget QTableView QHeaderView::section {{
                background-color: {COLORS['BG_PANEL']};
                color: {COLORS['ACCENT']};
                font-weight: bold;
                font-size: 12px;
                padding: 6px;
                border: none;
                border-bottom: 1px solid {COLORS['ACCENT_PURPLE']};
            }}
            QCalendarWidget QAbstractItemView:enabled {{
                color: {COLORS['TEXT_PRIMARY']};
                font-size: 13px;
            }}
            QCalendarWidget QAbstractItemView:disabled {{
                color: #55556d;
            }}
        """)

        # Connect calendar signals
        self.calendar.currentPageChanged.connect(self.on_month_changed)
        self.calendar.selectionChanged.connect(self.on_date_selected)
        main_layout.addWidget(self.calendar)

        # --- 4. Deadlines Table Filter & Control Bar ---
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(10)

        self.lbl_table_header = QLabel("المواعيد النهائية (Deadlines)")
        self.lbl_table_header.setStyleSheet(
            f"font-size: 14px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};"
        )
        filter_bar.addWidget(self.lbl_table_header)

        filter_bar.addStretch()

        # View Mode Selector: Selected Date vs All Month
        lbl_mode = QLabel("عرض (View):")
        lbl_mode.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 12px;")
        filter_bar.addWidget(lbl_mode)

        self.mode_combo = QComboBox()
        self.mode_combo.addItem("مواعيد اليوم المحدد (Selected Date)", "DATE")
        self.mode_combo.addItem("جميع مواعيد الشهر (All Month)", "MONTH")
        self.mode_combo.currentIndexChanged.connect(self.filter_and_display_deadlines)
        filter_bar.addWidget(self.mode_combo)

        # Type Filter: All / DSAR / Incident
        lbl_type = QLabel("النوع (Type):")
        lbl_type.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 12px;")
        filter_bar.addWidget(lbl_type)

        self.type_combo = QComboBox()
        self.type_combo.addItem("الكل (All)", "ALL")
        self.type_combo.addItem("طلبات DSAR (DSAR)", "DSAR")
        self.type_combo.addItem("الحوادث (Incidents)", "Incident")
        self.type_combo.currentIndexChanged.connect(self.filter_and_display_deadlines)
        filter_bar.addWidget(self.type_combo)

        # Search Box
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("بحث في المواعيد... (Search...)")
        self.search_input.setFixedWidth(200)
        self.search_input.textChanged.connect(self.filter_and_display_deadlines)
        filter_bar.addWidget(self.search_input)

        main_layout.addLayout(filter_bar)

        # --- 5. QTableWidget for Deadlines ---
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([
            "العنوان (Title)",
            "تاريخ الاستحقاق (Date)",
            "الحالة (Status)",
            "النوع (Type)"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)

        self.table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['BG_PANEL']};
                alternate-background-color: {COLORS['BG_MAIN']};
                color: {COLORS['TEXT_PRIMARY']};
                gridline-color: {COLORS['BG_BUTTON']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 6px;
                selection-background-color: {COLORS['ACCENT_PURPLE']};
            }}
            QHeaderView::section {{
                background-color: {COLORS['BG_BUTTON']};
                color: {COLORS['ACCENT']};
                padding: 6px;
                font-weight: bold;
                border: 1px solid {COLORS['ACCENT_PURPLE']};
            }}
            QTableWidget::item {{
                padding: 6px;
            }}
        """)

        self.table.cellDoubleClicked.connect(self._on_table_row_double_clicked)
        main_layout.addWidget(self.table, stretch=1)

    # --- Data Loading & Synchronization ---

    def load_month_data(self, year: int, month: int):
        """Fetches calendar deadlines for the specified month and year."""
        self.current_year = year
        self.current_month = month
        try:
            if self.db:
                self.month_deadlines = self.db.get_calendar_deadlines(month, year) or []
            else:
                self.month_deadlines = []
        except Exception as e:
            logger.error(f"Error loading calendar deadlines: {e}")
            self.month_deadlines = []

        self._update_calendar_highlighting()
        self._update_stats()
        self.filter_and_display_deadlines()

    def reload_data(self):
        """Refreshes the current month data."""
        self.load_month_data(self.current_year, self.current_month)

    def go_to_today(self):
        """Jumps the calendar selection and page to today's date."""
        today = QDate.currentDate()
        self.calendar.setCurrentPage(today.year(), today.month())
        self.calendar.setSelectedDate(today)
        self.on_date_selected()

    def on_month_changed(self, year: int, month: int):
        """Handles month navigation from the QCalendarWidget navigation bar."""
        if year != self.current_year or month != self.current_month:
            self.load_month_data(year, month)

    def on_date_selected(self):
        """Handles user clicking/selecting a date on the calendar."""
        sel_date = self.calendar.selectedDate()
        if sel_date.year() != self.current_year or sel_date.month() != self.current_month:
            self.load_month_data(sel_date.year(), sel_date.month())
        else:
            self._update_stats()
            self.filter_and_display_deadlines()

    # --- Calendar Highlighting ---

    def _update_calendar_highlighting(self):
        """Highlights calendar dates that have deadlines using QTextCharFormat."""
        # Clear previous formats
        for d in self._formatted_dates:
            self.calendar.setDateTextFormat(d, QTextCharFormat())
        self._formatted_dates.clear()

        # Group deadlines by ISO date (YYYY-MM-DD)
        dates_map = {}
        for item in self.month_deadlines:
            d_str = self._extract_date_str(item.get("date"))
            if d_str:
                dates_map.setdefault(d_str, []).append(item)

        for d_str, items in dates_map.items():
            qdate = QDate.fromString(d_str, "yyyy-MM-dd")
            if qdate.isValid():
                fmt = QTextCharFormat()
                has_overdue = any(self._is_overdue(it.get("date"), it.get("status")) for it in items)
                if has_overdue:
                    fmt.setBackground(QColor(COLORS['ERROR']))
                else:
                    fmt.setBackground(QColor(COLORS['ACCENT_PURPLE']))
                fmt.setForeground(QColor("#ffffff"))
                fmt.setFontWeight(QFont.Weight.Bold)

                tooltip_lines = [
                    f"• [{it.get('type')}] {it.get('title')} ({it.get('status')})"
                    for it in items
                ]
                fmt.setToolTip(f"{len(items)} مواعيد نهائية (Deadlines):\n" + "\n".join(tooltip_lines))

                self.calendar.setDateTextFormat(qdate, fmt)
                self._formatted_dates.append(qdate)

    # --- KPI Stats Calculation ---

    def _update_stats(self):
        """Recalculates and updates top metric cards."""
        total_count = len(self.month_deadlines)
        dsar_count = sum(1 for d in self.month_deadlines if d.get("type") == "DSAR")
        incidents_count = sum(1 for d in self.month_deadlines if d.get("type") == "Incident")

        sel_date_str = self.calendar.selectedDate().toString("yyyy-MM-dd")
        sel_count = sum(
            1 for d in self.month_deadlines
            if self._extract_date_str(d.get("date")) == sel_date_str
        )

        self.card_total.set_value(str(total_count))
        self.card_dsar.set_value(str(dsar_count))
        self.card_incidents.set_value(str(incidents_count))
        self.card_selected_date.set_value(str(sel_count))

    # --- Table Filtering & Population ---

    def filter_and_display_deadlines(self):
        """Filters the cached deadlines by date, type, and search keyword, and populates the table."""
        view_mode = self.mode_combo.currentData()
        type_filter = self.type_combo.currentData()
        search_kw = self.search_input.text().strip().lower()
        sel_date_str = self.calendar.selectedDate().toString("yyyy-MM-dd")

        filtered = []
        for item in self.month_deadlines:
            # 1. Date Filter
            item_date_str = self._extract_date_str(item.get("date"))
            if view_mode == "DATE" and item_date_str != sel_date_str:
                continue

            # 2. Type Filter
            if type_filter != "ALL" and item.get("type") != type_filter:
                continue

            # 3. Search Filter
            if search_kw:
                title = str(item.get("title", "")).lower()
                status = str(item.get("status", "")).lower()
                if search_kw not in title and search_kw not in status:
                    continue

            filtered.append(item)

        # Sort filtered deadlines by date
        filtered.sort(key=lambda x: str(x.get("date", "")))
        self._current_filtered = filtered

        # Update Table Header Label
        if view_mode == "DATE":
            self.lbl_table_header.setText(
                f"المواعيد لتاريخ {sel_date_str} ({len(filtered)}) — Deadlines for {sel_date_str} ({len(filtered)})"
            )
        else:
            self.lbl_table_header.setText(
                f"جميع مواعيد شهر {self.current_month:02d}/{self.current_year} ({len(filtered)}) — All Deadlines for Month ({len(filtered)})"
            )

        # Populate QTableWidget
        self.table.setRowCount(0)
        for row_idx, item in enumerate(filtered):
            self.table.insertRow(row_idx)

            # 1. Title
            title_text = str(item.get("title", "—"))
            item_title = QTableWidgetItem(title_text)
            if item.get("type") == "DSAR":
                item_title.setIcon(qta.icon('fa5s.user-shield', color=COLORS['ACCENT_PURPLE']))
            else:
                item_title.setIcon(qta.icon('fa5s.exclamation-triangle', color=COLORS['ACCENT']))
            self.table.setItem(row_idx, 0, item_title)

            # 2. Date
            raw_date = str(item.get("date", "—"))
            is_overdue = self._is_overdue(raw_date, item.get("status"))
            display_date = raw_date
            if is_overdue:
                display_date = f"⚠️ {raw_date} (متأخر / Overdue)"
            item_date = QTableWidgetItem(display_date)
            if is_overdue:
                item_date.setForeground(QColor(COLORS['ERROR']))
            self.table.setItem(row_idx, 1, item_date)

            # 3. Status
            status_val = str(item.get("status", "OPEN")).upper()
            item_status = QTableWidgetItem(status_val)
            if status_val in ("CLOSED", "RESOLVED"):
                item_status.setForeground(QColor(COLORS['SUCCESS']))
            elif status_val == "CRITICAL":
                item_status.setForeground(QColor(COLORS['ERROR']))
            else:
                item_status.setForeground(QColor(COLORS['WARNING']))
            self.table.setItem(row_idx, 2, item_status)

            # 4. Type
            type_val = item.get("type", "—")
            type_label = "طلب DSAR (DSAR)" if type_val == "DSAR" else "حادث (Incident)"
            item_type = QTableWidgetItem(type_label)
            if type_val == "DSAR":
                item_type.setForeground(QColor(COLORS['ACCENT_PURPLE']))
            else:
                item_type.setForeground(QColor(COLORS['ACCENT']))
            self.table.setItem(row_idx, 3, item_type)

    def _on_table_row_double_clicked(self, row: int, col: int):
        """Opens detailed modal when double-clicking a deadline row."""
        if hasattr(self, '_current_filtered') and 0 <= row < len(self._current_filtered):
            dlg = DeadlineDetailsDialog(self._current_filtered[row], self)
            dlg.exec()

    # --- Utility Helpers ---

    @staticmethod
    def _extract_date_str(date_val) -> str:
        """Extracts YYYY-MM-DD from various date string formats."""
        if not date_val:
            return ""
        clean = str(date_val).replace("T", " ").strip()
        return clean.split(" ")[0].strip()

    @staticmethod
    def _is_overdue(date_str: str, status: str) -> bool:
        """Checks if a deadline has passed and is still open."""
        if not date_str:
            return False
        if str(status).upper() in ("CLOSED", "RESOLVED", "COMPLETED", "DONE"):
            return False
        try:
            clean = str(date_str).replace("T", " ").split(".")[0].strip()
            if " " in clean:
                dt = datetime.datetime.strptime(clean, "%Y-%m-%d %H:%M:%S")
            else:
                dt = datetime.datetime.strptime(clean, "%Y-%m-%d")
            return dt < datetime.datetime.now()
        except Exception:
            return False
