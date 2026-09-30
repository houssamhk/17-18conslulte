"""
Transfer Page Widget for Alg-PII Engine
Feature #28: Secure Inter-Department Document Transfer

Provides an administrative register for inter-department transfer requests. It does not
redact or move files; those actions must be completed and verified separately.
"""

import logging
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QFrame, QComboBox,
    QLineEdit, QTextEdit, QMessageBox, QGridLayout,
    QSizePolicy, QPushButton
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
import qtawesome as qta

from storage.secure_db import SecureDatabase
from gui.theme import COLORS
from gui.widgets import AnimatedButton

logger = logging.getLogger(__name__)


class TransferStatCard(QFrame):
    """Statistic card showing transfer metrics."""

    def __init__(self, title: str, value: str = "0", color: str = COLORS['ACCENT'], icon_name: str = None, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        header_layout = QHBoxLayout()
        if icon_name:
            icon_lbl = QLabel()
            icon_lbl.setPixmap(qta.icon(icon_name, color=color).pixmap(16, 16))
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


class TransferPageWidget(QWidget):
    """
    Feature #28: Secure Inter-Department Document Transfer Widget.

    Allows users to request transfers of scanned documents to target departments
    with a requested masking strategy and monitor approval status. This page does not
    create an anonymized artifact or move documents.
    """

    def __init__(self, db: SecureDatabase, current_department_id: int = None, current_username: str = None, parent=None):
        super().__init__(parent)
        self.db = db
        self.current_username = current_username or "admin"
        self._departments_cache = []

        # Resolve department ID if passed as a string name or int
        self.current_department_id = self._resolve_department_id(current_department_id)

        self._ensure_default_departments()
        self._init_ui()
        self.refresh_all()

    def _resolve_department_id(self, dept_val) -> int:
        """Resolve department parameter to an integer ID or None."""
        if dept_val is None:
            return None
        if isinstance(dept_val, int):
            return dept_val
        if isinstance(dept_val, str):
            depts = self.db.get_departments()
            for d_id, name, _ in depts:
                if name.strip().lower() == dept_val.strip().lower():
                    return d_id
        return None

    def _ensure_default_departments(self):
        """Seed default departments if none exist in the system."""
        try:
            depts = self.db.get_departments()
            if not depts:
                defaults = [
                    ("الموارد البشرية (HR)", "إدارة الموارد البشرية والتوظيف"),
                    ("المالية والمحاسبة (Finance)", "إدارة العمليات المالية والمحاسبية"),
                    ("الشؤون القانونية (Legal)", "الاستشارات والامتثال القانوني والقضائي"),
                    ("تكنولوجيا المعلومات (IT)", "إدارة النظم والأمن السيبراني")
                ]
                for name, desc in defaults:
                    self.db.save_department(name, desc)
        except Exception as e:
            logger.error(f"Error checking default departments: {e}")

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)

        # 1. Header Section
        header_layout = QHBoxLayout()
        header_left = QVBoxLayout()

        title_lbl = QLabel("طلبات نقل المستندات بين الأقسام (Inter-Department Transfer Requests)")
        title_lbl.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        subtitle_lbl = QLabel("تسجيل الطلب ومتابعة الموافقة فقط. هذه الشاشة لا تعمّي الملفات ولا تنقلها؛ نفّذ التعتيم وتحقق منه ثم انقل الملف المعالج عبر قناة آمنة.")
        subtitle_lbl.setStyleSheet(f"font-size: 12px; color: {COLORS['TEXT_SECONDARY']};")

        header_left.addWidget(title_lbl)
        header_left.addWidget(subtitle_lbl)
        header_layout.addLayout(header_left)
        header_layout.addStretch()

        self.btn_refresh = QPushButton("تحديث (Refresh)")
        self.btn_refresh.setIcon(qta.icon('fa5s.sync-alt', color=COLORS['TEXT_PRIMARY']))
        self.btn_refresh.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['BG_BUTTON']};
                color: {COLORS['TEXT_PRIMARY']};
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['ACCENT_PURPLE']};
            }}
        """)
        self.btn_refresh.clicked.connect(self.refresh_all)
        header_layout.addWidget(self.btn_refresh)
        main_layout.addLayout(header_layout)

        # 2. Stat Cards Row
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)

        self.card_total = TransferStatCard("إجمالي الطلبات (Total Requests)", "0", COLORS['ACCENT'], 'fa5s.exchange-alt')
        self.card_pending = TransferStatCard("قيد الانتظار (Pending)", "0", COLORS['WARNING'], 'fa5s.clock')
        self.card_approved = TransferStatCard("تمت الموافقة (Approved)", "0", COLORS['SUCCESS'], 'fa5s.check-circle')
        self.card_rejected = TransferStatCard("مرفوضة (Rejected)", "0", COLORS['ERROR'], 'fa5s.times-circle')

        stats_layout.addWidget(self.card_total)
        stats_layout.addWidget(self.card_pending)
        stats_layout.addWidget(self.card_approved)
        stats_layout.addWidget(self.card_rejected)
        main_layout.addLayout(stats_layout)

        # 3. Transfer Request Form (Card Frame)
        form_card = QFrame()
        form_card.setStyleSheet(f"""
            QFrame#TransferFormCard {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 8px;
            }}
        """)
        form_card.setObjectName("TransferFormCard")
        form_layout = QVBoxLayout(form_card)
        form_layout.setContentsMargins(15, 12, 15, 15)
        form_layout.setSpacing(10)

        # Form Header
        form_header = QHBoxLayout()
        form_icon = QLabel()
        form_icon.setPixmap(qta.icon('fa5s.file-export', color=COLORS['ACCENT']).pixmap(18, 18))
        form_title = QLabel("طلب نقل مستند جديد (New Document Transfer Request)")
        form_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        form_header.addWidget(form_icon)
        form_header.addWidget(form_title)
        form_header.addStretch()
        form_layout.addLayout(form_header)

        workflow_note = QLabel(
            "تنبيه سير العمل: اختيار الاستراتيجية يسجل النية فقط. الموافقة لا تنشئ نسخة معماة ولا تنقل ملفًا. "
            "يجب تنفيذ التعتيم والتحقق من الناتج خارج هذه الشاشة قبل مشاركته."
        )
        workflow_note.setWordWrap(True)
        workflow_note.setStyleSheet(
            f"color: {COLORS['WARNING']}; background-color: {COLORS['BG_MAIN']}; "
            "border-radius: 6px; padding: 8px;"
        )
        form_layout.addWidget(workflow_note)

        # Form Inputs Grid
        grid = QGridLayout()
        grid.setHorizontalSpacing(15)
        grid.setVerticalSpacing(10)

        # Row 0: Source Department & Target Department
        lbl_source_dept = QLabel("القسم المصدر (Source Department):")
        lbl_source_dept.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-weight: bold;")
        self.source_dept_combo = QComboBox()
        self.source_dept_combo.setStyleSheet(self._combo_style())

        lbl_target_dept = QLabel("القسم الوجهة (Target Department):")
        lbl_target_dept.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-weight: bold;")
        self.target_dept_combo = QComboBox()
        self.target_dept_combo.setStyleSheet(self._combo_style())

        grid.addWidget(lbl_source_dept, 0, 0)
        grid.addWidget(self.source_dept_combo, 0, 1)
        grid.addWidget(lbl_target_dept, 0, 2)
        grid.addWidget(self.target_dept_combo, 0, 3)

        # Row 1: Source Scan ID & Strategy
        lbl_scan = QLabel("معرف الفحص (Source Scan ID):")
        lbl_scan.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-weight: bold;")

        scan_input_box = QHBoxLayout()
        scan_input_box.setSpacing(6)
        self.scan_id_input = QLineEdit()
        self.scan_id_input.setPlaceholderText("معرف الفحص (Scan ID e.g. 1)")
        self.scan_id_input.setFixedWidth(110)
        self.scan_id_input.setStyleSheet(self._line_edit_style())

        self.scan_combo = QComboBox()
        self.scan_combo.setStyleSheet(self._combo_style())
        self.scan_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.scan_combo.currentIndexChanged.connect(self._on_scan_combo_changed)

        scan_input_box.addWidget(self.scan_id_input)
        scan_input_box.addWidget(self.scan_combo)

        lbl_strategy = QLabel("استراتيجية التعتيم المطلوبة (Requested Strategy):")
        lbl_strategy.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-weight: bold;")
        self.strategy_combo = QComboBox()
        self.strategy_combo.setStyleSheet(self._combo_style())
        self.strategy_combo.addItem("تعتيم قانوني (Legal Mask)", "Legal Mask")
        self.strategy_combo.addItem("تعتيم كامل (Full Mask)", "Full Mask")

        grid.addWidget(lbl_scan, 1, 0)
        grid.addLayout(scan_input_box, 1, 1)
        grid.addWidget(lbl_strategy, 1, 2)
        grid.addWidget(self.strategy_combo, 1, 3)

        # Row 2: Transfer Reason (spans columns 1 to 3)
        lbl_reason = QLabel("سبب النقل والغرض (Transfer Reason):")
        lbl_reason.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-weight: bold;")
        self.reason_edit = QTextEdit()
        self.reason_edit.setPlaceholderText("اكتب مبررات النقل وسياق الاستخدام المأذون به بين القسمين... (Reason & context)")
        self.reason_edit.setMaximumHeight(65)
        self.reason_edit.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['BG_MAIN']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 4px;
                padding: 6px;
                color: {COLORS['TEXT_PRIMARY']};
            }}
            QTextEdit:focus {{
                border-color: {COLORS['ACCENT']};
            }}
        """)

        grid.addWidget(lbl_reason, 2, 0, Qt.AlignmentFlag.AlignTop)
        grid.addWidget(self.reason_edit, 2, 1, 1, 3)

        form_layout.addLayout(grid)

        # Form Submit Button
        btn_box = QHBoxLayout()
        btn_box.addStretch()

        self.btn_send = AnimatedButton("إرسال طلب النقل (Send Transfer Request)", primary=True)
        self.btn_send.setIcon(qta.icon('fa5s.paper-plane', color='white'))
        self.btn_send.setFixedHeight(36)
        self.btn_send.setMinimumWidth(260)
        self.btn_send.clicked.connect(self.on_send_transfer)

        btn_box.addWidget(self.btn_send)
        form_layout.addLayout(btn_box)

        main_layout.addWidget(form_card)

        # 4. Transfer History Table Header
        table_header_layout = QHBoxLayout()
        table_title = QLabel("سجل عمليات النقل بين الأقسام (Transfer History)")
        table_title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        table_header_layout.addWidget(table_title)

        table_header_layout.addStretch()

        self.filter_status_combo = QComboBox()
        self.filter_status_combo.setStyleSheet(self._combo_style())
        self.filter_status_combo.addItems([
            "جميع الحالات (All Statuses)",
            "قيد الانتظار (PENDING)",
            "تمت الموافقة (APPROVED)",
            "مرفوض (REJECTED)"
        ])
        self.filter_status_combo.currentIndexChanged.connect(self.apply_table_filter)
        table_header_layout.addWidget(self.filter_status_combo)

        main_layout.addLayout(table_header_layout)

        # 5. History Table
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels([
            "المعرف (ID)",
            "القسم المصدر (Source Dept)",
            "القسم الوجهة (Target Dept)",
            "معرف الفحص (Scan ID)",
            "الاستراتيجية (Strategy)",
            "سبب النقل (Reason)",
            "الحالة (Status)",
            "التاريخ (Date)",
            "الإجراء (Action)"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)

        self.table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['BG_PANEL']};
                alternate-background-color: {COLORS['BG_MAIN']};
                color: {COLORS['TEXT_PRIMARY']};
                gridline-color: {COLORS['BG_BUTTON']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 6px;
            }}
            QHeaderView::section {{
                background-color: {COLORS['BG_BUTTON']};
                color: {COLORS['TEXT_PRIMARY']};
                padding: 6px;
                font-weight: bold;
                border: 1px solid {COLORS['BG_PANEL']};
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['ACCENT_PURPLE']};
                color: white;
            }}
        """)
        main_layout.addWidget(self.table, stretch=1)

    def _combo_style(self) -> str:
        return f"""
            QComboBox {{
                background-color: {COLORS['BG_MAIN']};
                color: {COLORS['TEXT_PRIMARY']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 4px;
                padding: 5px 10px;
                min-height: 22px;
            }}
            QComboBox:hover, QComboBox:focus {{
                border-color: {COLORS['ACCENT']};
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox QAbstractItemView {{
                background-color: {COLORS['BG_PANEL']};
                color: {COLORS['TEXT_PRIMARY']};
                selection-background-color: {COLORS['ACCENT_PURPLE']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
            }}
        """

    def _line_edit_style(self) -> str:
        return f"""
            QLineEdit {{
                background-color: {COLORS['BG_MAIN']};
                color: {COLORS['TEXT_PRIMARY']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 4px;
                padding: 5px 10px;
                min-height: 22px;
            }}
            QLineEdit:focus {{
                border-color: {COLORS['ACCENT']};
            }}
        """

    def refresh_all(self):
        """Reload departments, scans, and transfers."""
        self.load_departments()
        self.load_scans()
        self.load_transfers()

    def load_departments(self):
        """Populate source and target department dropdowns."""
        self._departments_cache = self.db.get_departments()

        # Update Source Dept Combo
        self.source_dept_combo.blockSignals(True)
        self.source_dept_combo.clear()

        selected_source_idx = 0
        for idx, (dept_id, name, desc) in enumerate(self._departments_cache):
            display_text = f"{name} ({desc})" if desc else name
            self.source_dept_combo.addItem(display_text, dept_id)
            if self.current_department_id and dept_id == self.current_department_id:
                selected_source_idx = idx

        if self._departments_cache:
            self.source_dept_combo.setCurrentIndex(selected_source_idx)

        # If current_department_id is locked to a specific department, disable source combo
        if self.current_department_id is not None:
            self.source_dept_combo.setEnabled(False)
        else:
            self.source_dept_combo.setEnabled(True)

        self.source_dept_combo.blockSignals(False)

        # Connect source changed to refresh target list
        self.source_dept_combo.currentIndexChanged.connect(self._update_target_departments)
        self._update_target_departments()

    def _update_target_departments(self):
        """Update target department combobox excluding the selected source department."""
        current_source_id = self.source_dept_combo.currentData()
        self.target_dept_combo.blockSignals(True)
        self.target_dept_combo.clear()

        for dept_id, name, desc in self._departments_cache:
            if dept_id != current_source_id:
                display_text = f"{name} ({desc})" if desc else name
                self.target_dept_combo.addItem(display_text, dept_id)

        self.target_dept_combo.blockSignals(False)

    def load_scans(self):
        """Load recent scans into combobox."""
        self.scan_combo.blockSignals(True)
        self.scan_combo.clear()
        self.scan_combo.addItem("--- اختر من الفحوصات الأخيرة (Select Recent Scan) ---", None)

        try:
            dept_filter = None
            if self.current_department_id:
                # Find department name if available
                for d_id, d_name, _ in self._departments_cache:
                    if d_id == self.current_department_id:
                        dept_filter = d_name
                        break

            scans = self.db.get_scan_history(limit=50, department=dept_filter)
            for scan in scans:
                # scan: id, timestamp, document_name, total_entities, ...
                scan_id = scan[0]
                doc_name = scan[2] if len(scan) > 2 else "Doc"
                label = f"#{scan_id} - {doc_name} ({scan[1]})"
                self.scan_combo.addItem(label, scan_id)
        except Exception as e:
            logger.error(f"Error loading scans: {e}")

        self.scan_combo.blockSignals(False)

    def _on_scan_combo_changed(self, index: int):
        """When a scan is selected from the combobox, update the QLineEdit."""
        scan_id = self.scan_combo.currentData()
        if scan_id is not None:
            self.scan_id_input.setText(str(scan_id))

    def load_transfers(self):
        """Fetch transfers using self.db.get_transfers(self.current_department_id)."""
        try:
            # Requirements: Fetch transfers using self.db.get_transfers(self.current_department_id)
            transfers = self.db.get_transfers(self.current_department_id)
            self._all_transfers = transfers or []
            self._update_stats(self._all_transfers)
            self.render_transfers_table(self._all_transfers)
        except Exception as e:
            logger.error(f"Error loading transfers: {e}")
            self.table.setRowCount(0)

    def _update_stats(self, transfers: list):
        """Update metrics cards."""
        total = len(transfers)
        pending = sum(1 for t in transfers if (t[9] if len(t) > 9 else '').upper() == 'PENDING')
        approved = sum(1 for t in transfers if (t[9] if len(t) > 9 else '').upper() in ('APPROVED', 'COMPLETED'))
        rejected = sum(1 for t in transfers if (t[9] if len(t) > 9 else '').upper() == 'REJECTED')

        self.card_total.set_value(str(total))
        self.card_pending.set_value(str(pending))
        self.card_approved.set_value(str(approved))
        self.card_rejected.set_value(str(rejected))

    def apply_table_filter(self):
        """Filter transfers table by status combo."""
        filter_text = self.filter_status_combo.currentText()
        if not hasattr(self, '_all_transfers'):
            return

        if "PENDING" in filter_text:
            filtered = [t for t in self._all_transfers if (t[9] if len(t) > 9 else '').upper() == 'PENDING']
        elif "APPROVED" in filter_text:
            filtered = [t for t in self._all_transfers if (t[9] if len(t) > 9 else '').upper() in ('APPROVED', 'COMPLETED')]
        elif "REJECTED" in filter_text:
            filtered = [t for t in self._all_transfers if (t[9] if len(t) > 9 else '').upper() == 'REJECTED']
        else:
            filtered = self._all_transfers

        self.render_transfers_table(filtered)

    def render_transfers_table(self, transfers: list):
        """Populate the transfers QTableWidget."""
        self.table.setRowCount(0)

        for row_idx, t in enumerate(transfers):
            # t schema from get_transfers:
            # 0: id, 1: d1.name (source), 2: d2.name (target), 3: orig_scan_id,
            # 4: anon_scan_id, 5: strategy_used, 6: transfer_reason, 7: sender,
            # 8: receiver, 9: status, 10: created_at
            t_id = t[0]
            source_dept = t[1] or "غير محدد (N/A)"
            target_dept = t[2] or "غير محدد (N/A)"
            scan_id = t[3] or "-"
            strategy = t[5] or "Legal Mask"
            reason = t[6] or ""
            status = (t[9] or "PENDING").upper()
            created_at = str(t[10] or "")

            self.table.insertRow(row_idx)

            # Columns: (ID, Source Dept, Target Dept, Scan ID, Strategy, Reason, Status, Date)
            col_id = QTableWidgetItem(f"#{t_id}")
            col_id.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            col_src = QTableWidgetItem(str(source_dept))
            col_src.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            col_tgt = QTableWidgetItem(str(target_dept))
            col_tgt.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            col_scan = QTableWidgetItem(f"#{scan_id}")
            col_scan.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            col_strat = QTableWidgetItem(str(strategy))
            col_strat.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            col_reason = QTableWidgetItem(str(reason))
            col_reason.setToolTip(str(reason))

            # Status Badge Column
            col_status = QTableWidgetItem(status)
            col_status.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            font = col_status.font()
            font.setBold(True)
            col_status.setFont(font)

            if status in ("APPROVED", "COMPLETED"):
                col_status.setForeground(QColor(COLORS['SUCCESS']))
            elif status == "REJECTED":
                col_status.setForeground(QColor(COLORS['ERROR']))
            else:
                col_status.setForeground(QColor(COLORS['WARNING']))

            col_date = QTableWidgetItem(created_at)
            col_date.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            self.table.setItem(row_idx, 0, col_id)
            self.table.setItem(row_idx, 1, col_src)
            self.table.setItem(row_idx, 2, col_tgt)
            self.table.setItem(row_idx, 3, col_scan)
            self.table.setItem(row_idx, 4, col_strat)
            self.table.setItem(row_idx, 5, col_reason)
            self.table.setItem(row_idx, 6, col_status)
            self.table.setItem(row_idx, 7, col_date)

            # Action Column Widget
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(4, 2, 4, 2)
            action_layout.setSpacing(4)

            if status == "PENDING":
                btn_approve = QPushButton("قبول (Approve)")
                btn_approve.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLORS['SUCCESS']};
                        color: white;
                        padding: 3px 8px;
                        font-size: 11px;
                        border-radius: 4px;
                    }}
                    QPushButton:hover {{
                        background-color: #3fb950;
                    }}
                """)
                btn_approve.clicked.connect(lambda _, tid=t_id: self._change_status(tid, "APPROVED"))

                btn_reject = QPushButton("رفض (Reject)")
                btn_reject.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLORS['ERROR']};
                        color: white;
                        padding: 3px 8px;
                        font-size: 11px;
                        border-radius: 4px;
                    }}
                    QPushButton:hover {{
                        background-color: #f85149;
                    }}
                """)
                btn_reject.clicked.connect(lambda _, tid=t_id: self._change_status(tid, "REJECTED"))

                action_layout.addWidget(btn_approve)
                action_layout.addWidget(btn_reject)
            else:
                decision_label = "تمت الموافقة" if status in ("APPROVED", "COMPLETED") else "مرفوض"
                lbl_done = QLabel(decision_label)
                lbl_done.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 11px;")
                lbl_done.setAlignment(Qt.AlignmentFlag.AlignCenter)
                action_layout.addWidget(lbl_done)

            self.table.setCellWidget(row_idx, 8, action_widget)

    def _change_status(self, transfer_id: int, new_status: str):
        """Update transfer status and refresh view."""
        try:
            self.db.update_transfer_status(transfer_id, new_status, self.current_username)
            QMessageBox.information(
                self,
                "تحديث الحالة (Status Updated)",
                f"تم تحديث حالة طلب النقل #{transfer_id} إلى {new_status} بنجاح."
            )
            self.load_transfers()
        except Exception as e:
            logger.error(f"Failed to update transfer status: {e}")
            QMessageBox.critical(self, "خطأ (Error)", f"فشل تحديث حالة النقل: {e}")

    def on_send_transfer(self):
        """Validate form inputs, call self.db.create_transfer(...), and refresh table."""
        source_dept_id = self.source_dept_combo.currentData()
        target_dept_id = self.target_dept_combo.currentData()

        # Validate departments
        if source_dept_id is None:
            QMessageBox.warning(self, "خطأ في الإدخال (Input Error)", "يرجى تحديد القسم المصدر (Please select source department).")
            return

        if target_dept_id is None:
            QMessageBox.warning(self, "خطأ في الإدخال (Input Error)", "يرجى تحديد القسم الوجهة (Please select target department).")
            return

        if source_dept_id == target_dept_id:
            QMessageBox.warning(self, "خطأ في التحويل (Transfer Error)", "لا يمكن نقل المستند لنفس القسم (Source and target department cannot be the same).")
            return

        # Validate Scan ID
        scan_id_text = self.scan_id_input.text().strip()
        if not scan_id_text:
            QMessageBox.warning(self, "خطأ في الإدخال (Input Error)", "يرجى إدخال أو تحديد معرف الفحص (Please enter or select a Scan ID).")
            return

        try:
            orig_scan_id = int(scan_id_text)
            if orig_scan_id <= 0:
                raise ValueError()
        except ValueError:
            QMessageBox.warning(self, "خطأ في الإدخال (Input Error)", "معرف الفحص يجب أن يكون رقماً صحيحاً موجباً (Scan ID must be a positive integer).")
            return

        # Validate Reason
        reason = self.reason_edit.toPlainText().strip()
        if not reason:
            QMessageBox.warning(self, "خطأ في الإدخال (Input Error)", "يرجى كتابة سبب النقل والغرض النظامي منه (Please enter the transfer reason).")
            return

        strategy = self.strategy_combo.currentData() or self.strategy_combo.currentText()
        sender = self.current_username or "admin"
        receiver = self.target_dept_combo.currentText().split("(")[0].strip()

        # Approval tracking does not create an anonymized scan artifact.
        # Keep this NULL until a real processed scan is produced by a workflow.
        anon_scan_id = None

        try:
            new_id = self.db.create_transfer(
                source_dept=source_dept_id,
                target_dept=target_dept_id,
                orig_scan=orig_scan_id,
                anon_scan=anon_scan_id,
                strategy=strategy,
                reason=reason,
                sender=sender,
                receiver=receiver
            )

            QMessageBox.information(
                self,
                "نجاح العملية (Success)",
                f"تم تسجيل طلب النقل للمراجعة برقم: #{new_id}. لم يُعمَّ الملف ولم يُنقل تلقائيًا."
            )

            # Reset form inputs
            self.reason_edit.clear()
            self.scan_id_input.clear()
            if self.scan_combo.count() > 0:
                self.scan_combo.setCurrentIndex(0)

            # Refresh table
            self.load_transfers()

        except Exception as e:
            logger.error(f"Error creating transfer: {e}")
            QMessageBox.critical(self, "خطأ في قاعدة البيانات (Database Error)", f"فشل تسجيل طلب النقل: {e}")
