from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QScrollArea, QFrame, QMessageBox, QDialog,
                             QFormLayout, QTextEdit, QComboBox)
from PyQt6.QtCore import Qt, QTimer
from datetime import datetime
from storage.secure_db import SecureDatabase
from .theme import COLORS


class IncidentCard(QFrame):
    def __init__(self, incident_data, parent_board):
        super().__init__()
        self.incident_data = incident_data
        self.parent_board = parent_board
        
        self.setObjectName("IncidentCard")
        self.setStyleSheet(f"""
            #IncidentCard {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['BG_MAIN']};
                border-radius: 6px;
                padding: 10px;
                margin-bottom: 10px;
            }}
            #IncidentCard:hover {{
                border: 1px solid {COLORS['ACCENT']};
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header (Title + ID)
        header_layout = QHBoxLayout()
        title_lbl = QLabel(f"#{incident_data[0]} {incident_data[1]}")
        title_lbl.setStyleSheet(f"font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        title_lbl.setWordWrap(True)
        header_layout.addWidget(title_lbl)
        layout.addLayout(header_layout)
        
        # Severity Badge
        sev_color = COLORS.get(incident_data[3], COLORS['WARNING'])
        if incident_data[3] == "CRITICAL": sev_color = COLORS['ERROR']
        
        sev_lbl = QLabel(incident_data[3])
        sev_lbl.setStyleSheet(f"background-color: {sev_color}; color: white; border-radius: 4px; padding: 2px 6px; font-size: 10px;")
        layout.addWidget(sev_lbl, alignment=Qt.AlignmentFlag.AlignLeft)
        
        # Description
        desc_lbl = QLabel(incident_data[2])
        desc_lbl.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 11px;")
        desc_lbl.setWordWrap(True)
        layout.addWidget(desc_lbl)
        
        # SLA Deadline
        sla = incident_data[7]
        sla_lbl = QLabel(f"SLA: {sla}")
        sla_lbl.setStyleSheet(f"color: {COLORS['WARNING']}; font-size: 10px;")
        layout.addWidget(sla_lbl)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        if incident_data[4] != 'CLOSED':
            act_btn = QPushButton("إجراء (Action)")
            act_btn.setStyleSheet(f"background-color: {COLORS['BG_BUTTON']}; color: white;")
            act_btn.clicked.connect(self.on_action)
            btn_layout.addWidget(act_btn)
            
        evid_btn = QPushButton("تصدير الأدلة (Export Evidence)")
        evid_btn.setStyleSheet(f"background-color: {COLORS['ACCENT_PURPLE']}; color: white;")
        evid_btn.clicked.connect(self.on_export_evidence)
        btn_layout.addWidget(evid_btn)
        
        layout.addLayout(btn_layout)
        
    def on_export_evidence(self):
        from PyQt6.QtWidgets import QFileDialog
        from engine.evidence_packager import EvidencePackager
        
        out_dir = QFileDialog.getExistingDirectory(self, "اختر مجلد الحفظ (Select Output Directory)")
        if out_dir:
            try:
                packager = EvidencePackager(self.parent_board.db)
                filepath = packager.generate_package(self.incident_data[0], out_dir)
                QMessageBox.information(self, "نجاح", f"تم تصدير حزمة الأدلة بنجاح إلى:\n{filepath}")
            except Exception as e:
                QMessageBox.critical(self, "خطأ", f"فشل في تصدير الأدلة: {e}")
                
    def on_action(self):
        dlg = IncidentActionDialog(self.incident_data, self)
        if dlg.exec():
            status, assignee, notes = dlg.get_data()
            self.parent_board.db.update_incident_status(self.incident_data[0], status, assignee, notes)
            self.parent_board.load_data()


class IncidentActionDialog(QDialog):
    def __init__(self, incident_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("تحديث الحادث (Update Incident)")
        self.resize(400, 300)
        
        layout = QFormLayout(self)
        
        self.status_combo = QComboBox()
        self.status_combo.addItems(["OPEN", "INVESTIGATING", "REMEDIATED", "CLOSED"])
        self.status_combo.setCurrentText(incident_data[4])
        
        self.assignee_input = QComboBox()
        self.assignee_input.addItems(["admin", "security_team", "legal_team"])
        if incident_data[5]:
            self.assignee_input.setCurrentText(incident_data[5])
            
        self.notes_input = QTextEdit()
        
        layout.addRow("الحالة (Status):", self.status_combo)
        layout.addRow("تعيين إلى (Assign To):", self.assignee_input)
        layout.addRow("ملاحظات (Notes):", self.notes_input)
        
        btn = QPushButton("حفظ (Save)")
        btn.clicked.connect(self.accept)
        layout.addRow(btn)
        
    def get_data(self):
        return self.status_combo.currentText(), self.assignee_input.currentText(), self.notes_input.toPlainText()


class IncidentsPageWidget(QWidget):
    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self._init_ui()
        self.load_data()
        
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        title = QLabel("إدارة الحوادث (Incident Management)")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        layout.addWidget(title)
        
        # Kanban Board
        board_layout = QHBoxLayout()
        
        self.columns = {
            "OPEN": self._create_column("مفتوح (Open)"),
            "INVESTIGATING": self._create_column("قيد التحقيق (Investigating)"),
            "REMEDIATED": self._create_column("تمت المعالجة (Remediated)"),
            "CLOSED": self._create_column("مغلق (Closed)")
        }
        
        for col in self.columns.values():
            board_layout.addWidget(col)
            
        layout.addLayout(board_layout)
        
    def _create_column(self, title_text):
        col_widget = QFrame()
        col_widget.setStyleSheet(f"background-color: {COLORS['BG_MAIN']}; border-radius: 8px;")
        
        layout = QVBoxLayout(col_widget)
        
        header = QLabel(title_text)
        header.setStyleSheet(f"font-weight: bold; font-size: 14px; padding: 10px; color: {COLORS['TEXT_PRIMARY']};")
        layout.addWidget(header)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("border: none; background-color: transparent;")
        
        content = QWidget()
        content.setStyleSheet("background-color: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        scroll.setWidget(content)
        layout.addWidget(scroll)
        
        # Store layout reference for adding cards
        col_widget.content_layout = content_layout
        return col_widget
        
    def load_data(self):
        # Clear existing cards
        for col in self.columns.values():
            layout = col.content_layout
            for i in reversed(range(layout.count())): 
                widget = layout.itemAt(i).widget()
                if widget:
                    widget.setParent(None)
                    
        incidents = self.db.get_incidents()
        
        for inc in incidents:
            status = inc[4]
            if status in self.columns:
                card = IncidentCard(inc, self)
                self.columns[status].content_layout.addWidget(card)
