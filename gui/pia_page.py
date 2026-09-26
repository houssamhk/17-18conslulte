import json
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QLabel)
from PyQt6.QtCore import Qt
from storage.secure_db import SecureDatabase
from gui.theme import COLORS
from gui.pia_wizard import PIAWizard

class PIAPageWidget(QWidget):
    def __init__(self, db: SecureDatabase, department: str, username: str, parent=None):
        super().__init__(parent)
        self.db = db
        self.department = department
        self.username = username
        self.setup_ui()
        self.load_pias()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("تقييم أثر الخصوصية (Privacy Impact Assessments)")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        new_btn = QPushButton("تقييم جديد (New PIA)")
        new_btn.setStyleSheet(f"background-color: {COLORS['ACCENT']}; color: white; padding: 5px 15px; border-radius: 4px;")
        new_btn.clicked.connect(self.on_new_pia)
        header_layout.addWidget(new_btn)
        
        export_btn = QPushButton("تصدير تقرير (Export PDF)")
        export_btn.setStyleSheet(f"background-color: {COLORS['BG_BUTTON']}; color: white; padding: 5px 15px; border-radius: 4px;")
        export_btn.clicked.connect(self.on_export_pdf)
        header_layout.addWidget(export_btn)
        
        layout.addLayout(header_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID", "المشروع (Project)", "القسم (Dept)", "مستوى الخطر (Risk)", "الحالة (Status)", "التاريخ (Date)"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setStyleSheet(f"""
            QTableWidget {{ background-color: {COLORS['BG_PANEL']}; color: {COLORS['TEXT_PRIMARY']}; gridline-color: {COLORS['BG_BUTTON']}; border: none; }}
            QHeaderView::section {{ background-color: {COLORS['BG_BUTTON']}; color: {COLORS['TEXT_PRIMARY']}; padding: 5px; border: none; }}
        """)
        layout.addWidget(self.table)
        
    def load_pias(self):
        self.table.setRowCount(0)
        
        c = self.db.conn.cursor()
        if self.department:
            c.execute("SELECT id, project_name, department, risk_level, status, created_at FROM pia_assessments WHERE department=? ORDER BY created_at DESC", (self.department,))
        else:
            c.execute("SELECT id, project_name, department, risk_level, status, created_at FROM pia_assessments ORDER BY created_at DESC")
            
        rows = c.fetchall()
        for i, row in enumerate(rows):
            self.table.insertRow(i)
            for j, val in enumerate(row):
                item = QTableWidgetItem(str(val))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(i, j, item)
                
    def on_new_pia(self):
        wizard = PIAWizard(self.db, self.department, self.username, self)
        if wizard.exec() == QWizard.DialogCode.Accepted:
            self.load_pias()

    def on_export_pdf(self):
        selected = self.table.selectedItems()
        if not selected:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "تحذير", "الرجاء تحديد تقييم من الجدول أولاً.")
            return
            
        pia_id = int(self.table.item(selected[0].row(), 0).text())
        
        c = self.db.conn.cursor()
        c.execute("SELECT project_name, department, assessor_name, data_types_json, processing_purpose, risk_level, mitigation_steps, created_at FROM pia_assessments WHERE id=?", (pia_id,))
        row = c.fetchone()
        
        if not row:
            return
            
        pia_data = {
            'project_name': row[0],
            'department': row[1],
            'assessor_name': row[2],
            'data_types': row[3],
            'processing_purpose': row[4],
            'risk_level': row[5],
            'mitigation_steps': row[6],
            'created_at': row[7]
        }
        
        from PyQt6.QtWidgets import QFileDialog
        from engine.pdf_exporter import PDFExporter
        
        file_path, _ = QFileDialog.getSaveFileName(self, "حفظ التقرير (Save Report)", f"PIA_{pia_id}.pdf", "PDF Files (*.pdf)")
        if file_path:
            try:
                PDFExporter.export_pia(pia_data, file_path)
                QMessageBox.information(self, "نجاح", f"تم تصدير التقرير بنجاح إلى:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "خطأ", f"فشل التصدير:\n{str(e)}")
