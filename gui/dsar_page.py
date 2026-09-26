import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QPushButton,
                             QDialog, QFormLayout, QLineEdit, QComboBox, QMessageBox, QFileDialog)
from PyQt6.QtCore import Qt
from gui.theme import COLORS
from engine.dsar_manager import DSARManager

class CreateDSARDialog(QDialog):
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("إنشاء طلب DSAR جديد")
        self.setFixedSize(400, 300)
        self.setStyleSheet(f"background-color: {COLORS['BG_MAIN']}; color: {COLORS['TEXT_PRIMARY']};")
        
        layout = QVBoxLayout(self)
        form = QFormLayout()
        
        self.name_input = QLineEdit()
        self.contact_input = QLineEdit()
        self.subject_input = QLineEdit()
        self.subject_input.setPlaceholderText("رقم الهوية، البريد الإلكتروني، أو الاسم الكامل")
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["ACCESS (الوصول)", "ERASURE (المحو)", "RECTIFICATION (التصحيح)"])
        
        form.addRow("اسم مقدم الطلب:", self.name_input)
        form.addRow("معلومات الاتصال:", self.contact_input)
        form.addRow("هوية صاحب البيانات:", self.subject_input)
        form.addRow("نوع الطلب:", self.type_combo)
        
        layout.addLayout(form)
        
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("حفظ")
        save_btn.setStyleSheet(f"background-color: {COLORS['SUCCESS']};")
        save_btn.clicked.connect(self.accept)
        
        cancel_btn = QPushButton("إلغاء")
        cancel_btn.clicked.connect(self.reject)
        
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
    def get_data(self):
        req_type = self.type_combo.currentText().split(" ")[0]
        return self.name_input.text(), self.contact_input.text(), self.subject_input.text(), req_type

class DSARPageWidget(QWidget):
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self.dsar_manager = DSARManager(db)
        self._init_ui()
        
    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("إدارة طلبات وصول الأفراد (DSAR Manager)")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        
        create_btn = QPushButton("+ طلب جديد (New Request)")
        create_btn.setFixedWidth(150)
        create_btn.setStyleSheet(f"background-color: {COLORS['ACCENT']};")
        create_btn.clicked.connect(self.create_request)
        
        refresh_btn = QPushButton("تحديث (Refresh)")
        refresh_btn.setFixedWidth(120)
        refresh_btn.clicked.connect(self.load_data)
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(create_btn)
        header_layout.addWidget(refresh_btn)
        layout.addLayout(header_layout)
        
        info = QLabel("يتيح هذا القسم إدارة طلبات وصول الأفراد للبيانات وفقاً للقانون 18-07، حيث يتطلب القانون الرد خلال 30 يوماً.")
        info.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']};")
        layout.addWidget(info)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["ID", "مقدم الطلب", "صاحب البيانات", "النوع", "الحالة", "الموعد النهائي (SLA)", "الإجراءات"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)
        
        self.load_data()
        
    def load_data(self):
        requests = self.db.get_dsar_requests()
        self.table.setRowCount(len(requests))
        
        for row, req in enumerate(requests):
            self.table.setItem(row, 0, QTableWidgetItem(str(req['id'])))
            self.table.setItem(row, 1, QTableWidgetItem(req['requester_name']))
            self.table.setItem(row, 2, QTableWidgetItem(req['subject_identity']))
            self.table.setItem(row, 3, QTableWidgetItem(req['request_type']))
            
            status_item = QTableWidgetItem(req['status'])
            if req['status'] == 'OPEN':
                status_item.setForeground(Qt.GlobalColor.yellow)
            elif req['status'] == 'CLOSED':
                status_item.setForeground(Qt.GlobalColor.green)
            self.table.setItem(row, 4, status_item)
            
            self.table.setItem(row, 5, QTableWidgetItem(req['sla_deadline']))
            
            action_btn = QPushButton("توليد التقرير (Generate Report)")
            action_btn.clicked.connect(lambda _, r=req: self.generate_report(r))
            if req['status'] == 'CLOSED':
                action_btn.setEnabled(False)
            self.table.setCellWidget(row, 6, action_btn)
            
    def create_request(self):
        dlg = CreateDSARDialog(self.db, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            name, contact, subject, req_type = dlg.get_data()
            if name and subject:
                self.db.create_dsar_request(name, contact, subject, req_type)
                self.load_data()
            else:
                QMessageBox.warning(self, "خطأ", "يجب إدخال اسم مقدم الطلب وهوية صاحب البيانات.")
                
    def generate_report(self, req):
        path, _ = QFileDialog.getSaveFileName(self, "حفظ التقرير", f"DSAR_{req['id']}_Response.pdf", "PDF Files (*.pdf)")
        if path:
            try:
                self.dsar_manager.generate_dsar_report(req['id'], req['subject_identity'], path)
                self.db.update_dsar_status(req['id'], 'CLOSED', f"Generated PDF report at {os.path.basename(path)}")
                QMessageBox.information(self, "نجاح", f"تم توليد التقرير بنجاح وتحديث حالة الطلب إلى مغلق.\n\nالمسار: {path}")
                self.load_data()
            except Exception as e:
                QMessageBox.critical(self, "خطأ", f"فشل في توليد التقرير: {e}")
