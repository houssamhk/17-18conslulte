from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QLabel,
                             QDialog, QLineEdit, QComboBox, QDateEdit, QMessageBox)
from PyQt6.QtCore import Qt, QDate
from storage.secure_db import SecureDatabase
from gui.theme import COLORS
import datetime
from .dialog_utils import configure_dialog_size

class ConsentDialog(QDialog):
    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("إضافة موافقة جديدة (New Consent)")
        configure_dialog_size(self, preferred=(560, 620), minimum=(380, 420))
        
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("معرف الفرد (Subject ID - NIN/Email):"))
        self.id_edit = QLineEdit()
        layout.addWidget(self.id_edit)
        
        layout.addWidget(QLabel("الاسم (Subject Name):"))
        self.name_edit = QLineEdit()
        layout.addWidget(self.name_edit)
        
        layout.addWidget(QLabel("نوع الموافقة (Consent Type):"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["DATA_PROCESSING", "MARKETING", "DATA_SHARING"])
        layout.addWidget(self.type_combo)
        
        layout.addWidget(QLabel("الحالة (Status):"))
        self.status_combo = QComboBox()
        self.status_combo.addItems(["OPT_IN", "OPT_OUT"])
        layout.addWidget(self.status_combo)
        
        layout.addWidget(QLabel("المصدر (Source):"))
        self.source_combo = QComboBox()
        self.source_combo.addItems(["WEB_FORM", "WRITTEN", "DSAR", "VERBAL"])
        layout.addWidget(self.source_combo)
        
        layout.addWidget(QLabel("تاريخ الانتهاء (Expiration Date):"))
        self.date_edit = QDateEdit()
        self.date_edit.setCalendarPopup(True)
        self.date_edit.setDate(QDate.currentDate().addYears(1))
        layout.addWidget(self.date_edit)
        
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("حفظ (Save)")
        save_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("إلغاء (Cancel)")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
        self.setStyleSheet(f"""
            QDialog {{ background-color: {COLORS['BG_MAIN']}; color: {COLORS['TEXT_PRIMARY']}; }}
            QLabel {{ color: {COLORS['TEXT_PRIMARY']}; }}
            QLineEdit, QComboBox, QDateEdit {{ background-color: {COLORS['BG_PANEL']}; color: {COLORS['TEXT_PRIMARY']}; padding: 5px; border-radius: 4px; border: 1px solid {COLORS['BG_BUTTON']}; }}
            QPushButton {{ background-color: {COLORS['BG_BUTTON']}; color: white; padding: 5px 15px; border-radius: 4px; }}
        """)

class ConsentPageWidget(QWidget):
    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self.setup_ui()
        self.load_consents()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        header_layout = QHBoxLayout()
        title = QLabel("سجل الموافقات (Consent Registry)")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        new_btn = QPushButton("موافقة جديدة (Add Consent)")
        new_btn.setStyleSheet(f"background-color: {COLORS['ACCENT']}; color: white; padding: 5px 15px; border-radius: 4px;")
        new_btn.clicked.connect(self.on_add_consent)
        header_layout.addWidget(new_btn)
        
        layout.addLayout(header_layout)
        
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["ID", "المعرف (Subject ID)", "الاسم (Name)", "النوع (Type)", "الحالة (Status)", "المصدر (Source)", "الانتهاء (Expires)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setStyleSheet(f"""
            QTableWidget {{ background-color: {COLORS['BG_PANEL']}; color: {COLORS['TEXT_PRIMARY']}; gridline-color: {COLORS['BG_BUTTON']}; border: none; }}
            QHeaderView::section {{ background-color: {COLORS['BG_BUTTON']}; color: {COLORS['TEXT_PRIMARY']}; padding: 5px; border: none; }}
        """)
        layout.addWidget(self.table)
        
    def load_consents(self):
        self.table.setRowCount(0)
        c = self.db.conn.cursor()
        c.execute("SELECT id, subject_id, subject_name, consent_type, status, source, expires_at FROM consent_registry ORDER BY created_at DESC")
        rows = c.fetchall()
        for i, row in enumerate(rows):
            self.table.insertRow(i)
            for j, val in enumerate(row):
                item = QTableWidgetItem(str(val) if val else "")
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                
                # Color code status
                if j == 4:
                    if val == "OPT_IN":
                        item.setForeground(Qt.GlobalColor.green)
                    else:
                        item.setForeground(Qt.GlobalColor.red)
                        
                self.table.setItem(i, j, item)
                
    def on_add_consent(self):
        dlg = ConsentDialog(self.db, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            c = self.db.conn.cursor()
            c.execute('''INSERT INTO consent_registry 
                         (subject_id, subject_name, consent_type, status, source, expires_at)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (dlg.id_edit.text(), dlg.name_edit.text(), dlg.type_combo.currentText(),
                       dlg.status_combo.currentText(), dlg.source_combo.currentText(), 
                       dlg.date_edit.date().toString(Qt.DateFormat.ISODate)))
            self.db.conn.commit()
            self.load_consents()
