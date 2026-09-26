import sys
import os
import jwt
import sqlite3
from datetime import datetime, timedelta
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTableWidget, QTableWidgetItem, QMessageBox, QHeaderView,
                             QSpinBox, QComboBox, QDialog, QFormLayout)
from PyQt6.QtCore import Qt

# Import the secret key directly from the engine
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from engine.license_manager import LicenseManager

class LicenseDB:
    def __init__(self, db_path="license_db.sqlite"):
        self.conn = sqlite3.connect(db_path)
        self._init_db()
        
    def _init_db(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS clients
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      company_name TEXT NOT NULL,
                      contact_email TEXT,
                      hwid TEXT NOT NULL UNIQUE,
                      license_key TEXT,
                      issue_date DATETIME,
                      expiry_date DATETIME,
                      status TEXT DEFAULT 'ACTIVE')''')
        self.conn.commit()

    def add_client(self, company, email, hwid):
        c = self.conn.cursor()
        try:
            c.execute("INSERT INTO clients (company_name, contact_email, hwid) VALUES (?, ?, ?)",
                      (company, email, hwid))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def update_license(self, hwid, license_key, expiry_date):
        c = self.conn.cursor()
        c.execute('''UPDATE clients 
                     SET license_key = ?, issue_date = ?, expiry_date = ?, status = 'ACTIVE'
                     WHERE hwid = ?''', 
                  (license_key, datetime.utcnow(), expiry_date, hwid))
        self.conn.commit()

    def revoke_license(self, hwid):
        c = self.conn.cursor()
        c.execute("UPDATE clients SET status = 'REVOKED' WHERE hwid = ?", (hwid,))
        self.conn.commit()
        
    def get_clients(self):
        c = self.conn.cursor()
        c.execute("SELECT id, company_name, hwid, issue_date, expiry_date, status, license_key FROM clients")
        return c.fetchall()

class AddClientDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("إضافة عميل جديد (Add Client)")
        self.setFixedSize(400, 200)
        
        layout = QFormLayout(self)
        self.company_input = QLineEdit()
        self.email_input = QLineEdit()
        self.hwid_input = QLineEdit()
        
        layout.addRow("اسم الشركة (Company):", self.company_input)
        layout.addRow("البريد (Email):", self.email_input)
        layout.addRow("معرف الجهاز (HWID):", self.hwid_input)
        
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("حفظ (Save)")
        save_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("إلغاء (Cancel)")
        cancel_btn.clicked.connect(self.reject)
        
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addRow(btn_layout)
        
    def get_data(self):
        return self.company_input.text(), self.email_input.text(), self.hwid_input.text()

class KeyGenApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db = LicenseDB()
        self.setWindowTitle("إدارة تراخيص Alg-PII Engine | License Manager")
        self.resize(900, 600)
        self._init_ui()
        self._load_data()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        add_btn = QPushButton("إضافة عميل (Add Client)")
        add_btn.clicked.connect(self._add_client)
        
        gen_btn = QPushButton("توليد ترخيص (Generate License)")
        gen_btn.clicked.connect(self._generate_license)
        
        revoke_btn = QPushButton("إلغاء ترخيص (Revoke)")
        revoke_btn.clicked.connect(self._revoke_license)
        
        copy_btn = QPushButton("نسخ المفتاح (Copy Key)")
        copy_btn.clicked.connect(self._copy_key)
        
        toolbar.addWidget(add_btn)
        toolbar.addWidget(gen_btn)
        toolbar.addWidget(revoke_btn)
        toolbar.addWidget(copy_btn)
        toolbar.addStretch()
        
        layout.addLayout(toolbar)
        
        # Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["ID", "Company", "HWID", "Issue Date", "Expiry Date", "Status", "License Key"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        
        layout.addWidget(self.table)

    def _load_data(self):
        self.table.setRowCount(0)
        clients = self.db.get_clients()
        for c in clients:
            row = self.table.rowCount()
            self.table.insertRow(row)
            for i, val in enumerate(c):
                item = QTableWidgetItem(str(val) if val is not None else "")
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, i, item)

    def _add_client(self):
        dlg = AddClientDialog(self)
        if dlg.exec():
            company, email, hwid = dlg.get_data()
            if not company or not hwid:
                QMessageBox.warning(self, "خطأ", "يجب إدخال اسم الشركة ومعرف الجهاز.")
                return
            if self.db.add_client(company, email, hwid):
                self._load_data()
            else:
                QMessageBox.warning(self, "خطأ", "معرف الجهاز موجود مسبقاً.")

    def _generate_license(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "تنبيه", "يرجى تحديد عميل أولاً.")
            return
            
        hwid = self.table.item(row, 2).text()
        
        days_dialog = QDialog(self)
        days_dialog.setWindowTitle("صلاحية الترخيص (Validity)")
        layout = QVBoxLayout(days_dialog)
        spin = QSpinBox()
        spin.setRange(1, 3650)
        spin.setValue(365)
        layout.addWidget(QLabel("عدد الأيام (Days):"))
        layout.addWidget(spin)
        
        btns = QHBoxLayout()
        ok = QPushButton("موافق (OK)")
        ok.clicked.connect(days_dialog.accept)
        btns.addWidget(ok)
        layout.addLayout(btns)
        
        if days_dialog.exec():
            days = spin.value()
            expiry_date = datetime.utcnow() + timedelta(days=days)
            payload = {
                "hwid": hwid.upper(),
                "exp": expiry_date,
                "iat": datetime.utcnow(),
                "product": "Alg-PII Engine Enterprise"
            }
            token = jwt.encode(payload, LicenseManager.SECRET_KEY, algorithm="HS256")
            
            self.db.update_license(hwid, token, expiry_date)
            self._load_data()
            QMessageBox.information(self, "نجاح", "تم توليد الترخيص بنجاح.")

    def _revoke_license(self):
        row = self.table.currentRow()
        if row < 0:
            return
        hwid = self.table.item(row, 2).text()
        reply = QMessageBox.question(self, "تأكيد الإلغاء", "هل أنت متأكد من إلغاء هذا الترخيص؟")
        if reply == QMessageBox.StandardButton.Yes:
            self.db.revoke_license(hwid)
            self._load_data()

    def _copy_key(self):
        row = self.table.currentRow()
        if row < 0:
            return
        key = self.table.item(row, 6).text()
        if key:
            QApplication.clipboard().setText(key)
            QMessageBox.information(self, "نجاح", "تم نسخ المفتاح.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Attempt to set dark fusion theme
    app.setStyle("Fusion")
    
    window = KeyGenApp()
    window.show()
    sys.exit(app.exec())
