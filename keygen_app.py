import sys
import os
import uuid
import sqlite3 as plain_sqlite
import keyring
from cryptography.fernet import Fernet
try:
    from sqlcipher3 import dbapi2 as sqlite
except ImportError as exc:
    raise RuntimeError("SQLCipher is required to open the encrypted license database.") from exc
from datetime import datetime, timedelta
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTableWidget, QTableWidgetItem, QMessageBox, QHeaderView,
                             QSpinBox, QComboBox, QDialog, QFormLayout)
from PyQt6.QtCore import Qt

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from engine.license_signer import generate_license

class LicenseDB:
    SERVICE_NAME = "AlgPIIEngine_LicenseIssuer"
    KEY_ACCOUNT = "license_database_key"

    def __init__(self, db_path="license_db.sqlite"):
        self.db_path = os.path.abspath(db_path)
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)
        self._migrate_plain_database()
        self.conn = sqlite.connect(self.db_path)
        self.conn.execute(f"PRAGMA key = '{self.key.hex()}'")
        try:
            self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlite.DatabaseError as exc:
            self.conn.close()
            raise RuntimeError("License database key is invalid or the database is corrupt.") from exc
        self._init_db()

    def _load_or_create_key(self):
        existing = os.path.isfile(self.db_path) and os.path.getsize(self.db_path) > 0
        is_plain = False
        if existing:
            with open(self.db_path, "rb") as db_file:
                is_plain = db_file.read(16) == b"SQLite format 3\x00"
        stored = keyring.get_password(self.SERVICE_NAME, self.KEY_ACCOUNT)
        if stored:
            return stored.encode("ascii")
        if existing and not is_plain:
            raise RuntimeError("Encrypted license database key is missing from Windows Credential Manager.")
        key = Fernet.generate_key()
        keyring.set_password(self.SERVICE_NAME, self.KEY_ACCOUNT, key.decode("ascii"))
        if keyring.get_password(self.SERVICE_NAME, self.KEY_ACCOUNT) != key.decode("ascii"):
            raise RuntimeError("Could not securely store the license database key.")
        return key

    def _migrate_plain_database(self):
        if not os.path.isfile(self.db_path) or os.path.getsize(self.db_path) == 0:
            return
        with open(self.db_path, "rb") as db_file:
            if db_file.read(16) != b"SQLite format 3\x00":
                return
        source = plain_sqlite.connect(self.db_path)
        try:
            dump = "\n".join(source.iterdump())
        finally:
            source.close()

        temp_path = f"{self.db_path}.{uuid.uuid4().hex}.encrypted"
        encrypted = sqlite.connect(temp_path)
        try:
            encrypted.execute(f"PRAGMA key = '{self.key.hex()}'")
            encrypted.execute("SELECT count(*) FROM sqlite_master").fetchone()
            encrypted.executescript(dump)
            encrypted.commit()
        except Exception:
            encrypted.close()
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
        encrypted.close()

        with open(self.db_path, "rb") as source_file:
            encrypted_backup = self.fernet.encrypt(source_file.read())
        backup_path = f"{self.db_path}.legacy-backup.fernet"
        if os.path.exists(backup_path):
            backup_path += f".{uuid.uuid4().hex}"
        with open(backup_path, "xb") as backup_file:
            backup_file.write(encrypted_backup)
        try:
            os.replace(temp_path, self.db_path)
        except Exception:
            os.remove(backup_path)
            raise
        
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

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

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
            try:
                token = generate_license(hwid, days)
            except (OSError, ValueError) as exc:
                QMessageBox.critical(self, "تعذر إصدار الرخصة", str(exc))
                return

            expiry_date = datetime.utcnow() + timedelta(days=days)
            
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
