from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QLabel,
                             QFileDialog, QMessageBox, QInputDialog)
from PyQt6.QtCore import Qt
from storage.secure_db import SecureDatabase
from storage.secure_vault import SecureVault
from gui.theme import COLORS

class VaultPageWidget(QWidget):
    def __init__(self, db: SecureDatabase, department: str, username: str, parent=None):
        super().__init__(parent)
        self.db = db
        self.department = department
        self.username = username
        self.vault = SecureVault(db)
        
        self.setup_ui()
        self.load_vault()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        header_layout = QHBoxLayout()
        title = QLabel("القبو الآمن (Secure Document Vault)")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        upload_btn = QPushButton("رفع مستند (Upload)")
        upload_btn.setStyleSheet(f"background-color: {COLORS['ACCENT']}; color: white; padding: 5px 15px; border-radius: 4px;")
        upload_btn.clicked.connect(self.on_upload)
        header_layout.addWidget(upload_btn)
        
        download_btn = QPushButton("تحميل (Download)")
        download_btn.setStyleSheet(f"background-color: {COLORS['BG_BUTTON']}; color: white; padding: 5px 15px; border-radius: 4px;")
        download_btn.clicked.connect(self.on_download)
        header_layout.addWidget(download_btn)
        
        delete_btn = QPushButton("حذف (Delete)")
        delete_btn.setStyleSheet(f"background-color: {COLORS['ERROR']}; color: white; padding: 5px 15px; border-radius: 4px;")
        delete_btn.clicked.connect(self.on_delete)
        header_layout.addWidget(delete_btn)
        
        layout.addLayout(header_layout)
        
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID", "اسم المستند (Filename)", "بواسطة (Uploaded By)", "القسم (Dept)", "الوصف (Description)", "التاريخ (Date)"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setStyleSheet(f"""
            QTableWidget {{ background-color: {COLORS['BG_PANEL']}; color: {COLORS['TEXT_PRIMARY']}; gridline-color: {COLORS['BG_BUTTON']}; border: none; }}
            QHeaderView::section {{ background-color: {COLORS['BG_BUTTON']}; color: {COLORS['TEXT_PRIMARY']}; padding: 5px; border: none; }}
        """)
        layout.addWidget(self.table)
        
    def load_vault(self):
        self.table.setRowCount(0)
        docs = self.vault.list_documents(self.department)
        for i, row in enumerate(docs):
            self.table.insertRow(i)
            for j, val in enumerate(row):
                item = QTableWidgetItem(str(val) if val else "")
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(i, j, item)
                
    def on_upload(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "اختر المستند (Select Document)")
        if file_path:
            desc, ok = QInputDialog.getText(self, "وصف المستند", "أدخل وصفاً قصيراً (اختياري):")
            if ok:
                if self.vault.store_document(file_path, self.department, self.username, desc):
                    QMessageBox.information(self, "نجاح", "تم حفظ المستند وتشفيره في القبو بنجاح.")
                    self.load_vault()
                else:
                    QMessageBox.critical(self, "خطأ", "فشل حفظ المستند في القبو.")
                    
    def on_download(self):
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "تحذير", "الرجاء تحديد مستند من الجدول.")
            return
            
        vault_id = int(self.table.item(selected[0].row(), 0).text())
        filename = self.table.item(selected[0].row(), 1).text()
        
        save_path, _ = QFileDialog.getSaveFileName(self, "حفظ المستند (Save Document)", filename)
        if save_path:
            if self.vault.retrieve_document(vault_id, save_path):
                QMessageBox.information(self, "نجاح", f"تم فك تشفير المستند وحفظه في:\n{save_path}")
            else:
                QMessageBox.critical(self, "خطأ", "فشل تحميل المستند.")
                
    def on_delete(self):
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "تحذير", "الرجاء تحديد مستند من الجدول.")
            return
            
        vault_id = int(self.table.item(selected[0].row(), 0).text())
        filename = self.table.item(selected[0].row(), 1).text()
        
        ans = QMessageBox.question(self, "تأكيد الحذف", f"هل أنت متأكد من حذف المستند المشفر '{filename}' نهائياً؟", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ans == QMessageBox.StandardButton.Yes:
            if self.vault.delete_document(vault_id):
                QMessageBox.information(self, "نجاح", "تم حذف المستند بنجاح.")
                self.load_vault()
            else:
                QMessageBox.critical(self, "خطأ", "فشل حذف المستند.")
