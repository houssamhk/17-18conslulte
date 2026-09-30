from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QMessageBox, QTextEdit)
from PyQt6.QtCore import Qt
from engine.license_manager import LicenseManager
from .theme import COLORS
from .dialog_utils import configure_dialog_size

class LicenseDialog(QDialog):
    """Modal dialog forcing the user to enter a valid license key."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("تفعيل البرنامج | Software Activation")
        configure_dialog_size(self, preferred=(640, 460), minimum=(480, 360))
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowCloseButtonHint) # Prevent closing
        
        self.hwid = LicenseManager.get_hardware_id()
        self._init_ui()
        
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        title = QLabel("برنامج Alg-PII Engine غير مفعل")
        title.setStyleSheet(f"color: {COLORS['ACCENT']}; font-size: 16px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        info = QLabel("يرجى إرسال 'رقم الجهاز' إلى مسؤول النظام للحصول على مفتاح التفعيل.")
        info.setWordWrap(True)
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(info)
        
        # HWID Display
        hwid_layout = QHBoxLayout()
        hwid_layout.addWidget(QLabel("رقم الجهاز (HWID):"))
        self.hwid_input = QLineEdit(self.hwid)
        self.hwid_input.setReadOnly(True)
        self.hwid_input.setStyleSheet(f"color: {COLORS['WARNING']}; font-weight: bold; text-align: center;")
        hwid_layout.addWidget(self.hwid_input)
        
        btn_copy = QPushButton("نسخ")
        btn_copy.setFixedWidth(60)
        btn_copy.clicked.connect(self._copy_hwid)
        hwid_layout.addWidget(btn_copy)
        
        layout.addLayout(hwid_layout)
        layout.addSpacing(15)
        
        # License Input
        layout.addWidget(QLabel("أدخل مفتاح التفعيل (License Key):"))
        self.key_input = QTextEdit()
        self.key_input.setFixedHeight(80)
        layout.addWidget(self.key_input)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_activate = QPushButton("تفعيل (Activate)")
        self.btn_activate.setStyleSheet(f"background-color: {COLORS['SUCCESS']};")
        self.btn_activate.clicked.connect(self._activate)
        
        self.btn_exit = QPushButton("خروج (Exit)")
        self.btn_exit.setStyleSheet(f"background-color: {COLORS['ERROR']};")
        self.btn_exit.clicked.connect(self.reject)
        
        btn_layout.addWidget(self.btn_activate)
        btn_layout.addWidget(self.btn_exit)
        layout.addLayout(btn_layout)
        
    def _copy_hwid(self):
        import PyQt6.QtWidgets as QtWidgets
        QtWidgets.QApplication.clipboard().setText(self.hwid)
        
    def _activate(self):
        token = self.key_input.toPlainText().strip()
        if not token:
            QMessageBox.warning(self, "تنبيه", "الرجاء إدخال مفتاح التفعيل.")
            return
            
        is_valid, msg = LicenseManager.validate_license(token)
        
        if is_valid:
            LicenseManager.save_license(token)
            QMessageBox.information(self, "نجاح", "تم تفعيل البرنامج بنجاح! شكراً لك.")
            self.accept()
        else:
            QMessageBox.critical(self, "فشل التفعيل", msg)
