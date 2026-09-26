from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QMessageBox)
from PyQt6.QtCore import Qt
from storage.secure_db import SecureDatabase
from .theme import COLORS

class LoginDialog(QDialog):
    """Modal dialog for User Authentication."""
    
    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self.authenticated_role = None
        self.authenticated_username = None
        
        self.setWindowTitle("تسجيل الدخول | Login")
        self.setFixedSize(400, 250)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowCloseButtonHint) # Prevent closing
        
        self._init_ui()
        
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        title = QLabel("تسجيل الدخول للنظام")
        title.setStyleSheet(f"color: {COLORS['ACCENT']}; font-size: 18px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        layout.addSpacing(20)
        
        # Form
        form_layout = QVBoxLayout()
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("اسم المستخدم (Username)")
        form_layout.addWidget(self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("كلمة المرور (Password)")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.returnPressed.connect(self._login)
        form_layout.addWidget(self.password_input)
        
        layout.addLayout(form_layout)
        layout.addSpacing(20)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_login = QPushButton("دخول (Login)")
        self.btn_login.setStyleSheet(f"background-color: {COLORS['SUCCESS']};")
        self.btn_login.clicked.connect(self._login)
        
        self.btn_exit = QPushButton("خروج (Exit)")
        self.btn_exit.setStyleSheet(f"background-color: {COLORS['ERROR']};")
        self.btn_exit.clicked.connect(self.reject)
        
        btn_layout.addWidget(self.btn_login)
        btn_layout.addWidget(self.btn_exit)
        layout.addLayout(btn_layout)
        
    def _login(self):
        user = self.username_input.text().strip()
        pw = self.password_input.text().strip()
        
        if not user or not pw:
            QMessageBox.warning(self, "خطأ", "الرجاء إدخال اسم المستخدم وكلمة المرور.")
            return
            
        success, role, dept = self.db.authenticate_user(user, pw)
        
        if success:
            self.authenticated_role = role
            self.authenticated_username = user
            self.authenticated_department = dept
            self.accept()
        else:
            QMessageBox.critical(self, "فشل", "اسم المستخدم أو كلمة المرور غير صحيحة.")
