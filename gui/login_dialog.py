from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QMessageBox, QInputDialog)
from .dialog_utils import configure_dialog_size
from PyQt6.QtCore import Qt
from storage.secure_db import SecureDatabase
from storage.password_policy import MIN_PASSWORD_LENGTH, password_is_valid, password_strength_hint
from .theme import COLORS


class FirstRunAdminDialog(QDialog):
    """Securely create the first administrator instead of shipping default credentials."""

    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("إعداد حساب المدير الأول")
        configure_dialog_size(self, preferred=(560, 440), minimum=(420, 340))
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"أنشئ حساب المدير للبدء. استخدم عبارة مرور من {MIN_PASSWORD_LENGTH} محرفًا على الأقل."))
        self.username = QLineEdit()
        self.username.setMaxLength(128)
        self.username.setPlaceholderText("اسم المستخدم")
        self.password = QLineEdit()
        self.password.setPlaceholderText("كلمة المرور")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_hint = QLabel()
        self.password.textChanged.connect(lambda text: self._update_strength(self.password_hint, text))
        self.confirm = QLineEdit()
        self.confirm.setPlaceholderText("تأكيد كلمة المرور")
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.username)
        layout.addWidget(self.password)
        layout.addWidget(self.password_hint)
        layout.addWidget(self.confirm)
        buttons = QHBoxLayout()
        create = QPushButton("إنشاء الحساب")
        cancel = QPushButton("خروج")
        create.clicked.connect(self._create)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(create)
        buttons.addWidget(cancel)
        layout.addLayout(buttons)

    def _create(self):
        username = self.username.text().strip()
        password = self.password.text()
        if not username or not password_is_valid(password) or password != self.confirm.text():
            QMessageBox.warning(self, "بيانات غير صالحة", f"استخدم كلمة مرور من {MIN_PASSWORD_LENGTH} محرفًا على الأقل، متنوعة وغير متكررة، ولا تتجاوز 72 بايتًا، ثم أكدها.")
            return
        if not self.db.create_user(username, password, "admin"):
            QMessageBox.critical(self, "تعذر إنشاء الحساب", "تعذر إنشاء الحساب. تحقق من اسم المستخدم وحاول مجددًا.")
            return
        self.accept()

    @staticmethod
    def _update_strength(label, password):
        hint, color_key = password_strength_hint(password)
        color = COLORS.get(color_key, COLORS["TEXT_SECONDARY"])
        label.setText(hint)
        label.setStyleSheet(f"color: {color};")

class LoginDialog(QDialog):
    """Modal dialog for User Authentication."""
    
    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self.authenticated_role = None
        self.authenticated_username = None
        
        self.setWindowTitle("تسجيل الدخول | Login")
        configure_dialog_size(self, preferred=(520, 380), minimum=(400, 300))
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
        self.username_input.setMaxLength(128)
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
        pw = self.password_input.text()
        
        if not user or not pw:
            QMessageBox.warning(self, "خطأ", "الرجاء إدخال اسم المستخدم وكلمة المرور.")
            return
            
        success, role, dept = self.db.authenticate_user(user, pw)
        
        if success:
            if self.db.user_totp_enabled(user):
                code, accepted = QInputDialog.getText(
                    self,
                    "التحقق الثنائي",
                    "أدخل رمز تطبيق المصادقة أو أحد أكواد الاسترداد لمرة واحدة:",
                    QLineEdit.EchoMode.Normal,
                )
                if not accepted:
                    return
                if not self.db.complete_totp_auth(user, code):
                    self.password_input.clear()
                    remaining = self.db.get_login_lock_remaining(user)
                    if remaining:
                        QMessageBox.warning(self, "تم إيقاف تسجيل الدخول مؤقتًا", f"تجاوزت محاولات التحقق. أعد المحاولة بعد {remaining} ثانية.")
                    else:
                        QMessageBox.critical(self, "فشل التحقق", "رمز المصادقة غير صحيح أو انتهت صلاحيته.")
                    return
            self.authenticated_role = role
            self.authenticated_username = user
            self.authenticated_department = dept
            self.accept()
        else:
            self.password_input.clear()
            remaining = self.db.get_login_lock_remaining(user)
            if remaining:
                minutes, seconds = divmod(remaining, 60)
                wait_text = f"{minutes} دقيقة و{seconds} ثانية" if minutes else f"{seconds} ثانية"
                QMessageBox.warning(
                    self,
                    "تم إيقاف تسجيل الدخول مؤقتًا",
                    f"تجاوزت عدد المحاولات المسموح. أعد المحاولة بعد {wait_text}.",
                )
            else:
                QMessageBox.critical(self, "فشل", "اسم المستخدم أو كلمة المرور غير صحيحة.")


class PasswordChangeDialog(QDialog):
    """Allow an authenticated user to change their own password."""

    def __init__(self, db: SecureDatabase, username: str, parent=None):
        super().__init__(parent)
        self.db = db
        self.username = username
        self.setWindowTitle("تغيير كلمة المرور")
        configure_dialog_size(self, preferred=(540, 390), minimum=(420, 330))
        layout = QVBoxLayout(self)
        title = QLabel(f"تغيير كلمة مرور الحساب: {username}")
        title.setStyleSheet(f"color: {COLORS['ACCENT']}; font-size: 17px; font-weight: bold;")
        layout.addWidget(title)
        layout.addWidget(QLabel(f"استخدم عبارة مرور من {MIN_PASSWORD_LENGTH} محرفًا على الأقل. سيتم طلب كلمة المرور الحالية للتحقق من هويتك."))

        self.current_password = QLineEdit()
        self.current_password.setPlaceholderText("كلمة المرور الحالية")
        self.current_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password = QLineEdit()
        self.new_password.setPlaceholderText("كلمة المرور الجديدة")
        self.new_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.strength_hint = QLabel()
        self.new_password.textChanged.connect(lambda text: FirstRunAdminDialog._update_strength(self.strength_hint, text))
        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText("تأكيد كلمة المرور الجديدة")
        self.confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        for field in (self.current_password, self.new_password, self.confirm_password):
            layout.addWidget(field)
            if field is self.new_password:
                layout.addWidget(self.strength_hint)

        buttons = QHBoxLayout()
        save = QPushButton("حفظ كلمة المرور")
        cancel = QPushButton("إلغاء")
        save.clicked.connect(self._save)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(save)
        buttons.addWidget(cancel)
        layout.addLayout(buttons)

    def _save(self):
        new_password = self.new_password.text()
        if not password_is_valid(new_password):
            QMessageBox.warning(self, "كلمة مرور غير صالحة", f"استخدم عبارة مرور من {MIN_PASSWORD_LENGTH} محرفًا على الأقل، متنوعة وغير متكررة، ولا تتجاوز 72 بايتًا.")
            return
        if new_password != self.confirm_password.text():
            QMessageBox.warning(self, "عدم تطابق", "تأكيد كلمة المرور لا يطابق كلمة المرور الجديدة.")
            return
        if not self.db.change_user_password(self.username, self.current_password.text(), new_password):
            self.current_password.clear()
            QMessageBox.warning(self, "تعذر التغيير", "كلمة المرور الحالية غير صحيحة أو تعذر تحديث كلمة المرور.")
            return
        self.db.log_audit(self.username, "PASSWORD_CHANGE", "User changed their own password.")
        QMessageBox.information(self, "تم التغيير", "تم تحديث كلمة المرور بنجاح.")
        self.accept()


class SessionLockDialog(QDialog):
    """Require the current user's credentials before revealing the session again."""

    def __init__(self, db: SecureDatabase, username: str, parent=None):
        super().__init__(parent)
        self.db = db
        self.username = username
        self.setWindowTitle("الجلسة مقفلة")
        configure_dialog_size(self, preferred=(500, 300), minimum=(400, 260))
        layout = QVBoxLayout(self)
        title = QLabel("الجلسة مقفلة")
        title.setStyleSheet(f"color: {COLORS['ACCENT']}; font-size: 20px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addWidget(QLabel(f"أدخل كلمة مرور المستخدم {username} للمتابعة."))
        self.password = QLineEdit()
        self.password.setPlaceholderText("كلمة المرور")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.returnPressed.connect(self._unlock)
        layout.addWidget(self.password)
        buttons = QHBoxLayout()
        unlock = QPushButton("إلغاء القفل")
        quit_button = QPushButton("إنهاء التطبيق")
        unlock.clicked.connect(self._unlock)
        quit_button.clicked.connect(self.reject)
        buttons.addWidget(unlock)
        buttons.addWidget(quit_button)
        layout.addLayout(buttons)

    def _unlock(self):
        success, _, _ = self.db.authenticate_user(self.username, self.password.text())
        if success:
            self.accept()
            return
        self.password.clear()
        remaining = self.db.get_login_lock_remaining(self.username)
        if remaining:
            minutes, seconds = divmod(remaining, 60)
            wait_text = f"{minutes} دقيقة و{seconds} ثانية" if minutes else f"{seconds} ثانية"
            QMessageBox.warning(self, "الجلسة ما زالت مقفلة", f"تجاوزت محاولات التحقق. أعد المحاولة بعد {wait_text}.")
        else:
            QMessageBox.warning(self, "تعذر إلغاء القفل", "كلمة المرور غير صحيحة.")
