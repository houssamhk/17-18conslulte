from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QMessageBox,
    QPlainTextEdit,
)

from .dialog_utils import configure_dialog_size
from .theme import COLORS


class TotpManagementDialog(QDialog):
    """Self-service enrollment and removal of authenticator-app TOTP."""

    def __init__(self, db, username, enabled, parent=None):
        super().__init__(parent)
        self.db = db
        self.username = username
        self.enabled = enabled
        self.secret_value = ""
        self.setWindowTitle("المصادقة الثنائية")
        configure_dialog_size(self, preferred=(600, 460), minimum=(440, 360))
        layout = QVBoxLayout(self)
        title = QLabel("إعداد المصادقة الثنائية" if not enabled else "تعطيل المصادقة الثنائية")
        title.setStyleSheet(f"color: {COLORS['ACCENT']}; font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        if enabled:
            layout.addWidget(QLabel("أدخل كلمة مرورك وكود المصادقة الحالي لإزالة العامل الثاني من حسابك."))
        else:
            layout.addWidget(QLabel(
                "اربط الحساب بتطبيق مصادقة يدعم TOTP. المفتاح يُنشأ محليًا ويُحفظ داخل قاعدة البيانات المشفرة. "
                "احفظه في تطبيق المصادقة ثم أدخل الرمز الحالي لتأكيد الإعداد."
            ))

        self.password = QLineEdit()
        self.password.setPlaceholderText("كلمة المرور الحالية")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password)

        if enabled:
            self.code = QLineEdit()
            self.code.setPlaceholderText("رمز المصادقة الحالي (6 أرقام)")
            self.code.setMaxLength(12)
            layout.addWidget(self.code)
            primary = QPushButton("تعطيل المصادقة الثنائية")
            primary.clicked.connect(self._disable)
        else:
            self.secret = QLineEdit()
            self.secret.setReadOnly(True)
            self.secret.setPlaceholderText("سيظهر مفتاح الربط بعد التحقق من كلمة المرور")
            layout.addWidget(self.secret)
            self.generate_button = QPushButton("التحقق وعرض مفتاح الربط")
            self.generate_button.clicked.connect(self._generate_secret)
            layout.addWidget(self.generate_button)
            self.code = QLineEdit()
            self.code.setPlaceholderText("رمز المصادقة لإكمال الإعداد")
            self.code.setMaxLength(12)
            self.code.setEnabled(False)
            layout.addWidget(self.code)
            primary = QPushButton("تفعيل المصادقة الثنائية")
            primary.clicked.connect(self._enable)

        cancel = QPushButton("إلغاء")
        cancel.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addWidget(primary)
        buttons.addWidget(cancel)
        layout.addLayout(buttons)

    def _generate_secret(self):
        secret = self.db.begin_totp_enrollment(self.username, self.password.text())
        if not secret:
            QMessageBox.warning(self, "تعذر الإعداد", "كلمة المرور غير صحيحة أو أن المصادقة الثنائية مفعلة بالفعل.")
            self.password.clear()
            return
        self.secret_value = secret
        self.secret.setText(secret)
        self.code.setEnabled(True)
        self.password.setEnabled(False)
        self.generate_button.setEnabled(False)

    def _enable(self):
        if not self.secret_value:
            QMessageBox.information(self, "خطوة مطلوبة", "تحقق من كلمة المرور واعرض مفتاح الربط أولًا.")
            return
        recovery_codes = self.db.enable_totp(self.username, self.password.text(), self.secret_value, self.code.text())
        if not recovery_codes:
            QMessageBox.warning(self, "تعذر التفعيل", "الرمز غير صحيح أو انتهت صلاحيته. تحقق من وقت الجهاز وتطبيق المصادقة.")
            self.code.clear()
            return
        self.db.log_audit(self.username, "TOTP_ENABLED", "User enabled authenticator-app second factor.")
        codes_text = "\n".join(recovery_codes)
        QMessageBox.information(
            self,
            "تم التفعيل — احفظ أكواد الاسترداد",
            "تم تفعيل المصادقة الثنائية. سيُطلب الرمز عند تسجيل الدخول التالي.\n\n"
            "كل كود استرداد صالح لاستخدام واحد فقط. احفظ هذه الأكواد الآن؛ لن يمكن عرضها مرة أخرى:\n\n"
            f"{codes_text}",
        )
        self.accept()


class TotpRecoveryDialog(QDialog):
    """Rotate and reveal one-time recovery codes after strong reauthentication."""

    def __init__(self, db, username, parent=None):
        super().__init__(parent)
        self.db = db
        self.username = username
        self.setWindowTitle("أكواد استرداد المصادقة الثنائية")
        configure_dialog_size(self, preferred=(620, 500), minimum=(460, 390))
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            "أدخل كلمة المرور ورمز TOTP الحالي لإبطال الأكواد القديمة وإنشاء مجموعة جديدة. "
            "تظهر المجموعة مرة واحدة فقط؛ انسخها إلى مكان آمن."
        ))
        self.password = QLineEdit()
        self.password.setPlaceholderText("كلمة المرور الحالية")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.code = QLineEdit()
        self.code.setPlaceholderText("رمز تطبيق المصادقة الحالي")
        self.code.setMaxLength(12)
        layout.addWidget(self.password)
        layout.addWidget(self.code)
        self.codes = QPlainTextEdit()
        self.codes.setReadOnly(True)
        self.codes.setPlaceholderText("ستظهر الأكواد الجديدة هنا بعد التحقق")
        self.codes.setVisible(False)
        layout.addWidget(self.codes, 1)
        buttons = QHBoxLayout()
        self.rotate_btn = QPushButton("إصدار أكواد جديدة")
        self.rotate_btn.clicked.connect(self._rotate)
        close = QPushButton("إغلاق")
        close.clicked.connect(self.accept)
        buttons.addWidget(self.rotate_btn)
        buttons.addWidget(close)
        layout.addLayout(buttons)

    def _rotate(self):
        codes = self.db.rotate_totp_recovery_codes(
            self.username, self.password.text(), self.code.text()
        )
        if not codes:
            QMessageBox.warning(self, "تعذر إصدار الأكواد", "تحقق من كلمة المرور ورمز المصادقة الحالي.")
            self.password.clear()
            self.code.clear()
            return
        self.db.log_audit(self.username, "TOTP_RECOVERY_ROTATED", "User replaced their one-time recovery codes.")
        self.codes.setPlainText("\n".join(codes))
        self.codes.setVisible(True)
        self.password.clear()
        self.code.clear()
        self.password.setEnabled(False)
        self.code.setEnabled(False)
        self.rotate_btn.setEnabled(False)

    def _disable(self):
        if not self.db.disable_totp(self.username, self.password.text(), self.code.text()):
            QMessageBox.warning(self, "تعذر التعطيل", "تحقق من كلمة المرور والرمز الحالي.")
            self.password.clear()
            self.code.clear()
            return
        self.db.log_audit(self.username, "TOTP_DISABLED", "User disabled authenticator-app second factor.")
        QMessageBox.information(self, "تم التعطيل", "تم تعطيل المصادقة الثنائية.")
        self.accept()
