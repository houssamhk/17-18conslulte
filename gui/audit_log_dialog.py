import csv

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QHeaderView,
)

from storage.secure_db import SecureDatabase
from .dialog_utils import configure_dialog_size


class AuditLogDialog(QDialog):
    """Search and export the local audit trail."""

    HEADERS = ["التاريخ والوقت", "المستخدم", "الإجراء", "التفاصيل"]

    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self.rows = []
        self.setWindowTitle("سجل التدقيق")
        configure_dialog_size(self, preferred=(1120, 720), minimum=(760, 500))

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("راجع أحداث النظام وابحث فيها. فحص السلامة يستخدم HMAC بمفتاح التخزين المحمي؛ السجلات السابقة للتحديث تُعتمد كسلسلة تأسيسية عند الترقية. ملف CSV يضم النتائج الظاهرة فقط."))

        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("بحث في التاريخ والمستخدم والإجراء والتفاصيل")
        self.search.returnPressed.connect(self.refresh)
        self.username = QLineEdit()
        self.username.setPlaceholderText("تصفية باسم المستخدم")
        self.username.returnPressed.connect(self.refresh)
        self.action = QComboBox()
        self.action.addItem("كل الإجراءات", "")
        for action in self.db.get_audit_actions():
            self.action.addItem(action, action)
        self.action.currentIndexChanged.connect(self.refresh)
        filters.addWidget(self.search, 2)
        filters.addWidget(self.username, 1)
        filters.addWidget(self.action, 1)
        layout.addLayout(filters)

        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, 1)

        footer = QHBoxLayout()
        self.count_label = QLabel()
        self.integrity_label = QLabel("لم يُفحص تسلسل السجل بعد.")
        verify = QPushButton("فحص سلامة السجل")
        verify.setToolTip("يكشف تغيير محتوى السجلات أو كسر الروابط بعد إنشاء البصمات المحمية.")
        verify.clicked.connect(self.verify_integrity)
        refresh = QPushButton("تحديث")
        refresh.clicked.connect(self.refresh)
        export = QPushButton("تصدير النتائج إلى CSV")
        export.clicked.connect(self.export_csv)
        close = QPushButton("إغلاق")
        close.clicked.connect(self.accept)
        footer.addWidget(self.count_label)
        footer.addWidget(self.integrity_label, 1)
        footer.addStretch()
        footer.addWidget(verify)
        footer.addWidget(refresh)
        footer.addWidget(export)
        footer.addWidget(close)
        layout.addLayout(footer)
        self.refresh()

    def refresh(self):
        self.rows = self.db.get_audit_log(
            limit=10000,
            search=self.search.text(),
            username=self.username.text(),
            action=self.action.currentData() or "",
        )
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            for column, value in enumerate(row):
                item = QTableWidgetItem(str(value or ""))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row_index, column, item)
        self.count_label.setText(f"عدد النتائج: {len(self.rows)}" + (" (الحد الأقصى 10,000)" if len(self.rows) == 10000 else ""))

    def verify_integrity(self):
        result = self.db.verify_audit_integrity()
        if not result["valid"]:
            if result.get("reason") == "empty_log":
                message = "سجل التدقيق فارغ؛ لا توجد أحداث يمكن التحقق من سلامتها."
            elif result.get("reason") == "tail_anchor_mismatch":
                message = "لا تطابق آخر بصمة في قاعدة البيانات المرساة المحمية في Windows Credential Manager. قد تكون سجلات قد حُذفت أو عُدّلت."
            else:
                message = f"فشل فحص سلامة سجل التدقيق عند السجل رقم {result['entry_id']} ({result['reason']})."
            self.integrity_label.setText("تحذير: فشل فحص السلامة")
            QMessageBox.warning(self, "خلل في سجل التدقيق", message)
            return
        if result.get("truncated_prefix"):
            message = (
                f"اجتازت السجلات المتاحة فحص الروابط والبصمات ({result['count']} سجلًا)، "
                "لكن بداية السلسلة غير موجودة؛ قد يكون ذلك نتيجة تطبيق سياسة الاحتفاظ."
            )
            self.integrity_label.setText("السجل سليم من أول سجل متاح؛ البداية مقتطعة")
        else:
            message = f"اجتاز سجل التدقيق فحص السلامة ({result['count']} سجلًا)."
            self.integrity_label.setText("سجل التدقيق سليم")
        QMessageBox.information(self, "نتيجة فحص السلامة", message)

    def export_csv(self):
        if not self.rows:
            QMessageBox.information(self, "لا توجد نتائج", "لا توجد سجلات لتصديرها.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "تصدير سجل التدقيق", "audit_log.csv", "CSV (*.csv)")
        if not path:
            return
        if not path.lower().endswith(".csv"):
            path += ".csv"
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as output:
                writer = csv.writer(output)
                writer.writerow(self.HEADERS)
                safe_rows = []
                for row in self.rows:
                    safe_rows.append([
                        "'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")) else value
                        for value in row
                    ])
                writer.writerows(safe_rows)
            QMessageBox.information(self, "تم التصدير", f"تم تصدير {len(self.rows)} سجلًا إلى:\n{path}")
        except OSError as exc:
            QMessageBox.critical(self, "تعذر التصدير", f"تعذر حفظ الملف:\n{exc}")
