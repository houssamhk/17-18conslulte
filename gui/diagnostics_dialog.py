from PyQt6.QtCore import Qt
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from engine.system_diagnostics import collect_system_diagnostics
from .dialog_utils import configure_dialog_size
from .theme import COLORS


class SystemDiagnosticsDialog(QDialog):
    """Show read-only readiness and dependency diagnostics."""

    def __init__(self, db, engine=None, parent=None):
        super().__init__(parent)
        self.db = db
        self.engine = engine
        self.setWindowTitle("فحص جاهزية النظام")
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        configure_dialog_size(self, preferred=(980, 700), minimum=(680, 480))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(12)

        title = QLabel("تشخيص مكونات التطبيق")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        layout.addWidget(title)
        intro = QLabel("فحص للقراءة فقط؛ لا يغيّر قاعدة البيانات أو إعدادات التطبيق.")
        intro.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']};")
        layout.addWidget(intro)

        self.summary = QLabel()
        self.summary.setStyleSheet(f"font-weight: bold; color: {COLORS['ACCENT']};")
        layout.addWidget(self.summary)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["المكوّن", "الحالة", "التفاصيل"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.table, 1)

        actions = QHBoxLayout()
        refresh = QPushButton("إعادة الفحص")
        refresh.clicked.connect(self.refresh)
        actions.addWidget(refresh)
        copy = QPushButton("نسخ التقرير")
        copy.clicked.connect(self.copy_report)
        actions.addWidget(copy)
        actions.addStretch()
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.accept)
        actions.addWidget(close)
        layout.addLayout(actions)
        self.refresh()

    def refresh(self):
        results = collect_system_diagnostics(self.db, self.engine)
        self.table.setRowCount(len(results))
        counts = {}
        colors = {
            "جاهز": COLORS["SUCCESS"],
            "فشل": COLORS["ERROR"],
            "يحتاج إعدادًا": COLORS["WARNING"],
            "تحذير": COLORS["WARNING"],
            "غير مفعّل": COLORS["TEXT_SECONDARY"],
            "معلومات": COLORS["TEXT_SECONDARY"],
            "غير مثبت": COLORS["ERROR"],
        }
        for row, result in enumerate(results):
            counts[result["status"]] = counts.get(result["status"], 0) + 1
            for column, key in enumerate(("name", "status", "details")):
                item = QTableWidgetItem(result[key])
                item.setToolTip(result[key])
                if column == 1:
                    item.setForeground(QBrush(QColor(COLORS["BG_MAIN"])))
                    item.setBackground(QBrush(QColor(colors.get(result["status"], COLORS["BG_BUTTON"]))))
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, column, item)
            self.table.setRowHeight(row, 38)

        ready_count = counts.get("جاهز", 0)
        attention_count = sum(counts.get(status, 0) for status in ("فشل", "يحتاج إعدادًا", "تحذير", "غير مثبت"))
        self.summary.setText(f"جاهز: {ready_count}    |    يحتاج انتباهًا: {attention_count}")

    def copy_report(self):
        lines = ["تقرير جاهزية Alg-PII Engine"]
        for row in range(self.table.rowCount()):
            lines.append(" | ".join(self.table.item(row, col).text() for col in range(3)))
        QApplication.clipboard().setText("\n".join(lines))
