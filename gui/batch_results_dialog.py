import os

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
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

from .dialog_utils import configure_dialog_size
from .theme import COLORS


class BatchResultsDialog(QDialog):
    """Review batch outcomes and open generated files from one place."""

    def __init__(self, output_dir, processed, failures, review_details, file_results, summary, parent=None):
        super().__init__(parent)
        self.output_dir = output_dir
        self.file_results = file_results
        self.setWindowTitle("نتائج الفحص المجمّع")
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        configure_dialog_size(self, preferred=(1180, 760), minimum=(720, 500))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(12)

        title = QLabel("ملخص نتائج الفحص")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        layout.addWidget(title)

        stats = QLabel(
            f"عولج بنجاح: {processed}    |    تعذر: {len(failures)}    |    يحتاج مراجعة: {len(review_details)}"
        )
        stats.setStyleSheet(f"color: {COLORS['ACCENT']}; font-weight: bold;")
        layout.addWidget(stats)

        summary_label = QLabel(summary)
        summary_label.setWordWrap(True)
        summary_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(summary_label)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["الملف", "الحالة", "الكيانات", "التكرار", "المخاطر", "التحقق"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._show_selected_details)
        layout.addWidget(self.table, 1)

        self.details = QLabel("حدد ملفًا لعرض تفاصيله ومخرجاته.")
        self.details.setWordWrap(True)
        self.details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.details.setMinimumHeight(54)
        self.details.setStyleSheet(
            f"background-color: {COLORS['BG_PANEL']}; border: 1px solid {COLORS['BG_BUTTON']}; "
            "border-radius: 6px; padding: 10px;"
        )
        layout.addWidget(self.details)

        actions = QHBoxLayout()
        self.open_file_button = QPushButton("فتح الملف المحدد")
        self.open_file_button.clicked.connect(self._open_selected_file)
        self.open_file_button.setEnabled(False)
        actions.addWidget(self.open_file_button)

        open_folder = QPushButton("فتح مجلد النتائج")
        open_folder.clicked.connect(lambda: self._open_path(self.output_dir))
        actions.addWidget(open_folder)

        manifest_button = QPushButton("فتح بيان JSON")
        manifest_button.clicked.connect(lambda: self._open_path(os.path.join(self.output_dir, "batch_manifest.json")))
        actions.addWidget(manifest_button)
        actions.addStretch()

        close_buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_buttons.rejected.connect(self.accept)
        actions.addWidget(close_buttons)
        layout.addLayout(actions)

        failure_by_source = {name: reason for name, reason in failures}
        for result in file_results:
            source = result.get("source", "")
            result_status = result.get("status")
            status = {
                "success": "اجتاز التحقق",
                "review_required": "يحتاج مراجعة",
                "failed": "تعذر",
            }.get(result_status, "غير معروف")
            checks = [result.get("text_verification"), result.get("original_format_verification")]
            checks = [check for check in checks if check]
            if checks:
                passed_checks = sum(bool(check.get("passed")) for check in checks)
                failed_checks = [check for check in checks if not check.get("passed")]
                verification_text = f"اجتاز {passed_checks}/{len(checks)}"
                if failed_checks:
                    remaining = max(check.get("remaining_original_count", 0) for check in failed_checks)
                    candidates = max(check.get("additional_candidate_count", 0) for check in failed_checks)
                    verification_text += f" ({remaining} متبقية، {candidates} محتملة)"
            else:
                verification_text = "تعذر التحقق"
            values = (
                source,
                status,
                str(result.get("entity_count", "—")),
                str(result.get("duplicates_found", "—")),
                str(result.get("risk_level", "—")),
                verification_text,
            )
            row = self.table.rowCount()
            self.table.insertRow(row)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, column, item)
            self.table.item(row, 0).setData(Qt.ItemDataRole.UserRole, result)
            if result_status == "failed":
                self.table.item(row, 1).setForeground(Qt.GlobalColor.red)
            elif result_status == "review_required":
                self.table.item(row, 4).setForeground(Qt.GlobalColor.yellow)
            if source in failure_by_source:
                result.setdefault("error", failure_by_source[source])

        if self.table.rowCount():
            self.table.selectRow(0)

    def _selected_result(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _show_selected_details(self):
        result = self._selected_result()
        if not result:
            self.details.setText("حدد ملفًا لعرض تفاصيله ومخرجاته.")
            self.open_file_button.setEnabled(False)
            return

        details = []
        if result.get("error"):
            details.append("السبب: " + str(result["error"]))
        if result.get("format_notes"):
            details.extend(result["format_notes"])
        for title, key in (("تحقق النص", "text_verification"), ("تحقق الصيغة الأصلية", "original_format_verification")):
            verification = result.get(key)
            if verification:
                details.append(f"{title}: {verification.get('details', '')}")
        if result.get("status") == "review_required":
            details.append("نُقلت المخرجات إلى مجلد needs_review. لا تشاركها قبل معالجة ملاحظات التحقق وإعادة الفحص.")
        elif result.get("status") == "failed" and any(
            result.get(key) for key in ("anonymized_original_format", "anonymized_text")
        ):
            details.append("نُقلت الملفات الناتجة إلى مجلد needs_review لتعذر إكمال المعالجة أو التحقق؛ لا تشاركها قبل مراجعتها.")
        output_paths = [
            result.get("anonymized_original_format"),
            result.get("anonymized_text"),
            result.get("report_pdf"),
        ]
        details.append("الملفات الناتجة: " + ("، ".join(path for path in output_paths if path) or "لا توجد"))
        self.details.setText("\n".join(details))
        self.open_file_button.setEnabled(any(output_paths))

    def _open_selected_file(self):
        result = self._selected_result()
        if not result:
            return
        relative = result.get("anonymized_original_format") or result.get("anonymized_text") or result.get("report_pdf")
        if relative:
            self._open_path(os.path.join(self.output_dir, relative))

    @staticmethod
    def _open_path(path):
        if os.path.exists(path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))
