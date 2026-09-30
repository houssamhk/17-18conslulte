from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
                             QDialog, QLineEdit, QComboBox, QFormLayout, QDialogButtonBox,
                             QMessageBox, QFileDialog)
from PyQt6.QtCore import Qt, QTimer
from storage.secure_db import SecureDatabase
from .theme import COLORS
from .dialog_utils import configure_dialog_size


class TaskBuilderDialog(QDialog):
    def __init__(self, db: SecureDatabase, parent=None, initial_task=None):
        super().__init__(parent)
        self.setWindowTitle("تعديل مهمة الفحص" if initial_task else "مهمة فحص جديدة (New Scheduled Task)")
        configure_dialog_size(self, preferred=(680, 520), minimum=(480, 380))
        
        layout = QFormLayout(self)

        guidance = QLabel(
            "ملاحظة: المهمة تفحص المجلد وتحدّث سجل النتائج والسياسات فقط. "
            "لا تعدّل الملفات الأصلية ولا تنشئ نسخًا معمّاة تلقائيًا."
        )
        guidance.setWordWrap(True)
        layout.addRow(guidance)
        
        self.name_input = QLineEdit()
        
        self.path_input = QLineEdit()
        self.btn_browse = QPushButton("استعراض (Browse)")
        self.btn_browse.clicked.connect(self.browse_dir)
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(self.btn_browse)
        
        self.cron_combo = QComboBox()
        self.cron_combo.addItems(["Daily (0 2 * * *)", "Weekly (0 2 * * 0)", "Monthly (0 2 1 * *)"])
        self.cron_combo.setEditable(True) # Allow custom
        
        self.strategy_combo = QComboBox()
        self.strategy_combo.addItems(["legal_mask", "full_mask", "partial_mask", "pseudonymize"])

        self.department_combo = QComboBox()
        self.department_combo.addItem("غير محدد — مهمة إدارية عامة", None)
        for _department_id, name, _description in db.get_departments():
            self.department_combo.addItem(name, name)
        
        layout.addRow("اسم المهمة (Task Name):", self.name_input)
        layout.addRow("المسار (Directory Path):", path_layout)
        layout.addRow("الجدول الزمني (Schedule):", self.cron_combo)
        layout.addRow("استراتيجية التحليل (Analysis Strategy):", self.strategy_combo)
        layout.addRow("قسم نتائج الفحص:", self.department_combo)
        
        self.btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.btns.accepted.connect(self.accept)
        self.btns.rejected.connect(self.reject)
        layout.addRow(self.btns)

        if initial_task:
            self.name_input.setText(initial_task[1])
            self.path_input.setText(initial_task[2])
            self.cron_combo.setEditText(initial_task[3])
            strategy_index = self.strategy_combo.findText(initial_task[4])
            if strategy_index >= 0:
                self.strategy_combo.setCurrentIndex(strategy_index)
            department_index = self.department_combo.findData(initial_task[10])
            self.department_combo.setCurrentIndex(department_index if department_index >= 0 else 0)
        
    def browse_dir(self):
        directory = QFileDialog.getExistingDirectory(self, "اختر المجلد (Select Directory)")
        if directory:
            self.path_input.setText(directory)
            
    def get_data(self):
        return {
            "name": self.name_input.text(),
            "path": self.path_input.text(),
            "cron": self.cron_combo.currentText(),
            "strategy": self.strategy_combo.currentText(),
            "department": self.department_combo.currentData(),
        }


class ScheduledTasksPageWidget(QWidget):
    def __init__(self, db: SecureDatabase, username: str = "system", scheduler=None, parent=None):
        super().__init__(parent)
        self.db = db
        self.username = username
        self.scheduler = scheduler
        self._init_ui()
        self.load_data()
        
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("المهام المجدولة (Scheduled Scans)")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        add_btn = QPushButton("مهمة جديدة (New Task)")
        add_btn.setStyleSheet(f"background-color: {COLORS['SUCCESS']}; color: white; padding: 8px;")
        add_btn.clicked.connect(self.on_add_task)
        header_layout.addWidget(add_btn)
        refresh_btn = QPushButton("تحديث")
        refresh_btn.clicked.connect(self.load_data)
        header_layout.addWidget(refresh_btn)
        layout.addLayout(header_layout)
        
        # Table
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(["الاسم", "المسار", "الجدول", "القسم", "الحالة", "آخر تشغيل", "إحصائيات (ملفات/انتهاكات/إخفاقات)", "تعديل", "إجراءات"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(15000)
        self.refresh_timer.timeout.connect(self.load_data)
        self.refresh_timer.start()
        
    def load_data(self):
        self.table.setRowCount(0)
        tasks = self.db.get_scheduled_tasks()
        
        for i, t in enumerate(tasks):
            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(t[1]))
            self.table.setItem(i, 1, QTableWidgetItem(t[2]))
            self.table.setItem(i, 2, QTableWidgetItem(t[3]))
            
            self.table.setItem(i, 3, QTableWidgetItem(t[10] or "مهمة عامة"))

            if len(t) > 11 and t[11]:
                status = f"قيد التشغيل منذ {t[11]}"
            else:
                task_enabled = "نشط" if t[5] else "متوقف"
                last_status = {
                    "SUCCESS": "آخر تشغيل ناجح",
                    "PARTIAL": "آخر تشغيل جزئي",
                    "FAILED": "آخر تشغيل فاشل",
                    "INTERRUPTED": "آخر تشغيل منقطع",
                }.get(t[13] if len(t) > 13 else None)
                status = f"{task_enabled} — {last_status}" if last_status else task_enabled
            self.table.setItem(i, 4, QTableWidgetItem(status))
            
            last_run = str(t[6]) if t[6] else "لم يتم التشغيل (Never)"
            self.table.setItem(i, 5, QTableWidgetItem(last_run))
            
            errors = (t[14] or 0) if len(t) > 14 else 0
            stats = f"{t[7] or 0} / {t[8] or 0} / {errors}"
            self.table.setItem(i, 6, QTableWidgetItem(stats))

            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 2, 4, 2)
            run_button = QPushButton("تشغيل الآن")
            run_button.clicked.connect(
                lambda _checked=False, task_id=t[0], task_name=t[1]:
                self._run_task_now(task_id, task_name)
            )
            run_button.setEnabled(bool(t[5]) and not (len(t) > 11 and t[11]) and self.scheduler is not None)
            actions_layout.addWidget(run_button)
            toggle_button = QPushButton("إيقاف" if t[5] else "تفعيل")
            toggle_button.clicked.connect(
                lambda _checked=False, task_id=t[0], enabled=not bool(t[5]):
                self._set_task_enabled(task_id, enabled)
            )
            delete_button = QPushButton("حذف")
            delete_button.clicked.connect(
                lambda _checked=False, task_id=t[0], task_name=t[1]:
                self._delete_task(task_id, task_name)
            )
            actions_layout.addWidget(toggle_button)
            actions_layout.addWidget(delete_button)
            edit_button = QPushButton("تعديل")
            edit_button.clicked.connect(
                lambda _checked=False, task_id=t[0]: self._edit_task(task_id)
            )
            if len(t) > 11 and t[11]:
                edit_button.setEnabled(False)
                edit_button.setToolTip("لا يمكن تعديل مهمة أثناء تشغيلها")
            self.table.setCellWidget(i, 7, edit_button)
            self.table.setCellWidget(i, 8, actions_widget)

    def _run_task_now(self, task_id: int, task_name: str):
        if not self.scheduler or not self.scheduler.request_task_run(task_id):
            QMessageBox.information(self, "تعذر بدء المهمة", "المهمة قيد التشغيل أو طُلب تشغيلها بالفعل.")
            return
        QMessageBox.information(self, "تمت جدولة التشغيل", f"سيبدأ فحص «{task_name}» في أقرب فرصة.")

    def _edit_task(self, task_id: int):
        task = next((row for row in self.db.get_scheduled_tasks() if row[0] == task_id), None)
        if not task:
            QMessageBox.warning(self, "المهمة غير موجودة", "تم حذف المهمة أو لم تعد متاحة.")
            self.load_data()
            return
        dlg = TaskBuilderDialog(self.db, self, initial_task=task)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        validated = self._validated_task_data(dlg)
        if not validated:
            return
        data, cron = validated
        try:
            if self.db.update_scheduled_task(
                task_id, data["name"], data["path"], cron, data["strategy"],
                data["department"], self.username,
            ):
                self.load_data()
        except ValueError as exc:
            QMessageBox.warning(self, "تعذر تعديل المهمة", str(exc))

    def _set_task_enabled(self, task_id: int, enabled: bool):
        if self.db.set_scheduled_task_enabled(task_id, enabled, self.username):
            self.load_data()

    def _delete_task(self, task_id: int, task_name: str):
        answer = QMessageBox.question(
            self,
            "تأكيد حذف المهمة",
            f"سيؤدي حذف «{task_name}» إلى إزالة المهمة وبيان تتبع الملفات المرتبط بها. لن تُحذف سجلات الفحص السابقة. هل تتابع؟",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            try:
                if self.db.delete_scheduled_task(task_id, self.username):
                    self.load_data()
            except ValueError as exc:
                QMessageBox.warning(self, "المهمة قيد التشغيل", str(exc))
            
    def on_add_task(self):
        dlg = TaskBuilderDialog(self.db, self)
        if dlg.exec():
            validated = self._validated_task_data(dlg)
            if not validated:
                return
            data, cron = validated
            self.db.save_scheduled_task(
                data['name'], data['path'], cron, data['strategy'], self.username, data['department']
            )
            self.load_data()

    @staticmethod
    def _validated_task_data(dialog):
        data = dialog.get_data()
        data["name"] = data["name"].strip()
        data["path"] = data["path"].strip()
        if not data["name"] or not data["path"]:
            QMessageBox.warning(dialog, "بيانات مطلوبة", "يجب إدخال اسم المهمة والمجلد.")
            return None
        import os
        if not os.path.isdir(data["path"]):
            QMessageBox.warning(dialog, "مسار غير صالح", "اختر مجلدًا موجودًا ويمكن للتطبيق الوصول إليه.")
            return None
        from croniter import croniter
        import re
        cron = data["cron"].strip()
        preset = re.fullmatch(r".*\(([^()]*)\)", cron)
        if preset:
            cron = preset.group(1).strip()
        if not croniter.is_valid(cron):
            QMessageBox.warning(dialog, "جدول غير صالح", "أدخل تعبير cron صالحًا من خمسة حقول.")
            return None
        return data, cron
