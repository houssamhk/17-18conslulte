from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
                             QDialog, QLineEdit, QComboBox, QFormLayout, QDialogButtonBox,
                             QMessageBox, QFileDialog)
from PyQt6.QtCore import Qt
from storage.secure_db import SecureDatabase
from .theme import COLORS


class TaskBuilderDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("مهمة فحص جديدة (New Scheduled Task)")
        self.resize(500, 300)
        
        layout = QFormLayout(self)
        
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
        
        layout.addRow("اسم المهمة (Task Name):", self.name_input)
        layout.addRow("المسار (Directory Path):", path_layout)
        layout.addRow("الجدول الزمني (Schedule):", self.cron_combo)
        layout.addRow("استراتيجية الحجب (Strategy):", self.strategy_combo)
        
        self.btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.btns.accepted.connect(self.accept)
        self.btns.rejected.connect(self.reject)
        layout.addRow(self.btns)
        
    def browse_dir(self):
        directory = QFileDialog.getExistingDirectory(self, "اختر المجلد (Select Directory)")
        if directory:
            self.path_input.setText(directory)
            
    def get_data(self):
        return {
            "name": self.name_input.text(),
            "path": self.path_input.text(),
            "cron": self.cron_combo.currentText(),
            "strategy": self.strategy_combo.currentText()
        }


class ScheduledTasksPageWidget(QWidget):
    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
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
        layout.addLayout(header_layout)
        
        # Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["الاسم", "المسار", "الجدول", "الحالة", "آخر تشغيل", "إحصائيات (ملفات/انتهاكات)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
        
    def load_data(self):
        self.table.setRowCount(0)
        tasks = self.db.get_scheduled_tasks()
        
        for i, t in enumerate(tasks):
            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(t[1]))
            self.table.setItem(i, 1, QTableWidgetItem(t[2]))
            self.table.setItem(i, 2, QTableWidgetItem(t[3]))
            
            status = "نشط (Enabled)" if t[5] else "متوقف (Disabled)"
            self.table.setItem(i, 3, QTableWidgetItem(status))
            
            last_run = str(t[6]) if t[6] else "لم يتم التشغيل (Never)"
            self.table.setItem(i, 4, QTableWidgetItem(last_run))
            
            stats = f"{t[7] or 0} / {t[8] or 0}"
            self.table.setItem(i, 5, QTableWidgetItem(stats))
            
    def on_add_task(self):
        dlg = TaskBuilderDialog(self)
        if dlg.exec():
            data = dlg.get_data()
            if not data['name'] or not data['path']:
                QMessageBox.warning(self, "خطأ", "يجب إدخال الاسم والمسار.")
                return
                
            self.db.save_scheduled_task(data['name'], data['path'], data['cron'], data['strategy'], "admin")
            self.load_data()
