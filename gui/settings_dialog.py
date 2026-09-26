from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QComboBox, QCheckBox, 
                             QGroupBox, QFileDialog, QTabWidget, QWidget, QListWidget, QMessageBox)
from PyQt6.QtCore import pyqtSignal, Qt
from storage.secure_db import SecureDatabase
from engine.presets import INDUSTRY_PRESETS
from .theme import COLORS

class SettingsDialog(QDialog):
    """Settings dialog including Admin Management panels."""
    settings_changed = pyqtSignal(dict)
    
    def __init__(self, db: SecureDatabase, role: str, parent=None):
        super().__init__(parent)
        self.db = db
        self.role = role
        self.setWindowTitle("الإعدادات وإدارة النظام | Settings & Management")
        self.setFixedSize(600, 500)
        
        self._init_ui()
        self._load_settings()
        
    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        
        # 1. General Settings Tab
        general_tab = QWidget()
        self._setup_general_tab(general_tab)
        self.tabs.addTab(general_tab, "الإعدادات العامة")
        
        # 2. Custom Keywords Tab (Admin Only)
        if self.role == "admin":
            kw_tab = QWidget()
            self._setup_keywords_tab(kw_tab)
            self.tabs.addTab(kw_tab, "الكلمات المحظورة (Custom Keywords)")
            
            users_tab = QWidget()
            self._setup_users_tab(users_tab)
            self.tabs.addTab(users_tab, "إدارة المستخدمين (Users)")
            
            policies_tab = QWidget()
            self._setup_policies_tab(policies_tab)
            self.tabs.addTab(policies_tab, "سياسات التصنيف (Policies)")
            
            retention_tab = QWidget()
            self._setup_retention_tab(retention_tab)
            self.tabs.addTab(retention_tab, "سياسات الاحتفاظ (Retention)")
            
            dept_tab = QWidget()
            self._setup_departments_tab(dept_tab)
            self.tabs.addTab(dept_tab, "الأقسام (Departments)")
            
        main_layout.addWidget(self.tabs)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.save_btn = QPushButton("حفظ (Save)")
        self.save_btn.clicked.connect(self._save_settings)
        self.cancel_btn = QPushButton("إغلاق (Close)")
        self.cancel_btn.clicked.connect(self.reject)
        
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.cancel_btn)
        main_layout.addLayout(btn_layout)

    def _setup_general_tab(self, tab):
        layout = QVBoxLayout(tab)
        
        # Presets Group
        preset_group = QGroupBox("الإعدادات المسبقة للامتثال (Compliance Presets)")
        preset_layout = QVBoxLayout()
        self.preset_combo = QComboBox()
        self.preset_combo.addItem("مخصص (Custom)", "")
        for p_name, p_data in INDUSTRY_PRESETS.items():
            self.preset_combo.addItem(f"{p_data['description_ar']} ({p_name})", p_name)
            
        self.preset_combo.currentIndexChanged.connect(self._on_preset_changed)
        if self.role != "admin":
            self.preset_combo.setEnabled(False)
            
        preset_layout.addWidget(self.preset_combo)
        preset_group.setLayout(preset_layout)
        layout.addWidget(preset_group)
        
        model_group = QGroupBox("إعدادات نموذج الذكاء الاصطناعي (AI Model)")
        model_layout = QVBoxLayout()
        self.nlp_enable_cb = QCheckBox("تفعيل التعرف على الكيانات بواسطة الذكاء الاصطناعي (Enable NLP)")
        model_layout.addWidget(self.nlp_enable_cb)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("مسار النموذج (Model Path):"))
        self.model_path_input = QLineEdit()
        path_layout.addWidget(self.model_path_input)
        self.browse_btn = QPushButton("تصفح...")
        self.browse_btn.clicked.connect(self._browse_model)
        path_layout.addWidget(self.browse_btn)
        
        model_layout.addLayout(path_layout)
        model_group.setLayout(model_layout)
        layout.addWidget(model_group)
        
        anon_group = QGroupBox("استراتيجية إخفاء الهوية (Anonymization Strategy)")
        anon_layout = QVBoxLayout()
        self.strategy_combo = QComboBox()
        self.strategy_combo.addItem("قناع قانوني - Legal Mask", "legal_mask")
        self.strategy_combo.addItem("قناع كامل - Full Mask", "full_mask")
        self.strategy_combo.addItem("قناع جزئي - Partial Mask", "partial_mask")
        self.strategy_combo.addItem("أسماء مستعارة - Pseudonymize", "pseudonymize")
        
        # Only admin can change strategy
        if self.role != "admin":
            self.strategy_combo.setEnabled(False)
            
        anon_layout.addWidget(self.strategy_combo)
        
        # Save Template Button (Admin Only)
        if self.role == "admin":
            self.btn_save_template = QPushButton("حفظ كقالب جديد (Save as Template)")
            self.btn_save_template.clicked.connect(self._save_as_template)
            anon_layout.addWidget(self.btn_save_template)
            
        anon_group.setLayout(anon_layout)
        layout.addWidget(anon_group)
        
        # OCR Settings Group
        ocr_group = QGroupBox("إعدادات التعرف الضوئي (OCR Settings)")
        ocr_layout = QVBoxLayout()
        self.ocr_enable_cb = QCheckBox("تفعيل التعرف الضوئي على الصور الممسوحة (Enable OCR)")
        ocr_layout.addWidget(self.ocr_enable_cb)
        
        ocr_lang_layout = QHBoxLayout()
        ocr_lang_layout.addWidget(QLabel("لغات OCR (OCR Languages):"))
        self.ocr_lang_combo = QComboBox()
        self.ocr_lang_combo.addItem("عربي + إنجليزي (ara+eng)", "ara+eng")
        self.ocr_lang_combo.addItem("عربي فقط (ara)", "ara")
        self.ocr_lang_combo.addItem("فرنسي + عربي (fra+ara)", "fra+ara")
        self.ocr_lang_combo.addItem("إنجليزي فقط (eng)", "eng")
        ocr_lang_layout.addWidget(self.ocr_lang_combo)
        ocr_layout.addLayout(ocr_lang_layout)
        
        ocr_group.setLayout(ocr_layout)
        layout.addWidget(ocr_group)
        
        layout.addStretch()

    def _setup_policies_tab(self, tab):
        from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
        layout = QVBoxLayout(tab)
        
        lbl = QLabel("عرض سياسات التصنيف الحالية (View Labeling Policies)")
        layout.addWidget(lbl)
        
        table = QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(["التصنيف (Label)", "أقل درجة (Min)", "أقصى درجة (Max)"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        
        policies = self.db.get_labeling_policies()
        for p in policies:
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(p['label_name']))
            table.setItem(row, 1, QTableWidgetItem(str(p['min_score'])))
            table.setItem(row, 2, QTableWidgetItem(str(p['max_score'])))
            
        layout.addWidget(table)

    def _setup_keywords_tab(self, tab):
        layout = QVBoxLayout(tab)
        
        self.kw_list = QListWidget()
        self._refresh_keywords()
        layout.addWidget(self.kw_list)
        
        add_layout = QHBoxLayout()
        self.kw_input = QLineEdit()
        self.kw_input.setPlaceholderText("أدخل الكلمة الجديدة...")
        self.kw_add_btn = QPushButton("إضافة (Add)")
        self.kw_add_btn.clicked.connect(self._add_keyword)
        self.kw_del_btn = QPushButton("حذف المحدد (Delete)")
        self.kw_del_btn.clicked.connect(self._del_keyword)
        
        add_layout.addWidget(self.kw_input)
        add_layout.addWidget(self.kw_add_btn)
        add_layout.addWidget(self.kw_del_btn)
        
        layout.addLayout(add_layout)
        
    def _refresh_keywords(self):
        self.kw_list.clear()
        kws = self.db.get_custom_keywords()
        for kw in kws:
            self.kw_list.addItem(kw)
            
    def _add_keyword(self):
        kw = self.kw_input.text().strip()
        if kw:
            if self.db.add_custom_keyword(kw):
                self.kw_input.clear()
                self._refresh_keywords()
            else:
                QMessageBox.warning(self, "تنبيه", "الكلمة موجودة مسبقاً.")
                
    def _del_keyword(self):
        sel = self.kw_list.currentItem()
        if sel:
            self.db.remove_custom_keyword(sel.text())
            self._refresh_keywords()

    def _setup_users_tab(self, tab):
        layout = QVBoxLayout(tab)
        
        self.users_list = QListWidget()
        self._refresh_users()
        layout.addWidget(self.users_list)
        
        add_layout = QHBoxLayout()
        self.u_name_input = QLineEdit()
        self.u_name_input.setPlaceholderText("اسم المستخدم (Username)")
        self.u_pass_input = QLineEdit()
        self.u_pass_input.setPlaceholderText("كلمة المرور (Password)")
        self.u_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.u_role_combo = QComboBox()
        self.u_role_combo.addItems(["user", "admin"])
        
        self.u_add_btn = QPushButton("إضافة")
        self.u_add_btn.clicked.connect(self._add_user)
        self.u_del_btn = QPushButton("حذف المحدد")
        self.u_del_btn.clicked.connect(self._del_user)
        
        add_layout.addWidget(self.u_name_input)
        add_layout.addWidget(self.u_pass_input)
        add_layout.addWidget(self.u_role_combo)
        add_layout.addWidget(self.u_add_btn)
        add_layout.addWidget(self.u_del_btn)
        
        layout.addLayout(add_layout)
        
    def _refresh_users(self):
        self.users_list.clear()
        users = self.db.get_users()
        for u in users:
            self.users_list.addItem(f"{u['username']} [{u['role']}]")
            
    def _add_user(self):
        user = self.u_name_input.text().strip()
        pw = self.u_pass_input.text().strip()
        role = self.u_role_combo.currentText()
        if user and pw:
            if self.db.create_user(user, pw, role):
                self.u_name_input.clear()
                self.u_pass_input.clear()
                self._refresh_users()
            else:
                QMessageBox.warning(self, "تنبيه", "اسم المستخدم موجود مسبقاً.")
                
    def _del_user(self):
        sel = self.users_list.currentItem()
        if sel:
            username = sel.text().split(" ")[0]
            if username == "admin":
                QMessageBox.warning(self, "تنبيه", "لا يمكن حذف الحساب الافتراضي.")
                return
            self.db.delete_user(username)
            self._refresh_users()

    def _browse_model(self):
        dir_path = QFileDialog.getExistingDirectory(self, "اختر مجلد النموذج (Select Model Directory)")
        if dir_path:
            self.model_path_input.setText(dir_path)

    def _load_settings(self):
        self.nlp_enable_cb.setChecked(self.db.get_setting("nlp_enabled", True))
        self.model_path_input.setText(self.db.get_setting("model_path", ""))
        strat = self.db.get_setting("anonymization_strategy", "legal_mask")
        index = self.strategy_combo.findData(strat)
        if index >= 0:
            self.strategy_combo.setCurrentIndex(index)
        
        if self.role == "admin" and hasattr(self, 'dept_table'):
            self._load_departments_list()
        
    def _on_preset_changed(self):
        preset_name = self.preset_combo.currentData()
        if not preset_name:
            return
            
        preset = INDUSTRY_PRESETS.get(preset_name)
        if preset:
            # Apply NLP Setting
            self.nlp_enable_cb.setChecked(preset["nlp_enabled"])
            
            # Apply Strategy
            strat = preset["anonymization_strategy"]
            index = self.strategy_combo.findData(strat)
            if index >= 0:
                self.strategy_combo.setCurrentIndex(index)
                
            # If admin, update custom keywords with the preset
            if self.role == "admin" and hasattr(self, 'kw_list'):
                self.kw_list.clear()
                for kw in preset["custom_keywords"]:
                    self.kw_list.addItem(kw)
                # Automatically save keywords so it takes effect
                self._save_keywords()
                
            QMessageBox.information(self, "تطبيق الإعداد المسبق", f"تم تطبيق إعدادات قطاع {preset['description_ar']}.")

    def _setup_departments_tab(self, tab):
        from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QFormLayout
        layout = QVBoxLayout(tab)
        
        lbl = QLabel("إدارة الأقسام — كل قسم يرى فقط بياناته (Department Isolation)")
        layout.addWidget(lbl)
        
        self.dept_table = QTableWidget(0, 2)
        self.dept_table.setHorizontalHeaderLabels(["اسم القسم (Name)", "الوصف (Description)"])
        self.dept_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.dept_table)
        
        form = QFormLayout()
        self.dept_name_input = QLineEdit()
        self.dept_name_input.setPlaceholderText("مثال: قسم الموارد البشرية")
        self.dept_desc_input = QLineEdit()
        self.dept_desc_input.setPlaceholderText("وصف اختياري")
        
        form.addRow("اسم القسم:", self.dept_name_input)
        form.addRow("الوصف:", self.dept_desc_input)
        
        add_btn = QPushButton("إضافة قسم (Add Department)")
        add_btn.clicked.connect(self._add_department)
        form.addRow(add_btn)
        
        layout.addLayout(form)
        
    def _add_department(self):
        name = self.dept_name_input.text().strip()
        desc = self.dept_desc_input.text().strip()
        if name:
            self.db.save_department(name, desc)
            self.dept_name_input.clear()
            self.dept_desc_input.clear()
            self._load_departments_list()
        else:
            QMessageBox.warning(self, "خطأ", "يجب إدخال اسم القسم.")
            
    def _load_departments_list(self):
        from PyQt6.QtWidgets import QTableWidgetItem
        depts = self.db.get_departments()
        self.dept_table.setRowCount(len(depts))
        for i, (dept_id, name, desc) in enumerate(depts):
            self.dept_table.setItem(i, 0, QTableWidgetItem(name))
            self.dept_table.setItem(i, 1, QTableWidgetItem(desc or ""))

    def _save_settings(self):
        if self.role == "admin":
            settings = {
                "nlp_enabled": self.nlp_enable_cb.isChecked(),
                "model_path": self.model_path_input.text(),
                "anonymization_strategy": self.strategy_combo.currentData()
            }
            for k, v in settings.items():
                self.db.save_setting(k, v)
            self.settings_changed.emit(settings)
        self.accept()
        
    def _save_as_template(self):
        from PyQt6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, "حفظ القالب", "أدخل اسم القالب (Template Name):")
        if ok and name:
            strategy = self.strategy_combo.currentData()
            preset = self.preset_combo.currentData()
            nlp_enabled = self.nlp_enable_cb.isChecked()
            
            self.db.save_template(name, strategy, preset, nlp_enabled)
            QMessageBox.information(self, "نجاح", "تم حفظ القالب بنجاح.")
