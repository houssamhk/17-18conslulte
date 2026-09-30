import os

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QComboBox, QCheckBox, 
                             QGroupBox, QFileDialog, QTabWidget, QWidget, QListWidget, QMessageBox, QSpinBox,
                             QScrollArea, QListWidgetItem)
from PyQt6.QtCore import pyqtSignal, Qt
from storage.secure_db import SecureDatabase
from storage.password_policy import MIN_PASSWORD_LENGTH, password_is_valid, password_strength_hint
from engine.presets import INDUSTRY_PRESETS
from .theme import COLORS
from .dialog_utils import configure_dialog_size

class SettingsDialog(QDialog):
    """Settings dialog including Admin Management panels."""
    settings_changed = pyqtSignal(dict)
    
    def __init__(self, db: SecureDatabase, role: str, parent=None):
        super().__init__(parent)
        self.db = db
        self.role = role
        self.setWindowTitle("الإعدادات وإدارة النظام | Settings & Management")
        configure_dialog_size(self, preferred=(980, 740), minimum=(760, 520))
        
        self._init_ui()
        self._load_settings()
        
    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tabs.setUsesScrollButtons(True)
        self.tabs.setDocumentMode(True)
        
        # 1. General Settings Tab
        general_tab = QWidget()
        self._setup_general_tab(general_tab)
        self._add_scrollable_tab(general_tab, "الإعدادات العامة")
        
        # 2. Custom Keywords Tab (Admin Only)
        if self.role == "admin":
            backup_tab = QWidget()
            self._setup_backup_tab(backup_tab)
            self._add_scrollable_tab(backup_tab, "النسخ الاحتياطي")

            kw_tab = QWidget()
            self._setup_keywords_tab(kw_tab)
            self._add_scrollable_tab(kw_tab, "الكلمات المحظورة (Custom Keywords)")
            
            users_tab = QWidget()
            self._setup_users_tab(users_tab)
            self._add_scrollable_tab(users_tab, "إدارة المستخدمين (Users)")
            
            policies_tab = QWidget()
            self._setup_policies_tab(policies_tab)
            self._add_scrollable_tab(policies_tab, "سياسات التصنيف (Policies)")
            
            retention_tab = QWidget()
            self._setup_retention_tab(retention_tab)
            self._add_scrollable_tab(retention_tab, "سياسات الاحتفاظ (Retention)")
            
            dept_tab = QWidget()
            self._setup_departments_tab(dept_tab)
            self._add_scrollable_tab(dept_tab, "الأقسام (Departments)")
            
        main_layout.addWidget(self.tabs)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.diagnostics_btn = QPushButton("فحص جاهزية النظام")
        self.diagnostics_btn.clicked.connect(self._open_diagnostics)
        btn_layout.addWidget(self.diagnostics_btn)
        btn_layout.addStretch()
        self.save_btn = QPushButton("حفظ (Save)")
        self.save_btn.clicked.connect(self._save_settings)
        self.cancel_btn = QPushButton("إغلاق (Close)")
        self.cancel_btn.clicked.connect(self.reject)
        
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.cancel_btn)
        main_layout.addLayout(btn_layout)

    def _add_scrollable_tab(self, content, title):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setWidget(content)
        self.tabs.addTab(scroll, title)

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

        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("مسار Tesseract (اختياري إذا كان في PATH):"))
        self.tesseract_path_input = QLineEdit()
        self.tesseract_path_input.setPlaceholderText(r"مثال: C:\Program Files\Tesseract-OCR\tesseract.exe")
        path_layout.addWidget(self.tesseract_path_input, 1)
        self.tesseract_browse_btn = QPushButton("اختيار")
        self.tesseract_browse_btn.clicked.connect(self._browse_tesseract)
        path_layout.addWidget(self.tesseract_browse_btn)
        ocr_layout.addLayout(path_layout)

        ocr_status_layout = QHBoxLayout()
        self.ocr_status_label = QLabel()
        self.ocr_status_label.setWordWrap(True)
        ocr_status_layout.addWidget(self.ocr_status_label, 1)
        self.ocr_check_btn = QPushButton("فحص جاهزية OCR")
        self.ocr_check_btn.clicked.connect(self._validate_ocr)
        ocr_status_layout.addWidget(self.ocr_check_btn)
        ocr_layout.addLayout(ocr_status_layout)

        if self.role != "admin":
            self.ocr_enable_cb.setEnabled(False)
            self.ocr_lang_combo.setEnabled(False)
            self.tesseract_path_input.setEnabled(False)
            self.tesseract_browse_btn.setEnabled(False)
            self.ocr_check_btn.setEnabled(False)
        
        ocr_group.setLayout(ocr_layout)
        layout.addWidget(ocr_group)

        session_group = QGroupBox("أمان الجلسة (Session Security)")
        session_layout = QVBoxLayout(session_group)
        session_layout.addWidget(QLabel("قفل التطبيق تلقائيًا بعد فترة من عدم استخدام لوحة المفاتيح أو الفأرة. القيمة 0 تعطل القفل التلقائي."))
        self.idle_lock_minutes = QSpinBox()
        self.idle_lock_minutes.setRange(0, 240)
        self.idle_lock_minutes.setSuffix(" دقيقة")
        self.idle_lock_minutes.setToolTip("القيمة الافتراضية 15 دقيقة؛ يمكن اختيار مدة من 0 إلى 240 دقيقة.")
        self.idle_lock_minutes.setEnabled(self.role == "admin")
        session_layout.addWidget(self.idle_lock_minutes)
        layout.addWidget(session_group)
        
        layout.addStretch()

    def _setup_backup_tab(self, tab):
        layout = QVBoxLayout(tab)
        heading = QLabel("نسخ احتياطي مشفر واستعادة آمنة")
        heading.setStyleSheet(f"color: {COLORS['ACCENT']}; font-size: 17px; font-weight: bold;")
        layout.addWidget(heading)
        explanation = QLabel(
            "ينشئ التطبيق نسخة متسقة ومشفرة من قاعدة البيانات. لا تحتوي النسخة على مفتاح فك التشفير، "
            "ولذلك لا يمكن فتحها إلا من التثبيت المرتبط بمفتاح Windows Credential Manager نفسه. "
            "بعد تجهيز الاستعادة سيُغلق التطبيق، وتُطبق النسخة عند تشغيله مرة أخرى. "
            "تُحفظ نسخة من قاعدة البيانات الحالية قبل الاستبدال."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        create_btn = QPushButton("إنشاء نسخة احتياطية مشفرة")
        create_btn.clicked.connect(self._create_encrypted_backup)
        validate_btn = QPushButton("فحص نسخة احتياطية")
        validate_btn.clicked.connect(self._validate_encrypted_backup)
        restore_btn = QPushButton("استعادة نسخة احتياطية")
        restore_btn.clicked.connect(self._stage_backup_restore)
        layout.addWidget(create_btn)
        layout.addWidget(validate_btn)
        layout.addWidget(restore_btn)
        last_run = self.db.get_setting("auto_backup_last_run", "")
        self.auto_backup_status = QLabel(f"آخر نسخة تلقائية ناجحة: {last_run or 'لا توجد بعد'}")
        self.auto_backup_status.setWordWrap(True)
        layout.addWidget(self.auto_backup_status)
        self.restore_staged = False
        auto_group = QGroupBox("النسخ التلقائي (Automatic Backups)")
        auto_layout = QVBoxLayout(auto_group)
        self.auto_backup_cb = QCheckBox("تفعيل النسخ الاحتياطي التلقائي")
        self.auto_backup_cb.toggled.connect(self._toggle_auto_backup_controls)
        auto_layout.addWidget(self.auto_backup_cb)
        folder_row = QHBoxLayout()
        self.auto_backup_dir = QLineEdit()
        self.auto_backup_dir.setPlaceholderText("مجلد حفظ النسخ")
        folder_row.addWidget(self.auto_backup_dir, 1)
        browse_dir = QPushButton("اختيار مجلد")
        browse_dir.clicked.connect(self._browse_backup_directory)
        folder_row.addWidget(browse_dir)
        auto_layout.addLayout(folder_row)
        cadence_row = QHBoxLayout()
        cadence_row.addWidget(QLabel("التكرار كل"))
        self.auto_backup_interval = QSpinBox()
        self.auto_backup_interval.setRange(1, 365)
        self.auto_backup_interval.setSuffix(" يومًا")
        cadence_row.addWidget(self.auto_backup_interval)
        cadence_row.addWidget(QLabel("الاحتفاظ بآخر"))
        self.auto_backup_count = QSpinBox()
        self.auto_backup_count.setRange(1, 100)
        self.auto_backup_count.setSuffix(" نسخة")
        cadence_row.addWidget(self.auto_backup_count)
        cadence_row.addStretch()
        auto_layout.addLayout(cadence_row)
        auto_layout.addWidget(QLabel("تبدأ النسخة التلقائية عند تشغيل التطبيق، ثم حسب التكرار المحدد. النسخ الأقدم من العدد المحدد تُحذف من مجلد النسخ التلقائي فقط."))
        layout.insertWidget(layout.count() - 1, auto_group)
        self._load_backup_settings()
        layout.addStretch()

    def _load_backup_settings(self):
        self.auto_backup_cb.setChecked(bool(self.db.get_setting("auto_backup_enabled", False)))
        self.auto_backup_dir.setText(self.db.get_setting("auto_backup_dir", os.path.join(os.path.dirname(self.db.db_path), "backups")))
        self.auto_backup_interval.setValue(int(self.db.get_setting("auto_backup_interval_days", 1)))
        self.auto_backup_count.setValue(int(self.db.get_setting("auto_backup_keep_count", 7)))
        self._toggle_auto_backup_controls(self.auto_backup_cb.isChecked())

    def _toggle_auto_backup_controls(self, enabled):
        self.auto_backup_dir.setEnabled(enabled)
        self.auto_backup_interval.setEnabled(enabled)
        self.auto_backup_count.setEnabled(enabled)

    def _browse_backup_directory(self):
        path = QFileDialog.getExistingDirectory(self, "اختر مجلد النسخ الاحتياطي")
        if path:
            self.auto_backup_dir.setText(path)

    def _create_encrypted_backup(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "حفظ النسخة الاحتياطية المشفرة", "AlgPII-backup.apibak", "نسخة Alg-PII المشفرة (*.apibak)"
        )
        if not path:
            return
        if not path.lower().endswith(".apibak"):
            path += ".apibak"
        try:
            from storage.backup_manager import SecureBackupManager
            result = SecureBackupManager.create_backup(self.db, path)
            size_mb = result["size"] / (1024 * 1024)
            QMessageBox.information(self, "اكتمل النسخ الاحتياطي", f"حُفظت النسخة المشفرة بنجاح ({size_mb:.2f} ميغابايت):\n{result['path']}")
        except Exception as exc:
            QMessageBox.critical(self, "فشل النسخ الاحتياطي", f"تعذر إنشاء نسخة احتياطية:\n{exc}")

    def _validate_encrypted_backup(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "اختر نسخة لفحصها", "", "نسخة Alg-PII المشفرة (*.apibak)"
        )
        if not path:
            return
        try:
            from storage.backup_manager import SecureBackupManager
            SecureBackupManager.validate_backup(self.db, path)
            QMessageBox.information(
                self,
                "النسخة سليمة",
                "نجح التحقق من تنسيق النسخة، ومفتاح SQLCipher، وسلامة صفحات قاعدة البيانات، وسلسلة سجل التدقيق عند توفرها.",
            )
        except Exception as exc:
            QMessageBox.critical(self, "فشل فحص النسخة", f"لا يمكن الاعتماد على هذه النسخة:\n{exc}")

    def _stage_backup_restore(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "اختر نسخة احتياطية", "", "نسخة Alg-PII المشفرة (*.apibak)"
        )
        if not path:
            return
        answer = QMessageBox.question(
            self,
            "تأكيد الاستعادة",
            "سيتم التحقق من تشفير النسخة وسلامتها، ثم إغلاق التطبيق وتطبيقها عند التشغيل التالي. "
            "ستُحفظ نسخة من قاعدة البيانات الحالية قبل الاستبدال. هل تريد المتابعة؟",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            from storage.backup_manager import SecureBackupManager
            SecureBackupManager.stage_restore(self.db, path)
        except Exception as exc:
            QMessageBox.critical(self, "تعذرت الاستعادة", f"النسخة غير صالحة أو لا تخص مفتاح هذا التثبيت:\n{exc}")
            return
        self.restore_staged = True
        QMessageBox.information(self, "النسخة جاهزة", "تم التحقق من النسخة. سيُغلق التطبيق الآن؛ شغّله مجددًا لإكمال الاستعادة.")
        self.accept()

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

    def _setup_retention_tab(self, tab):
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("حدد مدة الاحتفاظ بالسجلات. التنظيف الدوري يحذف السجلات الأقدم تلقائيًا؛ استخدم المعاينة قبل الحفظ."))

        self.retention_list = QListWidget()
        self._refresh_retention_policies()
        layout.addWidget(self.retention_list)

        form = QHBoxLayout()
        self.retention_table_combo = QComboBox()
        for table, title in (
            ("scan_history", "سجل الفحوصات"),
            ("audit_log", "سجل التدقيق"),
            ("policy_violations", "انتهاكات السياسات"),
            ("incidents", "الحوادث"),
        ):
            self.retention_table_combo.addItem(title, table)
        self.retention_days = QSpinBox()
        self.retention_days.setRange(1, 36500)
        self.retention_days.setValue(365)
        self.retention_days.setSuffix(" يومًا")
        preview_btn = QPushButton("معاينة عدد السجلات")
        preview_btn.clicked.connect(self._preview_retention)
        save_btn = QPushButton("حفظ المدة")
        save_btn.clicked.connect(self._save_retention_policy)
        form.addWidget(self.retention_table_combo)
        form.addWidget(self.retention_days)
        form.addWidget(preview_btn)
        form.addWidget(save_btn)
        layout.addLayout(form)

        self.retention_preview = QLabel("لم تُجرَ معاينة بعد.")
        self.retention_preview.setWordWrap(True)
        layout.addWidget(self.retention_preview)

        layout.addWidget(QLabel("آخر عمليات التنظيف المسجلة:"))
        self.retention_history = QListWidget()
        layout.addWidget(self.retention_history)
        history_btn = QPushButton("تحديث سجل التنظيف")
        history_btn.clicked.connect(self._refresh_retention_history)
        layout.addWidget(history_btn)
        self._refresh_retention_history()

    def _refresh_retention_policies(self):
        self.retention_list.clear()
        labels = {
            "scan_history": "سجل الفحوصات",
            "audit_log": "سجل التدقيق",
            "policy_violations": "انتهاكات السياسات",
            "incidents": "الحوادث",
        }
        for table, days in self.db.get_retention_policies().items():
            self.retention_list.addItem(f"{labels.get(table, table)}: {days} يومًا")
        if self.retention_list.count() == 0:
            self.retention_list.addItem("لا توجد سياسات احتفاظ مفعلة.")

    def _preview_retention(self):
        table = self.retention_table_combo.currentData()
        days = self.retention_days.value()
        try:
            count = self.db.count_retention_candidates(table, days)
            self.retention_preview.setText(
                f"تطابق {count} سجل(ات) حاليًا مدة الاحتفاظ المحددة ({days} يومًا). "
                "هذه معاينة فقط؛ وقد تختلف النتيجة عند تشغيل التنظيف الدوري."
            )
        except Exception as exc:
            QMessageBox.warning(self, "تعذرت المعاينة", f"تعذر حساب السجلات المطابقة:\n{exc}")

    def _refresh_retention_history(self):
        self.retention_history.clear()
        labels = {
            "scan_history": "الفحوصات",
            "audit_log": "سجل التدقيق",
            "policy_violations": "انتهاكات السياسات",
            "incidents": "الحوادث",
        }
        for table, count, timestamp in self.db.get_retention_log(100):
            self.retention_history.addItem(
                f"{timestamp} — حُذف {count} سجلًا من {labels.get(table, table)}"
            )
        if self.retention_history.count() == 0:
            self.retention_history.addItem("لا توجد عمليات حذف مسجلة حتى الآن.")

    def _save_retention_policy(self):
        table = self.retention_table_combo.currentData()
        days = self.retention_days.value()
        labels = {
            "scan_history": "سجل الفحوصات",
            "audit_log": "سجل التدقيق",
            "policy_violations": "انتهاكات السياسات",
            "incidents": "الحوادث",
        }
        reply = QMessageBox.question(
            self,
            "تأكيد سياسة الحذف الدوري",
            f"سيتم حذف سجلات {labels.get(table, table)} الأقدم من {days} يومًا تلقائيًا عند تشغيل التنظيف. الحذف دائم. هل تريد تفعيل هذه السياسة؟",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.db.save_retention_policy(table, days)
        current_user = getattr(self.parent(), "username", "admin")
        self.db.log_audit(current_user, "RETENTION_POLICY", f"Enabled retention policy for {table}: {days} days.")
        self._refresh_retention_policies()
        self._preview_retention()

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
        from PyQt6.QtWidgets import QFormLayout
        layout = QVBoxLayout(tab)
        
        self.users_list = QListWidget()
        self.users_list.currentItemChanged.connect(self._on_user_selected)
        self._refresh_users()
        layout.addWidget(self.users_list)
        
        form = QFormLayout()
        self.u_name_input = QLineEdit()
        self.u_name_input.setMaxLength(128)
        self.u_name_input.setPlaceholderText("اسم المستخدم (Username)")
        self.u_pass_input = QLineEdit()
        self.u_pass_input.setPlaceholderText("كلمة المرور (Password)")
        self.u_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.u_pass_hint = QLabel("استخدم عبارة مرور طويلة يسهل تذكرها ويصعب تخمينها.")
        self.u_pass_input.textChanged.connect(lambda text: self._update_password_hint(text))
        self.u_confirm_input = QLineEdit()
        self.u_confirm_input.setPlaceholderText("تأكيد كلمة المرور")
        self.u_confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.u_role_combo = QComboBox()
        self.u_role_combo.addItems(["user", "admin"])
        self.u_department_combo = QComboBox()
        self._refresh_department_combo()
        form.addRow("اسم المستخدم:", self.u_name_input)
        form.addRow("كلمة المرور:", self.u_pass_input)
        form.addRow("قوة كلمة المرور:", self.u_pass_hint)
        form.addRow("تأكيد كلمة المرور:", self.u_confirm_input)
        form.addRow("الدور:", self.u_role_combo)
        form.addRow("القسم:", self.u_department_combo)
        layout.addLayout(form)
        
        self.u_add_btn = QPushButton("إضافة")
        self.u_add_btn.clicked.connect(self._add_user)
        self.u_del_btn = QPushButton("حذف المحدد")
        self.u_del_btn.clicked.connect(self._del_user)
        self.u_unlock_btn = QPushButton("فك قفل الدخول")
        self.u_unlock_btn.clicked.connect(self._unlock_user)
        self.u_totp_reset_btn = QPushButton("إعادة ضبط المصادقة الثنائية")
        self.u_totp_reset_btn.clicked.connect(self._reset_user_totp)
        self.u_assign_dept_btn = QPushButton("تعيين القسم للمستخدم المحدد")
        self.u_assign_dept_btn.clicked.connect(self._assign_selected_department)

        actions = QHBoxLayout()
        actions.addWidget(self.u_add_btn)
        actions.addWidget(self.u_del_btn)
        actions.addWidget(self.u_unlock_btn)
        actions.addWidget(self.u_totp_reset_btn)
        actions.addWidget(self.u_assign_dept_btn)
        actions.addStretch()
        layout.addLayout(actions)
        
    def _refresh_users(self):
        self.users_list.clear()
        users = self.db.get_users()
        for u in users:
            mfa_status = "2FA مفعلة" if u.get("totp_enabled") else "2FA غير مفعلة"
            dept_status = f"القسم: {u['department']}" if u.get("department") else "بدون قسم"
            item = QListWidgetItem(f"{u['username']} [{u['role']}] — {dept_status} — {mfa_status}")
            item.setData(Qt.ItemDataRole.UserRole, u["username"])
            item.setData(Qt.ItemDataRole.UserRole + 1, u.get("department_id"))
            self.users_list.addItem(item)

    def _selected_username(self):
        selected = self.users_list.currentItem()
        return selected.data(Qt.ItemDataRole.UserRole) if selected else None

    def _refresh_department_combo(self, selected_id=None):
        if not hasattr(self, "u_department_combo"):
            return
        if selected_id is None:
            selected_id = self.u_department_combo.currentData()
        self.u_department_combo.clear()
        self.u_department_combo.addItem("بدون قسم", None)
        for department_id, name, _description in self.db.get_departments():
            self.u_department_combo.addItem(name, department_id)
        index = self.u_department_combo.findData(selected_id)
        if index >= 0:
            self.u_department_combo.setCurrentIndex(index)

    def _on_user_selected(self, current, _previous):
        if current:
            department_id = current.data(Qt.ItemDataRole.UserRole + 1)
            index = self.u_department_combo.findData(department_id)
            self.u_department_combo.setCurrentIndex(index if index >= 0 else 0)

    def _assign_selected_department(self):
        username = self._selected_username()
        if not username:
            QMessageBox.information(self, "تعيين القسم", "حدد مستخدمًا من القائمة أولًا.")
            return
        department_id = self.u_department_combo.currentData()
        if not self.db.set_user_department(username, department_id):
            QMessageBox.warning(self, "تعذر التعيين", "لم يتم العثور على المستخدم أو القسم المحدد.")
            return
        department_name = self.u_department_combo.currentText() if department_id is not None else "بدون قسم"
        current_user = getattr(self.parent(), "username", "admin")
        self.db.log_audit(current_user, "USER_DEPARTMENT", f"Admin assigned user {username} to department {department_name}.")
        self._refresh_users()
        QMessageBox.information(self, "تم التحديث", f"تم تحديث قسم المستخدم {username}.")
            
    def _add_user(self):
        user = self.u_name_input.text().strip()
        pw = self.u_pass_input.text()
        role = self.u_role_combo.currentText()
        if not user or not password_is_valid(pw):
            QMessageBox.warning(self, "بيانات غير صالحة", f"أدخل اسم مستخدم وكلمة مرور من {MIN_PASSWORD_LENGTH} محرفًا على الأقل، متنوعة وغير متكررة، ولا تتجاوز 72 بايتًا.")
            return
        if pw != self.u_confirm_input.text():
            QMessageBox.warning(self, "عدم تطابق", "تأكيد كلمة المرور لا يطابق كلمة المرور.")
            return
        if user and pw:
            if self.db.create_user(user, pw, role):
                department_id = self.u_department_combo.currentData()
                if department_id is not None:
                    self.db.set_user_department(user, department_id)
                current_user = getattr(self.parent(), "username", "admin")
                self.db.log_audit(current_user, "USER_CREATE", f"Admin created {role} account {user}.")
                self.u_name_input.clear()
                self.u_pass_input.clear()
                self.u_confirm_input.clear()
                self._refresh_users()
            else:
                QMessageBox.warning(self, "تنبيه", "اسم المستخدم موجود أو الدور غير صالح.")

    def _update_password_hint(self, password):
        hint, color_key = password_strength_hint(password)
        self.u_pass_hint.setText(hint)
        self.u_pass_hint.setStyleSheet(f"color: {COLORS.get(color_key, COLORS['TEXT_SECONDARY'])};")
                
    def _del_user(self):
        sel = self.users_list.currentItem()
        if sel:
            username = self._selected_username()
            if username == getattr(self.parent(), "username", None):
                QMessageBox.warning(self, "تنبيه", "لا يمكن حذف الحساب المستخدم حاليًا.")
                return
            answer = QMessageBox.question(
                self,
                "تأكيد حذف المستخدم",
                f"سيُحذف الحساب {username}. هل تريد المتابعة؟",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            if self.db.delete_user(username):
                current_user = getattr(self.parent(), "username", "admin")
                self.db.log_audit(current_user, "USER_DELETE", f"Admin deleted account {username}.")
                self._refresh_users()

    def _unlock_user(self):
        selected = self.users_list.currentItem()
        if not selected:
            QMessageBox.information(self, "فك قفل الدخول", "حدد حسابًا من القائمة أولًا.")
            return
        username = self._selected_username()
        if self.db.reset_login_attempts(username):
            current_user = getattr(self.parent(), "username", "admin")
            self.db.log_audit(current_user, "LOGIN_LOCK_RESET", f"Admin reset login lock for user {username}.")
            QMessageBox.information(self, "فك قفل الدخول", f"تم فك القفل المؤقت للحساب {username}.")
        else:
            QMessageBox.information(self, "فك قفل الدخول", "لا يوجد قفل مؤقت لهذا الحساب.")

    def _reset_user_totp(self):
        selected = self.users_list.currentItem()
        if not selected:
            QMessageBox.information(self, "إعادة ضبط المصادقة", "حدد حسابًا من القائمة أولًا.")
            return
        username = self._selected_username()
        if username == getattr(self.parent(), "username", None):
            QMessageBox.warning(self, "غير مسموح", "لا يمكن للمشرف إعادة ضبط عامل المصادقة لحسابه الحالي من هذه الشاشة.")
            return
        answer = QMessageBox.question(
            self,
            "تأكيد إعادة الضبط",
            f"سيُزال عامل المصادقة وأكواد الاسترداد للحساب {username}. سيحتاج المستخدم إلى تسجيل الدخول بكلمة المرور وإعداد العامل مجددًا. هل تتابع؟",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        if self.db.admin_reset_totp(username):
            current_user = getattr(self.parent(), "username", "admin")
            self.db.log_audit(current_user, "TOTP_ADMIN_RESET", f"Admin reset second factor for user {username}.")
            QMessageBox.information(self, "تمت إعادة الضبط", f"أُعيد ضبط المصادقة الثنائية للحساب {username}.")
        else:
            QMessageBox.information(self, "لا يوجد عامل مفعّل", "هذا الحساب لا يملك مصادقة ثنائية مفعّلة.")

    def _browse_model(self):
        dir_path = QFileDialog.getExistingDirectory(self, "اختر مجلد النموذج (Select Model Directory)")
        if dir_path:
            self.model_path_input.setText(dir_path)

    def _browse_tesseract(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "اختر tesseract.exe", "", "Tesseract executable (tesseract.exe);;All files (*)"
        )
        if path:
            self.tesseract_path_input.setText(path)
            self._validate_ocr()

    def _validate_ocr(self):
        from engine.document_parser import DocumentParser
        ready, message = DocumentParser.validate_ocr_configuration(
            self.ocr_lang_combo.currentData(), self.tesseract_path_input.text().strip()
        )
        color = COLORS["SUCCESS"] if ready else COLORS["WARNING"]
        self.ocr_status_label.setStyleSheet(f"color: {color}; font-weight: bold;")
        self.ocr_status_label.setText(("جاهز: " if ready else "غير جاهز: ") + message)

    def _load_settings(self):
        self.nlp_enable_cb.setChecked(self.db.get_setting("nlp_enabled", False))
        self.nlp_enable_cb.setToolTip("يستخدم نموذجًا موجودًا محليًا فقط؛ لا ينزّل ملفات من الإنترنت عند التشغيل.")
        self.model_path_input.setText(self.db.get_setting("model_path", ""))
        self.ocr_enable_cb.setChecked(self.db.get_setting("ocr_enabled", True))
        ocr_index = self.ocr_lang_combo.findData(self.db.get_setting("ocr_language", "ara+eng"))
        if ocr_index >= 0:
            self.ocr_lang_combo.setCurrentIndex(ocr_index)
        self.tesseract_path_input.setText(self.db.get_setting("tesseract_cmd", ""))
        self.idle_lock_minutes.setValue(int(self.db.get_setting("session_idle_minutes", 15)))
        strat = self.db.get_setting("anonymization_strategy", "legal_mask")
        index = self.strategy_combo.findData(strat)
        if index >= 0:
            self.strategy_combo.setCurrentIndex(index)
        
        if self.role == "admin" and hasattr(self, 'dept_table'):
            self._load_departments_list()
        self._validate_ocr()
        
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
            self._refresh_department_combo()
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
                "anonymization_strategy": self.strategy_combo.currentData(),
                "ocr_enabled": self.ocr_enable_cb.isChecked(),
                "ocr_language": self.ocr_lang_combo.currentData(),
                "tesseract_cmd": self.tesseract_path_input.text().strip(),
                "session_idle_minutes": self.idle_lock_minutes.value(),
            }
            if hasattr(self, "auto_backup_cb"):
                backup_settings = {
                    "auto_backup_enabled": self.auto_backup_cb.isChecked(),
                    "auto_backup_dir": self.auto_backup_dir.text().strip(),
                    "auto_backup_interval_days": self.auto_backup_interval.value(),
                    "auto_backup_keep_count": self.auto_backup_count.value(),
                }
                if backup_settings["auto_backup_enabled"] and not backup_settings["auto_backup_dir"]:
                    QMessageBox.warning(self, "مجلد النسخ مطلوب", "حدد مجلدًا لحفظ النسخ التلقائية أو عطّل النسخ التلقائي.")
                    return
                settings.update(backup_settings)
            for k, v in settings.items():
                self.db.save_setting(k, v)
            self.settings_changed.emit(settings)
        self.accept()

    def _open_diagnostics(self):
        from .diagnostics_dialog import SystemDiagnosticsDialog
        engine = getattr(self.parent(), "engine", None)
        dialog = SystemDiagnosticsDialog(self.db, engine, self)
        dialog.exec()
        
    def _save_as_template(self):
        from PyQt6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, "حفظ القالب", "أدخل اسم القالب (Template Name):")
        if ok and name:
            strategy = self.strategy_combo.currentData()
            preset = self.preset_combo.currentData()
            nlp_enabled = self.nlp_enable_cb.isChecked()
            
            self.db.save_template(name, strategy, preset, nlp_enabled)
            QMessageBox.information(self, "نجاح", "تم حفظ القالب بنجاح.")
