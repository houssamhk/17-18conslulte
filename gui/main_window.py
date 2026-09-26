import sys
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QSplitter, QTextEdit, QLabel, QStatusBar, QMenuBar, 
                             QFileDialog, QMessageBox, QApplication, QProgressDialog,
                             QStackedWidget, QPushButton, QFrame, QDialog)
from PyQt6.QtCore import Qt, QTimer, QSize
from PyQt6.QtGui import QAction, QIcon
import qtawesome as qta

from engine.compliance_engine import AlgComplianceEngine
from engine.regex_detector import AnonymizedResult
from engine.document_parser import DocumentParser
from engine.pdf_exporter import PDFExporter
from engine.redaction_verifier import RedactionVerifier
from engine.fingerprint import FingerprintEngine
from engine.policy_engine import PolicyEngine
from engine.scheduler import TaskScheduler
from storage.secure_db import SecureDatabase
from .widgets import AnimatedButton, EntityBadge, StatusIndicator, DropZone, ComplianceGauge
from .scan_thread import ScanWorker
from .batch_worker import BatchWorker
from .settings_dialog import SettingsDialog
from .theme import COLORS
from engine.license_manager import LicenseManager
from .license_dialog import LicenseDialog
from .login_dialog import LoginDialog
from .dashboard import DashboardWidget
from .policies_page import PoliciesPageWidget
from .incidents_page import IncidentsPageWidget
from .scheduled_tasks_page import ScheduledTasksPageWidget
from .transfer_page import TransferPageWidget
from .data_flow_page import DataFlowPageWidget
from .training_page import TrainingPageWidget
from .report_template_page import ReportTemplatePageWidget
from .calendar_page import CalendarPageWidget

class SidebarButton(QPushButton):
    """Custom sidebar button with icon."""
    def __init__(self, icon_name, text, parent=None):
        super().__init__(text, parent)
        self.setIcon(qta.icon(icon_name, color=COLORS['TEXT_PRIMARY']))
        self.setIconSize(QSize(20, 20))
        self.setStyleSheet(f"""
            QPushButton {{
                text-align: left;
                padding: 12px 20px;
                background-color: transparent;
                border: none;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['BG_PANEL']};
            }}
            QPushButton:checked {{
                background-color: {COLORS['ACCENT_PURPLE']};
                color: {COLORS['ACCENT']};
            }}
        """)
        self.setCheckable(True)
        # Handle RTL icon alignment if needed (Qtawesome supports RTL automatically usually)

class AlgPIIMainWindow(QMainWindow):
    def __init__(self, db: SecureDatabase):
        super().__init__()
        self.db = db
        
        # 1. License Check
        if not LicenseManager.is_activated():
            dlg = LicenseDialog(self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                sys.exit(0)
                
        # 2. User Authentication
        login_dlg = LoginDialog(self.db, self)
        if login_dlg.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)
            
        self.user_role = login_dlg.authenticated_role
        self.username = login_dlg.authenticated_username
        self.user_department = getattr(login_dlg, 'authenticated_department', None)
        
        dept_str = f" in department {self.user_department}" if self.user_department else ""
        self.db.log_audit(self.username, "LOGIN", f"User logged into the system{dept_str}.")
        
        # 3. Load Settings & Keywords
        self.nlp_enabled = self.db.get_setting("nlp_enabled", True)
        self.model_path = self.db.get_setting("model_path", None)
        self.strategy = self.db.get_setting("anonymization_strategy", "legal_mask")
        self.custom_keywords = self.db.get_custom_keywords()
        
        self.setWindowTitle("محرك الامتثال الجزائري | Alg-PII Engine")
        self.resize(1200, 800)
        
        self.labeling_policies = self.db.get_labeling_policies()
        self.regulatory_mappings = self.db.get_regulatory_mappings()
        
        self.engine = AlgComplianceEngine(
            use_nlp=self.nlp_enabled, 
            model_path=self.model_path,
            custom_keywords=self.custom_keywords,
            labeling_policies=self.labeling_policies,
            regulatory_mappings=self.regulatory_mappings
        )
        self.fingerprint_engine = FingerprintEngine(self.db)
        self.policy_engine = PolicyEngine(self.db)
        self.cross_linker = CrossLinker(self.db)
        
        from engine.anomaly_detector import AnomalyDetector
        self.anomaly_detector = AnomalyDetector(self.db)
        
        self.worker = None
        
        self._init_ui()
        self._init_shortcuts()
        self._check_engine_status()
        
        # Start Scheduler Background Daemon
        self.scheduler = TaskScheduler(self.db, self.engine, self)
        self.scheduler.task_started.connect(lambda n: self.status_lbl.setText(f"تشغيل المهمة المجدولة (Running task): {n}"))
        self.scheduler.task_finished.connect(lambda n, f, v: self.status_lbl.setText(f"اكتملت المهمة (Task done): {n} ({f} ملفات، {v} انتهاكات)"))
        self.scheduler.start()
        
        self._init_tray()

    def _init_tray(self):
        from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(qta.icon('fa5s.shield-alt', color=COLORS['ACCENT']))
        
        menu = QMenu()
        restore_action = menu.addAction("إظهار النافذة (Show Window)")
        restore_action.triggered.connect(self.showNormal)
        
        quit_action = menu.addAction("إنهاء (Quit)")
        quit_action.triggered.connect(self.force_quit)
        
        self.tray.setContextMenu(menu)
        self.tray.show()
        
    def closeEvent(self, event):
        # Hide to tray instead of quitting
        event.ignore()
        self.hide()
        self.tray.showMessage("Alg-PII Engine", "التطبيق يعمل في الخلفية.\nThe application is running in the background.", QSystemTrayIcon.MessageIcon.Information, 2000)

    def force_quit(self):
        self.scheduler.stop()
        self.scheduler.wait()
        from PyQt6.QtWidgets import QApplication
        QApplication.instance().quit()

    def _init_shortcuts(self):
        """Phase 4 Feature #30: Global Keyboard Shortcuts."""
        from PyQt6.QtGui import QShortcut, QKeySequence
        
        # Ctrl+S — Scan
        QShortcut(QKeySequence("Ctrl+S"), self, activated=self.on_scan)
        
        # Ctrl+Shift+B — Batch Scan
        QShortcut(QKeySequence("Ctrl+Shift+B"), self, activated=self.on_batch_scan)
        
        # Ctrl+Shift+D — Database Scan
        QShortcut(QKeySequence("Ctrl+Shift+D"), self, activated=self.on_db_scan)
        
        # Ctrl+L — Clear
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self.on_clear)
        
        # Ctrl+E — Export
        QShortcut(QKeySequence("Ctrl+E"), self, activated=self.on_export)
        
        # Ctrl+Shift+C — Copy anonymized output
        QShortcut(QKeySequence("Ctrl+Shift+C"), self, activated=self.on_copy)
        
        # F1 — About
        QShortcut(QKeySequence("F1"), self, activated=self.on_about)
        
        # Ctrl+Q — Quit
        QShortcut(QKeySequence("Ctrl+Q"), self, activated=self.force_quit)
        
        # Ctrl+, — Settings
        QShortcut(QKeySequence("Ctrl+,"), self, activated=self.on_settings)
        
        # Navigation shortcuts (admin pages)
        if self.user_role == "admin":
            # Ctrl+1..9 — Switch pages
            for i in range(min(10, self.content_stack.count())):
                shortcut = QShortcut(QKeySequence(f"Ctrl+{i+1}"), self)
                shortcut.activated.connect(lambda idx=i: self._switch_page(idx))

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # --- SIDEBAR ---
        self.sidebar = QFrame()
        self.sidebar.setFixedWidth(250)
        self.sidebar.setStyleSheet(f"background-color: {COLORS['BG_MAIN']}; border-right: 1px solid {COLORS['BG_PANEL']};")
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(10, 20, 10, 20)
        
        # Logo/Brand
        brand_lbl = QLabel("Alg-PII Engine")
        brand_lbl.setStyleSheet(f"color: {COLORS['ACCENT']}; font-size: 20px; font-weight: bold; border: none;")
        brand_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(brand_lbl)
        
        user_lbl = QLabel(f"مرحباً، {self.username}\n({self.user_role})")
        user_lbl.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; border: none;")
        user_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(user_lbl)
        
        sidebar_layout.addSpacing(30)
        
        # Sidebar Buttons
        self.nav_btns = []
        
        self.btn_nav_scan = SidebarButton('fa5s.search', "الماسح الضوئي (Scanner)")
        self.btn_nav_scan.setChecked(True)
        self.btn_nav_scan.clicked.connect(lambda: self._switch_page(0))
        sidebar_layout.addWidget(self.btn_nav_scan)
        self.nav_btns.append(self.btn_nav_scan)
        
        # Admin Only Buttons
        if self.user_role == "admin":
            self.btn_nav_dash = SidebarButton('fa5s.chart-pie', "لوحة الإحصائيات (Dashboard)")
            self.btn_nav_dash.clicked.connect(lambda: self._switch_page(1))
            sidebar_layout.addWidget(self.btn_nav_dash)
            self.nav_btns.append(self.btn_nav_dash)
            
            self.btn_nav_policies = SidebarButton('fa5s.shield-alt', "السياسات (Policies)")
            self.btn_nav_policies.clicked.connect(lambda: self._switch_page(2))
            sidebar_layout.addWidget(self.btn_nav_policies)
            self.nav_btns.append(self.btn_nav_policies)
            
            self.btn_nav_incidents = SidebarButton('fa5s.exclamation-triangle', "الحوادث (Incidents)")
            self.btn_nav_incidents.clicked.connect(lambda: self._switch_page(3))
            sidebar_layout.addWidget(self.btn_nav_incidents)
            self.nav_btns.append(self.btn_nav_incidents)
            
            self.btn_nav_scheduled = SidebarButton('fa5s.clock', "المهام المجدولة (Scheduled Tasks)")
            self.btn_nav_scheduled.clicked.connect(lambda: self._switch_page(4))
            sidebar_layout.addWidget(self.btn_nav_scheduled)
            self.nav_btns.append(self.btn_nav_scheduled)
            
            self.btn_nav_network = SidebarButton('fa5s.project-diagram', "شبكة الكيانات (Entity Network)")
            self.btn_nav_network.clicked.connect(lambda: self._switch_page(5))
            sidebar_layout.addWidget(self.btn_nav_network)
            self.nav_btns.append(self.btn_nav_network)
            
            self.btn_nav_dsar = SidebarButton('fa5s.user-shield', "طلبات الأفراد (DSAR)")
            self.btn_nav_dsar.clicked.connect(lambda: self._switch_page(6))
            sidebar_layout.addWidget(self.btn_nav_dsar)
            self.nav_btns.append(self.btn_nav_dsar)
            
            self.btn_nav_pia = SidebarButton('fa5s.clipboard-check', "التقييمات (PIA)")
            self.btn_nav_pia.clicked.connect(lambda: self._switch_page(7))
            sidebar_layout.addWidget(self.btn_nav_pia)
            self.nav_btns.append(self.btn_nav_pia)
            
            self.btn_nav_consent = SidebarButton('fa5s.handshake', "الموافقات (Consents)")
            self.btn_nav_consent.clicked.connect(lambda: self._switch_page(8))
            sidebar_layout.addWidget(self.btn_nav_consent)
            self.nav_btns.append(self.btn_nav_consent)
            
            self.btn_nav_vault = SidebarButton('fa5s.lock', "القبو الآمن (Vault)")
            self.btn_nav_vault.clicked.connect(lambda: self._switch_page(9))
            sidebar_layout.addWidget(self.btn_nav_vault)
            self.nav_btns.append(self.btn_nav_vault)
            
            self.btn_nav_settings = SidebarButton('fa5s.cog', "الإعدادات (Settings)")
            self.btn_nav_settings.clicked.connect(self.on_settings)
            sidebar_layout.addWidget(self.btn_nav_settings)
            self.nav_btns.append(self.btn_nav_settings)
            
        sidebar_layout.addStretch()
        
        self.btn_nav_about = SidebarButton('fa5s.info-circle', "حول البرنامج (About)")
        self.btn_nav_about.clicked.connect(self.on_about)
        sidebar_layout.addWidget(self.btn_nav_about)
        
        self.btn_nav_logout = SidebarButton('fa5s.sign-out-alt', "تسجيل خروج (Logout)")
        self.btn_nav_logout.clicked.connect(self.close)
        sidebar_layout.addWidget(self.btn_nav_logout)
        
        main_layout.addWidget(self.sidebar)
        
        # --- STACKED WIDGET (Content Area) ---
        self.content_stack = QStackedWidget()
        
        # Page 0: Scanner
        self.scanner_page = self._create_scanner_page()
        self.content_stack.addWidget(self.scanner_page)
        
        # Page 1: Dashboard (Only created if admin)
        if self.user_role == "admin":
            self.dashboard_page = DashboardWidget(self.db, self.user_role, self.user_department)
            self.content_stack.addWidget(self.dashboard_page)
            
            # Page 2: Policies
            self.policies_page = PoliciesPageWidget(self.db)
            self.content_stack.addWidget(self.policies_page)
            
            # Page 3: Incidents
            self.incidents_page = IncidentsPageWidget(self.db)
            self.content_stack.addWidget(self.incidents_page)
            
            # Page 4: Scheduled Tasks
            self.scheduled_page = ScheduledTasksPageWidget(self.db)
            self.content_stack.addWidget(self.scheduled_page)
            
            # Page 5: Entity Network
            from gui.entity_network_page import EntityNetworkPage
            self.network_page = EntityNetworkPage(self.db)
            self.content_stack.addWidget(self.network_page)
            
            # Page 6: DSAR Manager
            from gui.dsar_page import DSARPageWidget
            self.dsar_page = DSARPageWidget(self.db)
            self.content_stack.addWidget(self.dsar_page)
            
            # Page 7: PIA Page
            from gui.pia_page import PIAPageWidget
            self.pia_page = PIAPageWidget(self.db, self.user_department, self.username)
            self.content_stack.addWidget(self.pia_page)
            
            # Page 8: Consent Page
            from gui.consent_page import ConsentPageWidget
            self.consent_page = ConsentPageWidget(self.db)
            self.content_stack.addWidget(self.consent_page)
            
            # Page 9: Vault Page
            from gui.vault_page import VaultPageWidget
            self.vault_page = VaultPageWidget(self.db, self.user_department, self.username)
            self.content_stack.addWidget(self.vault_page)
            
        main_layout.addWidget(self.content_stack, stretch=1)
        
        # --- Status Bar ---
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.status_ind = StatusIndicator()
        self.status_bar.addPermanentWidget(self.status_ind)
        self.status_lbl = QLabel("جاهز (Ready)")
        self.status_bar.addPermanentWidget(self.status_lbl)
        
    def _create_scanner_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Input Panel
        input_panel = QWidget()
        input_layout = QVBoxLayout(input_panel)
        input_header_layout = QHBoxLayout()
        input_header = QLabel("النص المُدخل (Input Text)")
        input_header.setStyleSheet(f"color: {COLORS['ACCENT']}; font-weight: bold; font-size: 14px;")
        input_header_layout.addWidget(input_header)
        
        from PyQt6.QtWidgets import QCheckBox
        self.sync_scroll_cb = QCheckBox("مزامنة التمرير (Sync Scroll)")
        self.sync_scroll_cb.setChecked(True)
        self.sync_scroll_cb.stateChanged.connect(self._toggle_sync_scroll)
        input_header_layout.addWidget(self.sync_scroll_cb, alignment=Qt.AlignmentFlag.AlignRight)
        
        input_layout.addLayout(input_header_layout)
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("أدخل النص هنا للفحص...\n(Enter text here for scanning...)")
        input_layout.addWidget(self.input_text)
        
        self.drop_zone = DropZone()
        self.drop_zone.file_dropped.connect(self._handle_file_drop)
        input_layout.addWidget(self.drop_zone)
        
        btn_layout = QHBoxLayout()
        self.btn_scan = AnimatedButton("فحص والامتثال 🔍", primary=True)
        self.btn_scan.clicked.connect(self.on_scan)
        self.btn_batch = AnimatedButton("فحص مجلد 📁")
        self.btn_batch.clicked.connect(self.on_batch_scan)
        self.btn_usb = AnimatedButton("فحص USB/شبكة 🔌")
        self.btn_usb.clicked.connect(self.on_usb_scan)
        self.btn_db = AnimatedButton("فحص DB 🗄️")
        self.btn_db.clicked.connect(self.on_db_scan)
        self.btn_clear = AnimatedButton("مسح (Clear)")
        self.btn_clear.clicked.connect(self.on_clear)
        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_batch)
        btn_layout.addWidget(self.btn_usb)
        btn_layout.addWidget(self.btn_db)
        btn_layout.addWidget(self.btn_clear)
        input_layout.addLayout(btn_layout)
        
        # Output Panel
        output_panel = QWidget()
        output_layout = QVBoxLayout(output_panel)
        output_header = QLabel("النتائج المُعالجة (Processed Results)")
        output_header.setStyleSheet(f"color: {COLORS['ACCENT']}; font-weight: bold; font-size: 14px;")
        output_layout.addWidget(output_header)
        
        self.badges_layout = QHBoxLayout()
        self.badges_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        output_layout.addLayout(self.badges_layout)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        
        self.btn_copy = AnimatedButton("نسخ (Copy)")
        self.btn_copy.clicked.connect(self.on_copy)
        self.btn_export = AnimatedButton("تصدير (Export)", primary=True)
        self.btn_export.clicked.connect(self.on_export)
        self.btn_verify = AnimatedButton("تحقق (Verify)")
        self.btn_verify.clicked.connect(self.on_verify)
        
        # Init sync scrolling state
        self._toggle_sync_scroll()
        
        out_btn_layout = QHBoxLayout()
        out_btn_layout.addStretch()
        out_btn_layout.addWidget(self.btn_verify)
        out_btn_layout.addWidget(self.btn_copy)
        out_btn_layout.addWidget(self.btn_export)
        output_layout.addLayout(out_btn_layout)
        
        self.splitter.addWidget(input_panel)
        self.splitter.addWidget(output_panel)
        self.splitter.setSizes([600, 600])
        
        layout.addWidget(self.splitter)
        return page

    def _switch_page(self, index: int):
        for i, btn in enumerate(self.nav_btns):
            if i != index:
                btn.setChecked(False)
        self.content_stack.setCurrentIndex(index)
        
        if index == 1 and self.user_role == "admin":
            self.dashboard_page.refresh_data()

    def _check_engine_status(self):
        if self.nlp_enabled:
            QTimer.singleShot(100, self._load_nlp)
        else:
            self.status_ind.set_state('ready')
            self.status_lbl.setText("جاهز - وضع التعابير النمطية فقط (Regex Only Mode)")
            self.db.log_audit(self.username, "ENGINE_STATUS", "NLP disabled, Regex only mode.")
            
    def _load_nlp(self):
        self.status_ind.set_state('loading')
        self.status_lbl.setText("جاري تحميل نموذج الذكاء الاصطناعي... (Loading AI Model...)")
        QApplication.processEvents()
        
        success = self.engine.load_nlp_model(self.model_path)
        
        if success:
            self.status_ind.set_state('ready')
            self.status_lbl.setText("النموذج جاهز (AI Model Ready)")
            self.db.log_audit(self.username, "ENGINE_STATUS", "NLP Model loaded successfully.")
        else:
            self.status_ind.set_state('error')
            self.status_lbl.setText("فشل تحميل النموذج (AI Model Load Failed)")
            self.db.log_audit(self.username, "ENGINE_STATUS", "Failed to load NLP Model.")

    def _toggle_sync_scroll(self):
        in_bar = self.input_text.verticalScrollBar()
        out_bar = self.output_text.verticalScrollBar()
        
        # Disconnect any existing connections to prevent duplicates
        try:
            in_bar.valueChanged.disconnect()
            out_bar.valueChanged.disconnect()
        except TypeError:
            pass # No connections existed
            
        if self.sync_scroll_cb.isChecked():
            in_bar.valueChanged.connect(out_bar.setValue)
            out_bar.valueChanged.connect(in_bar.setValue)

    def _handle_file_drop(self, file_path: str):
        try:
            extracted_text, self._last_ocr_used = DocumentParser.extract_text(file_path)
            self._last_file_path = file_path
            self.input_text.setText(extracted_text)
            self.status_lbl.setText(f"تم تحميل الملف: {file_path.split('/')[-1]}")
            self.db.log_audit(self.username, "FILE_LOAD", f"Loaded file: {file_path}")
        except Exception as e:
            QMessageBox.warning(self, "خطأ (Error)", f"لا يمكن قراءة الملف: {e}")

    def on_scan(self):
        text = self.input_text.toPlainText()
        if not text.strip():
            return
            
        self.btn_scan.set_loading(True)
        self.status_ind.set_state('loading')
        self.status_lbl.setText("جاري الفحص... (Scanning...)")
        
        # Enforce strategy if not admin (standard users must use 'legal_mask')
        if self.user_role != "admin":
            self.strategy = "legal_mask"
            
        self.worker = ScanWorker(text, self.engine, self.strategy)
        self.worker.result.connect(self.on_scan_complete)
        self.worker.error.connect(self.on_scan_error)
        self.worker.finished.connect(self._on_scan_finished)
        self.worker.start()
        self.db.log_audit(self.username, "SCAN_START", f"Started manual scan with strategy {self.strategy}.")

    def on_batch_scan(self):
        batch_strategy = self.strategy if self.user_role == "admin" else "legal_mask"
        
        if self.user_role == "admin":
            templates = self.db.get_templates()
            if templates:
                from PyQt6.QtWidgets import QInputDialog
                items = ["بدون قالب (No Template)"] + [t[1] for t in templates]
                item, ok = QInputDialog.getItem(self, "اختر قالب", "قالب إخفاء الهوية (Anonymization Template):", items, 0, False)
                if ok and item != "بدون قالب (No Template)":
                    for t in templates:
                        if t[1] == item:
                            batch_strategy = t[2]
                            if t[4]:
                                self.engine.use_nlp = True
                                if not self.engine.is_nlp_available():
                                    self.engine.load_nlp_model(self.model_path)
                            else:
                                self.engine.use_nlp = False
                            break
                            
        input_dir = QFileDialog.getExistingDirectory(self, "اختر مجلد المصدر (Select Source Directory)")
        if not input_dir: return
        
        output_dir = QFileDialog.getExistingDirectory(self, "اختر مجلد الوجهة (Select Output Directory)")
        if not output_dir: return
        
        self.progress_dlg = QProgressDialog("جاري معالجة الملفات... (Processing files...)", "إلغاء (Cancel)", 0, 100, self)
        self.progress_dlg.setWindowTitle("فحص مجلد (Batch Scan)")
        self.progress_dlg.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dlg.setAutoClose(True)
        self.progress_dlg.setValue(0)
        
        self.batch_worker = BatchWorker(input_dir, output_dir, self.engine, batch_strategy, self.db, self.user_department)
        self.batch_worker.progress.connect(self._update_batch_progress)
        self.batch_worker.file_completed.connect(lambda f: self.progress_dlg.setLabelText(f"اكتمل (Completed): {f}"))
        self.batch_worker.finished.connect(self._on_batch_finished)
        self.batch_worker.error.connect(self.on_scan_error)
        self.progress_dlg.canceled.connect(self.batch_worker.cancel)
        
        self.batch_worker.start()

    def on_usb_scan(self):
        try:
            import psutil
            drives = []
            for part in psutil.disk_partitions(all=True):
                # Look for removable drives or network mounts
                if 'removable' in part.opts or 'network' in part.opts or part.fstype == 'exFAT' or part.fstype == 'FAT32':
                    drives.append(part.mountpoint)
                    
            if not drives:
                QMessageBox.information(self, "فحص USB/شبكة", "لم يتم اكتشاف أي أقراص USB أو أقراص شبكة متصلة حالياً.\nسيتم فتح نافذة اختيار المجلد العادية.")
            else:
                msg = "تم اكتشاف الأقراص الخارجية التالية:\n" + "\n".join(drives) + "\n\nيرجى تحديد المجلد المطلوب فحصه في النافذة التالية."
                QMessageBox.information(self, "اكتشاف USB/شبكة", msg)
                
        except ImportError:
            pass # psutil not installed, fallback to normal batch scan
            
        self.on_batch_scan()
        self.db.log_audit(self.username, "BATCH_SCAN_START", f"Started batch scan on USB/network drive.")
        
    def on_db_scan(self):
        """Opens the Database Scanner dialog and feeds extracted text into the scan engine."""
        from gui.db_scanner import DatabaseScanDialog
        dlg = DatabaseScanDialog(self)
        if dlg.exec() == DatabaseScanDialog.DialogCode.Accepted:
            text = dlg.fetch_data()
            if text:
                self.input_text.setPlainText(text)
                self.status_lbl.setText("تم استخراج البيانات من قاعدة البيانات — اضغط فحص (Data extracted from DB — press Scan)")
                self.db.log_audit(self.username, "DB_SCAN_EXTRACT", 
                    f"Extracted data from {dlg.db_type.currentText()} table '{dlg.table_name.text()}' for scanning.")
            else:
                QMessageBox.warning(self, "تحذير", "لم يتم استخراج أي بيانات من قاعدة البيانات.")

    def _update_batch_progress(self, current, total):
        if total > 0:
            val = int((current / total) * 100)
            self.progress_dlg.setValue(val)
            
    def _on_batch_finished(self, total_processed):
        QMessageBox.information(self, "اكتمل الفحص (Batch Complete)", f"تمت معالجة {total_processed} ملف(ات) بنجاح.")
        self.db.log_audit(self.username, "BATCH_SCAN_END", f"Finished batch scan, processed {total_processed} files.")

    def _on_scan_finished(self):
        self.btn_scan.set_loading(False)
        self.status_ind.set_state('ready')

    def on_scan_complete(self, result: AnonymizedResult):
        self._last_anon_result = result
        self.output_text.setHtml(result.html_highlighted)
        self.status_lbl.setText("اكتمل الفحص (Scan Complete)")
        
        # Original text reveal (Admin only feature conceptually, but we can just let them see the output)
        # We enforce viewing only redacted in the UI implicitly because output_text sets HTML
        
        # Update badges
        for i in reversed(range(self.badges_layout.count())): 
            widget = self.badges_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
                
        counts = {}
        for ent in result.entities:
            counts[ent.entity_type] = counts.get(ent.entity_type, 0) + 1
            
        report = self.engine.generate_report(result.scan_result)
        
        # Display Sensitivity Label
        label_color = next((p['label_color'] for p in self.labeling_policies if p['label_name'] == report.sensitivity_label), COLORS['ACCENT'])
        lbl_badge = EntityBadge("التصنيف: " + report.sensitivity_label, 0)
        lbl_badge.setStyleSheet(f"background-color: {label_color}; color: white; border-radius: 12px;")
        lbl_badge.layout().itemAt(1).widget().hide() # Hide count
        self.badges_layout.addWidget(lbl_badge)
        
        for etype, count in counts.items():
            # Check if this etype has a legal mapping
            has_law = any(a['entity_type'] == etype for a in report.applicable_articles)
            badge_text = f"{etype} 📜" if has_law else etype
            
            badge = EntityBadge(badge_text, count)
            if has_law:
                # Store the applicable articles as tooltip
                articles_text = "\n".join([f"{a['law_name']} - {a['article_number']}: {a['article_summary_ar']}" for a in report.applicable_articles if a['entity_type'] == etype])
                badge.setToolTip(articles_text)
                
            self.badges_layout.addWidget(badge)
            
        # PII Clusters Display
        if report.clusters:
            cluster_badge = EntityBadge("عناقيد البيانات (Data Clusters) 🔗", len(report.clusters))
            cluster_badge.setStyleSheet(f"background-color: {COLORS['ACCENT_PURPLE']}; color: white; border-radius: 12px;")
            
            cluster_tips = []
            for i, cluster in enumerate(report.clusters, 1):
                cluster_tips.append(f"Cluster {i}: {cluster['reason']} (x{cluster['multiplier']})")
                
            cluster_badge.setToolTip("\n".join(cluster_tips))
            self.badges_layout.addWidget(cluster_badge)
            
        # Fingerprinting and Duplicate Detection
        fp = self.fingerprint_engine.compute_fingerprint(result.original_text)
        duplicates = self.fingerprint_engine.find_duplicates(fp)
        duplicates_found = len(duplicates)
        
        if duplicates_found > 0:
            dup_badge = EntityBadge("⚠️ مستند مكرر (Duplicate)", duplicates_found)
            dup_badge.setStyleSheet(f"background-color: {COLORS['WARNING']}; color: {COLORS['BG_MAIN']}; border-radius: 12px;")
            self.badges_layout.addWidget(dup_badge)
            
            dup_text = "\n".join([f"Scan {d[0]}: {d[1]} ({d[2]*100:.1f}%)" for d in duplicates])
            dup_badge.setToolTip(dup_text)
            
        self.badges_layout.addStretch()
        
        # Determine if OCR was used (either from recent file load, or default to False)
        ocr_used = getattr(self, '_last_ocr_used', False)
        
        if result.entities or duplicates_found > 0:
            # Use user_department
            last_id = self.db.log_scan("User_Input", len(result.entities), report.risk_level, self.strategy, counts, report.sensitivity_label, ocr_used, duplicates_found, self.user_department)
            self.fingerprint_engine.store_fingerprint(last_id, "User_Input", fp)
            
            # Log clusters
            for cluster in report.clusters:
                self.db.save_cluster(last_id, cluster['reason'], cluster['multiplier'], ",".join(cluster['types']))
                
            # Cross-document Entity Indexing
            # Determine document name if available
            doc_name = "User_Input"
            if hasattr(self, '_last_file_path') and self._last_file_path:
                doc_name = self._last_file_path.split('/')[-1]
            self.cross_linker.index_scan_result(last_id, doc_name, result.entities, department=None)
                
            # Evaluate Compliance Policies
            violations = self.policy_engine.evaluate(result.scan_result, "User_Input")
            if violations:
                violation_badge = EntityBadge(f"⚠️ {len(violations)} Policy Violations", len(violations))
                violation_badge.setStyleSheet(f"background-color: {COLORS['ERROR']}; color: white; border-radius: 12px;")
                v_tips = [f"{v.severity}: {v.name}" for v in violations]
                violation_badge.setToolTip("\n".join(v_tips))
                self.badges_layout.addWidget(violation_badge)
                
                for v in violations:
                    self.db.log_policy_violation(v.policy_id, last_id, "User_Input", v.details)
                    # Auto-create incident for serious violations
                    if v.severity in ["CRITICAL", "BLOCKER", "HIGH"]:
                        mapped_sev = "CRITICAL" if v.severity == "BLOCKER" else v.severity
                        self.db.create_incident(f"انتهاك سياسة (Policy): {v.name}", v.details, mapped_sev, "policy_violation", last_id, "system")
                        
            # Run Anomaly Detection
            anomaly = self.anomaly_detector.analyze_scan(last_id, len(result.entities))
            if anomaly:
                anomaly_badge = EntityBadge(f"🚨 شذوذ بيانات (Anomaly Z={anomaly['z_score']:.1f})", anomaly['observed'])
                anomaly_badge.setStyleSheet(f"background-color: {COLORS['ERROR']}; color: white; border-radius: 12px;")
                anomaly_badge.setToolTip(f"تم اكتشاف شذوذ بمقدار {anomaly['z_score']:.1f} انحرافات معيارية فوق المتوسط.")
                self.badges_layout.addWidget(anomaly_badge)
                        
            # Auto-create incident for CRITICAL risk level scans
            if report.risk_level == "CRITICAL":
                self.db.create_incident(f"مستند عالي الخطورة (CRITICAL Scan)", f"تم العثور على بيانات حساسة للغاية في المستند.", "CRITICAL", "scan_alert", last_id, "system")
                
        self._last_report = report

    def on_scan_error(self, msg: str):
        QMessageBox.critical(self, "خطأ (Error)", f"حدث خطأ أثناء الفحص:\n{msg}")
        self.status_lbl.setText("خطأ (Error)")

    def on_clear(self):
        self.input_text.clear()
        self.output_text.clear()
        for i in reversed(range(self.badges_layout.count())): 
            widget = self.badges_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

    def on_copy(self):
        QApplication.clipboard().setText(self.output_text.toPlainText())
        self.status_lbl.setText("تم النسخ إلى الحافظة (Copied to Clipboard)")

    def on_export(self):
        if not hasattr(self, '_last_anon_result') or not self._last_anon_result:
            QMessageBox.warning(self, "تنبيه", "لا توجد نتائج للتصدير. يرجى الفحص أولاً.")
            return
            
        formats = "PDF Report (*.pdf);;Word Document (*.docx);;Excel Spreadsheet (*.xlsx);;JSON Format (*.json);;XML Format (*.xml);;CSV Format (*.csv);;Text Files (*.txt)"
        path, _ = QFileDialog.getSaveFileName(self, "حفظ (Save)", "", formats)
        if path:
            try:
                from engine.exporters import ReportExporter
                if path.lower().endswith('.pdf'):
                    PDFExporter.export_report(self._last_anon_result, self._last_report, path)
                elif path.lower().endswith('.docx'):
                    ReportExporter.save_docx(self._last_anon_result.scan_result, self._last_report, path)
                elif path.lower().endswith('.xlsx'):
                    ReportExporter.save_xlsx(self._last_anon_result.scan_result, path)
                elif path.lower().endswith('.json'):
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(ReportExporter.to_json(self._last_anon_result.scan_result, self._last_report))
                elif path.lower().endswith('.xml'):
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(ReportExporter.to_xml(self._last_anon_result.scan_result, self._last_report))
                elif path.lower().endswith('.csv'):
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(ReportExporter.to_csv(self._last_anon_result.scan_result))
                else:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(self.output_text.toPlainText())
                QMessageBox.information(self, "نجاح", f"تم التصدير بنجاح إلى:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "خطأ", f"فشل التصدير:\n{str(e)}")

    def on_verify(self):
        if not hasattr(self, '_last_anon_result') or not self._last_anon_result:
            QMessageBox.warning(self, "تنبيه", "لا توجد نتائج للتحقق. يرجى الفحص أولاً.")
            return
            
        original_scan = self._last_anon_result.scan_result
        anonymized_text = self._last_anon_result.anonymized_text
        
        result = RedactionVerifier.verify(original_scan, anonymized_text)
        
        if result.is_successful:
            QMessageBox.information(self, "تحقق ناجح (Verification Passed)", 
                f"نسبة التمويه: {result.masking_percentage:.1f}%\n{result.details}")
        else:
            QMessageBox.warning(self, "تحذير: تسريب بيانات (Leak Warning)", 
                f"نسبة التمويه: {result.masking_percentage:.1f}%\n{result.details}\n\n"
                f"الكيانات المسربة: {', '.join([e.text for e in result.leaked_entities])}")

    def on_settings(self):
        if self.user_role != "admin":
            QMessageBox.warning(self, "مرفوض", "فقط المشرف يمكنه الدخول للإعدادات.")
            return
            
        dlg = SettingsDialog(self.db, self.user_role, self)
        dlg.settings_changed.connect(self._apply_settings)
        dlg.exec()
        
    def _apply_settings(self, settings: dict):
        self.nlp_enabled = settings.get('nlp_enabled', True)
        self.model_path = settings.get('model_path', None)
        self.strategy = settings.get('anonymization_strategy', 'legal_mask')
        
        # Dynamically reload custom keywords
        self.custom_keywords = self.db.get_custom_keywords()
        self.engine.update_custom_keywords(self.custom_keywords)
        
        self.labeling_policies = self.db.get_labeling_policies()
        self.engine.update_labeling_policies(self.labeling_policies)
        
        self.regulatory_mappings = self.db.get_regulatory_mappings()
        self.engine.update_regulatory_mappings(self.regulatory_mappings)
        
        self.db.log_audit(self.username, "SETTINGS", "Admin updated system settings and keywords.")
        
        # Check NLP engine status
        if self.nlp_enabled and not self.engine.is_nlp_available():
            self._check_engine_status()

    def on_about(self):
        msg = f"""
        <h3>Alg-PII Engine v1.0.0 (Enterprise)</h3>
        <p><b>The Sovereign RegTech Hub of Algeria</b></p>
        <p>Built for absolute data sovereignty, functioning entirely offline without external API dependencies.</p>
        <hr>
        <h4>Legal Compliance Framework:</h4>
        <ul>
            <li><b>Law 18-07:</b> Protection of natural persons in the processing of personal data.</li>
            <li><b>Law 18-05:</b> Electronic Commerce and Banking Secrecy.</li>
        </ul>
        <hr>
        <h4>اختصارات لوحة المفاتيح (Keyboard Shortcuts):</h4>
        <table>
            <tr><td><b>Ctrl+S</b></td><td>فحص (Scan)</td></tr>
            <tr><td><b>Ctrl+Shift+B</b></td><td>فحص مجلد (Batch Scan)</td></tr>
            <tr><td><b>Ctrl+Shift+D</b></td><td>فحص قاعدة بيانات (DB Scan)</td></tr>
            <tr><td><b>Ctrl+L</b></td><td>مسح (Clear)</td></tr>
            <tr><td><b>Ctrl+E</b></td><td>تصدير (Export)</td></tr>
            <tr><td><b>Ctrl+Shift+C</b></td><td>نسخ (Copy Output)</td></tr>
            <tr><td><b>Ctrl+,</b></td><td>الإعدادات (Settings)</td></tr>
            <tr><td><b>F1</b></td><td>حول البرنامج (About)</td></tr>
            <tr><td><b>Ctrl+Q</b></td><td>إنهاء (Quit)</td></tr>
            <tr><td><b>Ctrl+1..9</b></td><td>التنقل بين الصفحات (Navigate Pages)</td></tr>
        </table>
        <hr>
        <p><i>Licensed to Hardware ID: {LicenseManager.get_hardware_id()}</i></p>
        """
        QMessageBox.about(self, "حول البرنامج | About Alg-PII Engine", msg)
