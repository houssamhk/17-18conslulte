import os
import sys
import logging
from dataclasses import replace
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QSplitter, QTextEdit, QLabel, QStatusBar, QMenuBar, 
                             QFileDialog, QMessageBox, QApplication, QProgressDialog,
                             QStackedWidget, QPushButton, QFrame, QDialog)
from PyQt6.QtWidgets import QScrollArea
from PyQt6.QtWidgets import QSystemTrayIcon
from PyQt6.QtCore import Qt, QTimer, QSize, QPropertyAnimation, QEasingCurve, QEvent, QObject
from PyQt6.QtWidgets import QGraphicsOpacityEffect
from PyQt6.QtGui import QAction, QIcon
import qtawesome as qta

from engine.compliance_engine import AlgComplianceEngine
from engine.regex_detector import AnonymizedResult
from engine.document_parser import DocumentParser
from engine.pdf_exporter import PDFExporter
from engine.fingerprint import FingerprintEngine
from engine.policy_engine import PolicyEngine
from engine.scheduler import TaskScheduler
from engine.cross_linker import CrossLinker
from storage.secure_db import SecureDatabase
from .widgets import AnimatedButton, EntityBadge, StatusIndicator, DropZone, ComplianceGauge
from .scan_thread import NLPModelLoadWorker, ScanWorker, VerificationWorker
from .batch_worker import BatchWorker
from .settings_dialog import SettingsDialog
from .theme import COLORS
from engine.license_manager import LicenseManager
from .license_dialog import LicenseDialog
from .login_dialog import FirstRunAdminDialog, LoginDialog, PasswordChangeDialog, SessionLockDialog
from .totp_dialog import TotpManagementDialog, TotpRecoveryDialog
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


class SessionActivityMonitor(QObject):
    """Reset a single-shot lock timer on keyboard and pointer activity."""

    ACTIVITY_EVENTS = {
        QEvent.Type.MouseMove,
        QEvent.Type.MouseButtonPress,
        QEvent.Type.MouseButtonRelease,
        QEvent.Type.KeyPress,
        QEvent.Type.Wheel,
        QEvent.Type.TouchBegin,
        QEvent.Type.TouchUpdate,
        QEvent.Type.TabletPress,
    }

    def __init__(self, window, timeout_minutes):
        super().__init__(QApplication.instance())
        self.window = window
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(window.lock_session)
        QApplication.instance().installEventFilter(self)
        self.set_timeout(timeout_minutes)

    def set_timeout(self, timeout_minutes):
        self.timeout_ms = max(0, int(timeout_minutes)) * 60 * 1000
        if self.timeout_ms:
            self.timer.start(self.timeout_ms)
        else:
            self.timer.stop()

    def pause(self):
        self.timer.stop()

    def resume(self):
        if self.timeout_ms:
            self.timer.start(self.timeout_ms)

    def eventFilter(self, watched, event):
        if (self.timeout_ms and not self.window._session_locked
                and event.type() in self.ACTIVITY_EVENTS):
            self.timer.start(self.timeout_ms)
        return False

class AlgPIIMainWindow(QMainWindow):
    def __init__(self, db: SecureDatabase):
        super().__init__()
        self.db = db
        self._verification_passed = False
        self._verification_target = None
        
        # 1. License Check
        if not LicenseManager.is_activated():
            dlg = LicenseDialog(self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                sys.exit(0)

        if not self.db.has_users():
            setup_dlg = FirstRunAdminDialog(self.db, self)
            if setup_dlg.exec() != QDialog.DialogCode.Accepted:
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
        self.nlp_enabled = self.db.get_setting("nlp_enabled", False)
        self.model_path = self.db.get_setting("model_path", None)
        self.strategy = self.db.get_setting("anonymization_strategy", "legal_mask")
        self.custom_keywords = self.db.get_custom_keywords()
        self.ocr_enabled = self.db.get_setting("ocr_enabled", True)
        self.ocr_language = self.db.get_setting("ocr_language", "ara+eng")
        self.tesseract_cmd = self.db.get_setting("tesseract_cmd", "")
        DocumentParser.configure_ocr(self.ocr_enabled, self.ocr_language, self.tesseract_cmd)
        
        self.setWindowTitle("محرك الامتثال الجزائري | Alg-PII Engine")
        
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

        # Build the scheduler before the page stack because the scheduled-task
        # page receives it during construction. Start it only after the UI is ready.
        self.scheduler = TaskScheduler(self.db, self.engine, self)
        
        self.worker = None
        
        self._init_ui()
        # Apply the window bounds after building pages; otherwise large
        # size hints from hidden admin pages can force it beyond screen height.
        self.setMinimumSize(900, 600)
        self.resize(1440, 900)
        self._init_shortcuts()
        self._check_engine_status()
        
        # Start Scheduler Background Daemon after status widgets exist.
        self.scheduler.task_started.connect(lambda n: self.status_lbl.setText(f"تشغيل المهمة المجدولة (Running task): {n}"))
        self.scheduler.task_finished.connect(
            lambda n, f, v, errors: self.status_lbl.setText(
                f"اكتملت المهمة: {n} ({f} ملفات، {v} انتهاكات، {errors} إخفاقات)"
            )
        )
        self.scheduler.start()
        
        self._init_tray()
        self._session_locked = False
        self.session_activity_monitor = SessionActivityMonitor(
            self, self.db.get_setting("session_idle_minutes", 15)
        )
        self._audit_integrity_alerted = False
        self.audit_integrity_timer = QTimer(self)
        self.audit_integrity_timer.setInterval(5 * 60 * 1000)
        self.audit_integrity_timer.timeout.connect(self._check_audit_integrity)
        self.audit_integrity_timer.start()
        QTimer.singleShot(1200, self._check_audit_integrity)

    def _check_audit_integrity(self):
        """Check the tamper-evident audit chain without writing to it."""
        try:
            result = self.db.verify_audit_integrity()
        except Exception:
            logging.exception("Could not verify audit log integrity")
            result = {"valid": False, "reason": "verification_error", "entry_id": None}

        if result.get("valid"):
            if result.get("truncated_prefix"):
                self.audit_integrity_lbl.setText("التدقيق: سلسلة مقتطعة")
                self.audit_integrity_lbl.setToolTip("السجلات المتاحة سليمة، لكن سياسة الاحتفاظ أزالت بداية السلسلة.")
                self.audit_integrity_lbl.setStyleSheet(f"color: {COLORS['WARNING']};")
            else:
                self.audit_integrity_lbl.setText("التدقيق: سليم")
                self.audit_integrity_lbl.setToolTip("اجتازت سلسلة سجل التدقيق فحص HMAC والمرساة المحمية.")
                self.audit_integrity_lbl.setStyleSheet(f"color: {COLORS['SUCCESS']};")
            self._audit_integrity_alerted = False
            return

        reason = result.get("reason", "verification_error")
        self.audit_integrity_lbl.setText("تحذير: تعذر التحقق من سجل التدقيق")
        self.audit_integrity_lbl.setToolTip(f"سبب الفشل: {reason}; السجل: {result.get('entry_id')}")
        self.audit_integrity_lbl.setStyleSheet(f"color: {COLORS['ERROR']}; font-weight: bold;")
        if not self._audit_integrity_alerted:
            self._audit_integrity_alerted = True
            QMessageBox.critical(
                self,
                "تحذير سلامة سجل التدقيق",
                "فشل فحص سلامة سجل التدقيق. قد تكون سجلات قد عُدّلت أو حُذفت، أو تعذر الوصول إلى المرساة المحمية. لا تعتمد على السجل حتى يراجعه مسؤول النظام.",
            )

    def _show_account_menu(self):
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        change_password = menu.addAction("تغيير كلمة المرور")
        totp_enabled = self.db.user_totp_enabled(self.username)
        manage_totp = menu.addAction("تعطيل المصادقة الثنائية" if totp_enabled else "إعداد المصادقة الثنائية")
        recovery_codes = None
        if totp_enabled:
            remaining = self.db.get_totp_recovery_count(self.username)
            recovery_codes = menu.addAction(f"تجديد أكواد الاسترداد ({remaining} متبقية)")
        lock_session = menu.addAction("قفل الجلسة")
        selected = menu.exec(self.cursor().pos())
        if selected == change_password:
            dialog = PasswordChangeDialog(self.db, self.username, self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.status_lbl.setText("تم تحديث كلمة مرور الحساب")
        elif selected == lock_session:
            self.lock_session()
        elif selected == manage_totp:
            dialog = TotpManagementDialog(self.db, self.username, totp_enabled, self)
            dialog.exec()
        elif selected == recovery_codes:
            dialog = TotpRecoveryDialog(self.db, self.username, self)
            dialog.exec()

    def lock_session(self):
        """Hide sensitive application content until the current user reauthenticates."""
        if self._session_locked:
            return
        self._session_locked = True
        self.session_activity_monitor.pause()
        self.db.log_audit(self.username, "SESSION_LOCK", "User locked their application session.")
        self.hide()
        dialog = SessionLockDialog(self.db, self.username)
        unlocked = dialog.exec() == QDialog.DialogCode.Accepted
        if not unlocked:
            self.force_quit()
            return
        self._session_locked = False
        self.session_activity_monitor.resume()
        self.db.log_audit(self.username, "SESSION_UNLOCK", "User unlocked their application session.")
        self.show()
        self.raise_()
        self.activateWindow()
        self.status_lbl.setText("تم إلغاء قفل الجلسة")

    def _init_tray(self):
        from PyQt6.QtWidgets import QMenu
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
        if getattr(self, "nlp_worker", None) and self.nlp_worker.isRunning():
            self.nlp_worker.wait()
        self.scheduler.stop()
        self.scheduler.wait()
        self.tray.hide()
        self.db.close()
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
        QShortcut(QKeySequence("Ctrl+Alt+L"), self, activated=self.lock_session)
        
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
        self.sidebar.setFixedWidth(268)
        self.sidebar.setStyleSheet(f"background-color: {COLORS['BG_MAIN']}; border-right: 1px solid {COLORS['BG_PANEL']};")
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(12, 24, 12, 20)
        sidebar_layout.setSpacing(6)
        
        # Logo/Brand
        brand_lbl = QLabel("Alg-PII Engine")
        brand_lbl.setStyleSheet(f"color: {COLORS['ACCENT']}; font-size: 20px; font-weight: bold; border: none;")
        brand_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(brand_lbl)
        
        user_lbl = QPushButton(f"مرحباً، {self.username}\n({self.user_role})  ·  الحساب")
        user_lbl.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; border: none; background: transparent; padding: 8px 4px;")
        user_lbl.setToolTip("إدارة كلمة مرور الحساب")
        user_lbl.clicked.connect(self._show_account_menu)
        sidebar_layout.addWidget(user_lbl)
        
        sidebar_layout.addSpacing(30)

        nav_scroll = QScrollArea()
        nav_scroll.setWidgetResizable(True)
        nav_scroll.setFrameShape(QFrame.Shape.NoFrame)
        nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        nav_content = QWidget()
        navigation_layout = QVBoxLayout(nav_content)
        navigation_layout.setContentsMargins(0, 0, 0, 0)
        navigation_layout.setSpacing(6)
        
        # Sidebar Buttons
        self.nav_btns = []
        
        self.btn_nav_scan = SidebarButton('fa5s.search', "الماسح الضوئي (Scanner)")
        self.btn_nav_scan.setChecked(True)
        self.btn_nav_scan.clicked.connect(lambda: self._switch_page(0))
        navigation_layout.addWidget(self.btn_nav_scan)
        self.nav_btns.append(self.btn_nav_scan)

        if self.user_role != "admin":
            self.btn_nav_dash = SidebarButton('fa5s.chart-pie', "لوحة القسم (Department Dashboard)")
            self.btn_nav_dash.clicked.connect(lambda: self._switch_page(1))
            navigation_layout.addWidget(self.btn_nav_dash)
            self.nav_btns.append(self.btn_nav_dash)
        
        # Admin Only Buttons
        if self.user_role == "admin":
            self.btn_nav_dash = SidebarButton('fa5s.chart-pie', "لوحة الإحصائيات (Dashboard)")
            self.btn_nav_dash.clicked.connect(lambda: self._switch_page(1))
            navigation_layout.addWidget(self.btn_nav_dash)
            self.nav_btns.append(self.btn_nav_dash)
            
            self.btn_nav_policies = SidebarButton('fa5s.shield-alt', "السياسات (Policies)")
            self.btn_nav_policies.clicked.connect(lambda: self._switch_page(2))
            navigation_layout.addWidget(self.btn_nav_policies)
            self.nav_btns.append(self.btn_nav_policies)
            
            self.btn_nav_incidents = SidebarButton('fa5s.exclamation-triangle', "الحوادث (Incidents)")
            self.btn_nav_incidents.clicked.connect(lambda: self._switch_page(3))
            navigation_layout.addWidget(self.btn_nav_incidents)
            self.nav_btns.append(self.btn_nav_incidents)
            
            self.btn_nav_scheduled = SidebarButton('fa5s.clock', "المهام المجدولة (Scheduled Tasks)")
            self.btn_nav_scheduled.clicked.connect(lambda: self._switch_page(4))
            navigation_layout.addWidget(self.btn_nav_scheduled)
            self.nav_btns.append(self.btn_nav_scheduled)
            
            self.btn_nav_network = SidebarButton('fa5s.project-diagram', "شبكة الكيانات (Entity Network)")
            self.btn_nav_network.clicked.connect(lambda: self._switch_page(5))
            navigation_layout.addWidget(self.btn_nav_network)
            self.nav_btns.append(self.btn_nav_network)
            
            self.btn_nav_dsar = SidebarButton('fa5s.user-shield', "طلبات الأفراد (DSAR)")
            self.btn_nav_dsar.clicked.connect(lambda: self._switch_page(6))
            navigation_layout.addWidget(self.btn_nav_dsar)
            self.nav_btns.append(self.btn_nav_dsar)
            
            self.btn_nav_pia = SidebarButton('fa5s.clipboard-check', "التقييمات (PIA)")
            self.btn_nav_pia.clicked.connect(lambda: self._switch_page(7))
            navigation_layout.addWidget(self.btn_nav_pia)
            self.nav_btns.append(self.btn_nav_pia)
            
            self.btn_nav_consent = SidebarButton('fa5s.handshake', "الموافقات (Consents)")
            self.btn_nav_consent.clicked.connect(lambda: self._switch_page(8))
            navigation_layout.addWidget(self.btn_nav_consent)
            self.nav_btns.append(self.btn_nav_consent)
            
            self.btn_nav_vault = SidebarButton('fa5s.lock', "القبو الآمن (Vault)")
            self.btn_nav_vault.clicked.connect(lambda: self._switch_page(9))
            navigation_layout.addWidget(self.btn_nav_vault)
            self.nav_btns.append(self.btn_nav_vault)

            self.btn_nav_transfers = SidebarButton('fa5s.exchange-alt', "النقل الآمن (Transfers)")
            self.btn_nav_transfers.clicked.connect(lambda: self._switch_page(10))
            navigation_layout.addWidget(self.btn_nav_transfers)
            self.nav_btns.append(self.btn_nav_transfers)

            self.btn_nav_data_flow = SidebarButton('fa5s.project-diagram', "تدفق البيانات (Data Flow)")
            self.btn_nav_data_flow.clicked.connect(lambda: self._switch_page(11))
            navigation_layout.addWidget(self.btn_nav_data_flow)
            self.nav_btns.append(self.btn_nav_data_flow)

            self.btn_nav_calendar = SidebarButton('fa5s.calendar-alt', "تقويم الامتثال (Calendar)")
            self.btn_nav_calendar.clicked.connect(lambda: self._switch_page(12))
            navigation_layout.addWidget(self.btn_nav_calendar)
            self.nav_btns.append(self.btn_nav_calendar)

            self.btn_nav_training = SidebarButton('fa5s.graduation-cap', "التدريب (Training)")
            self.btn_nav_training.clicked.connect(lambda: self._switch_page(13))
            navigation_layout.addWidget(self.btn_nav_training)
            self.nav_btns.append(self.btn_nav_training)

            self.btn_nav_report_templates = SidebarButton('fa5s.file-alt', "قوالب التقارير (Report Templates)")
            self.btn_nav_report_templates.clicked.connect(lambda: self._switch_page(14))
            navigation_layout.addWidget(self.btn_nav_report_templates)
            self.nav_btns.append(self.btn_nav_report_templates)
            
            self.btn_nav_settings = SidebarButton('fa5s.cog', "الإعدادات (Settings)")
            self.btn_nav_settings.clicked.connect(self.on_settings)
            navigation_layout.addWidget(self.btn_nav_settings)
            self.nav_btns.append(self.btn_nav_settings)
            
        navigation_layout.addStretch()
        nav_scroll.setWidget(nav_content)
        sidebar_layout.addWidget(nav_scroll, stretch=1)
        
        self.btn_nav_about = SidebarButton('fa5s.info-circle', "حول البرنامج (About)")
        self.btn_nav_about.clicked.connect(self.on_about)
        sidebar_layout.addWidget(self.btn_nav_about)
        
        self.btn_nav_logout = SidebarButton('fa5s.sign-out-alt', "إنهاء آمن (Quit)")
        self.btn_nav_logout.clicked.connect(self.force_quit)
        sidebar_layout.addWidget(self.btn_nav_logout)
        
        main_layout.addWidget(self.sidebar)
        
        # --- STACKED WIDGET (Content Area) ---
        self.content_stack = QStackedWidget()
        
        # Page 0: Scanner
        self.scanner_page = self._create_scanner_page()
        self.content_stack.addWidget(self.scanner_page)
        
        # Page 1: Dashboard; standard users receive department-scoped data.
        self.dashboard_page = DashboardWidget(self.db, self.user_role, self.user_department)
        self.content_stack.addWidget(self.dashboard_page)

        if self.user_role == "admin":
            # Page 2: Policies
            self.policies_page = PoliciesPageWidget(self.db)
            self.content_stack.addWidget(self.policies_page)
            
            # Page 3: Incidents
            self.incidents_page = IncidentsPageWidget(self.db)
            self.content_stack.addWidget(self.incidents_page)
            
            # Page 4: Scheduled Tasks
            self.scheduled_page = ScheduledTasksPageWidget(
                self.db, self.username, scheduler=self.scheduler
            )
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

            # These pages contain organization-wide transfer and flow records.
            # Keep them in the administrator-only page stack.
            self.transfer_page = TransferPageWidget(self.db, None, self.username)
            self.content_stack.addWidget(self.transfer_page)

            self.data_flow_page = DataFlowPageWidget(self.db)
            self.content_stack.addWidget(self.data_flow_page)

            # These admin pages were implemented but not reachable from navigation.
            self.calendar_page = CalendarPageWidget(self.db)
            self.content_stack.addWidget(self.calendar_page)

            self.training_page = TrainingPageWidget(self.db, self.username)
            self.content_stack.addWidget(self.training_page)

            self.report_template_page = ReportTemplatePageWidget(self.db)
            self.content_stack.addWidget(self.report_template_page)
            
        main_layout.addWidget(self.content_stack, stretch=1)
        
        # --- Status Bar ---
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.status_ind = StatusIndicator()
        self.status_bar.addPermanentWidget(self.status_ind)
        self.status_lbl = QLabel("جاهز (Ready)")
        self.status_bar.addPermanentWidget(self.status_lbl)
        self.engine_capability_lbl = QLabel("الكشف: قواعد محلية | OCR: حسب التثبيت")
        self.engine_capability_lbl.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']};")
        self.status_bar.addPermanentWidget(self.engine_capability_lbl)
        self.audit_integrity_lbl = QLabel("التدقيق: جارٍ الفحص")
        self.audit_integrity_lbl.setToolTip("يُفحص سجل التدقيق تلقائيًا عند بدء التشغيل وكل خمس دقائق.")
        self.status_bar.addPermanentWidget(self.audit_integrity_lbl)
        
    def _create_scanner_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        # A small first-run guide makes the scanner usable without requiring
        # users to find their own sensitive documents just to try the app.
        intro = QFrame()
        intro.setObjectName("scannerIntro")
        intro.setStyleSheet(f"""
            QFrame#scannerIntro {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 12px;
            }}
            QFrame#scannerIntro QLabel {{ border: none; background: transparent; }}
        """)
        intro_layout = QHBoxLayout(intro)
        intro_layout.setContentsMargins(18, 12, 18, 12)
        intro_copy = QVBoxLayout()
        intro_title = QLabel("ابدأ بفحص بيانات تجريبية")
        intro_title.setStyleSheet(f"color: {COLORS['ACCENT']}; font-size: 16px; font-weight: bold;")
        intro_hint = QLabel("جرّب ملفًا اصطناعيًا، راجع النص، ثم افحصه. راجع التصنيف والتظليل واستخدم «تحقق». صيغ التصدير تتضمن النص المعالج وملخصًا دون القيم الأصلية المكتشفة.")
        intro_hint.setWordWrap(True)
        intro_hint.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']};")
        intro_copy.addWidget(intro_title)
        intro_copy.addWidget(intro_hint)
        intro_layout.addLayout(intro_copy, stretch=1)
        self.btn_demo_sample = AnimatedButton("تجربة عينة آمنة")
        self.btn_demo_sample.clicked.connect(self.load_demo_sample)
        intro_layout.addWidget(self.btn_demo_sample)
        layout.addWidget(intro)
        
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

        self.results_hint = QLabel("بعد الفحص: راجع التظليل والشارات واضغط «تحقق». كل صيغ التصدير تتضمن النص المعالج وملخص النتائج دون القيم الأصلية المكتشفة.")
        self.results_hint.setWordWrap(True)
        self.results_hint.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; padding: 4px;")
        output_layout.addWidget(self.results_hint)
        
        self.badges_layout = QHBoxLayout()
        self.badges_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        output_layout.addLayout(self.badges_layout)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        
        self.btn_copy = AnimatedButton("نسخ (Copy)")
        self.btn_copy.clicked.connect(self.on_copy)
        self.btn_copy.setEnabled(False)
        self.btn_export = AnimatedButton("تصدير (Export)", primary=True)
        self.btn_export.clicked.connect(self.on_export)
        self.btn_export.setEnabled(False)
        self.btn_verify = AnimatedButton("تحقق (Verify)")
        self.btn_verify.clicked.connect(self.on_verify)
        self.btn_review = AnimatedButton("مراجعة الكيانات")
        self.btn_review.setEnabled(False)
        self.btn_review.clicked.connect(self.on_review_entities)
        
        # Init sync scrolling state
        self._toggle_sync_scroll()
        
        out_btn_layout = QHBoxLayout()
        out_btn_layout.addStretch()
        out_btn_layout.addWidget(self.btn_review)
        out_btn_layout.addWidget(self.btn_verify)
        out_btn_layout.addWidget(self.btn_copy)
        out_btn_layout.addWidget(self.btn_export)
        output_layout.addLayout(out_btn_layout)
        
        self.splitter.addWidget(input_panel)
        self.splitter.addWidget(output_panel)
        self.splitter.setSizes([600, 600])
        
        layout.addWidget(self.splitter)
        return page

    def load_demo_sample(self):
        """Generate and load an explicitly synthetic sample in a supported format."""
        from PyQt6.QtWidgets import QInputDialog
        formats = ["TXT - نص", "CSV - جدول", "PDF - مستند", "DOCX - مستند Word", "XLSX - جدول Excel"]
        selected, accepted = QInputDialog.getItem(
            self, "عينة تدريبية آمنة", "اختر صيغة الملف:", formats, 0, False
        )
        if not accepted:
            return

        import csv
        import os
        import tempfile
        sample_dir = os.path.join(tempfile.gettempdir(), "AlgPIIEngine-DemoSamples")
        os.makedirs(sample_dir, exist_ok=True)
        stem = "synthetic_pii_demo"
        rows = [
            ("الحقل", "القيمة التجريبية"),
            ("الاسم", "أحمد بن سالم (اسم افتراضي)"),
            ("البريد", "demo.person@example.com"),
            ("الهاتف", "0551234567"),
            ("رقم تعريف تجريبي", "123456789012345678"),
            ("تنبيه", "بيانات اصطناعية للاختبار فقط؛ لا تخص أشخاصاً حقيقيين."),
        ]
        path = os.path.join(sample_dir, stem)
        try:
            if selected.startswith("TXT"):
                path += ".txt"
                with open(path, "w", encoding="utf-8") as sample_file:
                    sample_file.write("سجل تجريبي - بيانات اصطناعية للاختبار فقط\n")
                    sample_file.write("\n".join(f"{key}: {value}" for key, value in rows[1:]))
            elif selected.startswith("CSV"):
                path += ".csv"
                with open(path, "w", encoding="utf-8-sig", newline="") as sample_file:
                    csv.writer(sample_file).writerows(rows)
            elif selected.startswith("PDF"):
                import fitz
                path += ".pdf"
                document = fitz.open()
                page = document.new_page()
                page.insert_text((48, 60), "Synthetic PII Demo - TEST DATA ONLY", fontsize=14)
                pdf_rows = [
                    ("Name", "Ahmed Ben Salem (synthetic)"),
                    ("Email", "demo.person@example.com"),
                    ("Phone", "0551234567"),
                    ("Test ID", "123456789012345678"),
                    ("Notice", "Synthetic values for testing only."),
                ]
                for index, (key, value) in enumerate(pdf_rows, start=1):
                    page.insert_text((48, 90 + index * 24), f"{key}: {value}", fontsize=11)
                document.save(path)
                document.close()
            elif selected.startswith("DOCX"):
                from docx import Document
                path += ".docx"
                document = Document()
                document.add_heading("عينة اصطناعية للاختبار فقط", level=1)
                for key, value in rows[1:]:
                    document.add_paragraph(f"{key}: {value}")
                document.save(path)
            else:
                from openpyxl import Workbook
                path += ".xlsx"
                workbook = Workbook()
                sheet = workbook.active
                sheet.title = "بيانات تجريبية"
                for row in rows:
                    sheet.append(row)
                workbook.save(path)
            if not self._handle_file_drop(path):
                return
            self.results_hint.setText("عينة اصطناعية: راجع النص المستخرج ثم افحصه. استخدم «تحقق» لمراجعة التمويه، ثم صدّر النص المعالج وملخص النتائج.")
        except Exception as exc:
            QMessageBox.warning(self, "تعذر إنشاء العينة", f"لم نتمكن من إنشاء ملف العينة بهذه الصيغة:\n{exc}")

    def _switch_page(self, index: int):
        for i, btn in enumerate(self.nav_btns):
            if i != index:
                btn.setChecked(False)
        if getattr(self, "_page_animation", None):
            self._page_animation.stop()
        previous = self.content_stack.currentWidget()
        if previous and previous.graphicsEffect() is getattr(self, "_page_effect", None):
            previous.setGraphicsEffect(None)
        self.content_stack.setCurrentIndex(index)
        current = self.content_stack.currentWidget()
        self._page_effect = QGraphicsOpacityEffect(current)
        current.setGraphicsEffect(self._page_effect)
        self._page_animation = QPropertyAnimation(self._page_effect, b"opacity", self)
        self._page_animation.setDuration(180)
        self._page_animation.setStartValue(0.72)
        self._page_animation.setEndValue(1.0)
        self._page_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._page_animation.start()

        if index == 1:
            self.dashboard_page.refresh_data()

    def _check_engine_status(self):
        if self.nlp_enabled:
            self.engine_capability_lbl.setText("الكشف: تحميل نموذج NLP | OCR: حسب التثبيت")
            QTimer.singleShot(100, self._load_nlp)
        else:
            self.engine_capability_lbl.setText("الكشف: قواعد محلية فقط | OCR: حسب التثبيت")
            self.status_ind.set_state('ready')
            self.status_lbl.setText("جاهز - وضع التعابير النمطية فقط (Regex Only Mode)")
            self.db.log_audit(self.username, "ENGINE_STATUS", "NLP disabled, Regex only mode.")
            
    def _load_nlp(self):
        self.status_ind.set_state('loading')
        self.status_lbl.setText("تحميل النموذج المحلي في الخلفية... (Loading local model...)")
        self.btn_scan.setEnabled(False)
        self.nlp_worker = NLPModelLoadWorker(self.engine, self.model_path, self)
        self.nlp_worker.load_finished.connect(self._on_nlp_loaded)
        self.nlp_worker.start()

    def _on_nlp_loaded(self, success: bool):
        self.btn_scan.setEnabled(True)
        if success:
            self.engine_capability_lbl.setText("الكشف: القواعد + NLP المحلي | OCR: حسب التثبيت")
            self.status_ind.set_state('ready')
            self.status_lbl.setText("النموذج المحلي جاهز (Local model ready)")
            self.db.log_audit(self.username, "ENGINE_STATUS", "NLP Model loaded successfully.")
        else:
            self.engine_capability_lbl.setText("الكشف: قواعد محلية فقط | NLP غير متاح | OCR: حسب التثبيت")
            self.status_ind.set_state('ready')
            self.status_lbl.setText("النموذج غير متاح؛ يعمل الفحص بالتعابير المحلية (Regex mode)")
            self.db.log_audit(self.username, "ENGINE_STATUS", "Local NLP model unavailable; regex detection remains active.")

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
            self._clear_previous_result()
            self.status_lbl.setText(f"تم تحميل الملف: {os.path.basename(file_path)}")
            detector = "القواعد + NLP المحلي" if self.engine.use_nlp and self.engine.is_nlp_available() else "القواعد المحلية فقط"
            ocr = "استُخدم" if self._last_ocr_used else "لم يُستخدم"
            self.engine_capability_lbl.setText(f"الكشف: {detector} | OCR: {ocr}")
            extension = os.path.splitext(file_path)[1].lower() or "unknown"
            self.db.log_audit(self.username, "FILE_LOAD", f"Loaded a document for scanning (format: {extension}). Local path omitted for privacy.")
            return True
        except Exception as e:
            QMessageBox.warning(self, "خطأ (Error)", f"لا يمكن قراءة الملف: {e}")
            return False

    def _clear_previous_result(self):
        self.output_text.clear()
        for i in reversed(range(self.badges_layout.count())):
            item = self.badges_layout.takeAt(i)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self._last_anon_result = None
        self._verification_passed = False
        self._verification_target = None
        self._last_report = None
        self._last_scan_id = None
        self._review_original_entities = []
        self._review_manual_entities = []
        self.btn_review.setEnabled(False)
        self.results_hint.setText("بعد الفحص: راجع التظليل والشارات واضغط «تحقق». كل صيغ التصدير تتضمن النص المعالج وملخص النتائج دون القيم الأصلية المكتشفة.")

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
        
        self.batch_worker = BatchWorker(
            input_dir,
            output_dir,
            self.engine,
            batch_strategy,
            self.db,
            self.user_department,
            user_role=self.user_role,
        )
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
        failures = getattr(self.batch_worker, "failure_details", [])
        summary = f"تم فحص {total_processed} ملف(ات) بنجاح."
        if total_processed:
            summary += (
                "\nلكل ملف ناجح: أُنشئ ملف ‎.anonymized.txt يحتوي النص المستخرج بعد تمويه الكيانات التي اكتشفها المحرك، "
                "وملف ‎.report.pdf منفصل لملخص الفحص."
            )
        summary += f"\nبيان النتائج التفصيلي: {os.path.join(self.batch_worker.output_dir, 'batch_manifest.json')}"
        if any(item.get("anonymized_original_format") for item in getattr(self.batch_worker, "file_results", [])):
            summary += (
                "\nأُنشئت نسخ بصيغتها الأصلية للملفات المدعومة (PDF وDOCX وXLSX وCSV والصور). "
                "راجع بيان النتائج batch_manifest.json لمعرفة حدود التنقيح الخاصة بكل ملف، وافحص النسخ يدويًا قبل مشاركتها."
            )
        review_details = getattr(self.batch_worker, "review_details", [])
        if review_details:
            summary += "\n\nتحذير: التحقق من بعض النسخ الأصلية يحتاج مراجعة:"
            summary += "\n" + "\n".join(
                f"• {name}: بقيت {leaked} قيمة مكتشفة أصلًا، وظهرت {candidates} نتيجة محتملة."
                for name, leaked, candidates in review_details[:5]
            )
            if len(review_details) > 5:
                summary += f"\n... و{len(review_details) - 5} ملفات أخرى."
        if failures:
            summary += f"\nتعذر فحص {len(failures)} ملف(ات):"
            summary += "\n" + "\n".join(f"• {name}: {reason}" for name, reason in failures[:5])
            if len(failures) > 5:
                summary += f"\n... و{len(failures) - 5} ملفات أخرى."
        self.db.log_audit(
            self.username,
            "BATCH_SCAN_END",
            f"Finished batch scan: {total_processed} succeeded, {len(failures)} failed.",
        )
        if getattr(self, "progress_dlg", None):
            self.progress_dlg.close()
        from .batch_results_dialog import BatchResultsDialog
        results_dialog = BatchResultsDialog(
            self.batch_worker.output_dir,
            total_processed,
            failures,
            review_details,
            getattr(self.batch_worker, "file_results", []),
            summary,
            self,
        )
        results_dialog.exec()

    def _on_scan_finished(self):
        self.btn_scan.set_loading(False)
        self.status_ind.set_state('ready')

    def on_scan_complete(self, result: AnonymizedResult):
        self._last_anon_result = result
        self._verification_passed = False
        self._verification_target = None
        self.btn_copy.setEnabled(False)
        self.btn_export.setEnabled(False)
        self._review_original_entities = list(result.entities)
        self._review_manual_entities = []
        self.btn_review.setEnabled(True)
        self.output_text.setHtml(result.html_highlighted)
        self.status_lbl.setText("اكتمل الفحص (Scan Complete)")
        self.results_hint.setText("راجع التصنيف والشارات والنص المظلل، ثم شغّل «تحقق». صيغ التصدير تحتوي النص المعالج وملخص النتائج ولا تتضمن القيم الأصلية المكتشفة.")
        
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
        lbl_badge.label.setText("التصنيف: " + report.sensitivity_label)
        lbl_badge.setStyleSheet(f"background-color: {label_color}; color: white; border-radius: 12px;")
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
        if self.user_role == "admin":
            duplicates = self.fingerprint_engine.find_duplicates(fp)
        elif self.user_department:
            duplicates = self.fingerprint_engine.find_duplicates(fp, department=self.user_department)
        else:
            duplicates = []
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
        # Keep every completed scan in history, including clean results.
        last_id = self.db.log_scan(
            "User_Input", len(result.entities), report.risk_level, self.strategy,
            counts, report.sensitivity_label, ocr_used, duplicates_found, self.user_department
        )
        self._last_scan_id = last_id
        self.fingerprint_engine.store_fingerprint(last_id, "User_Input", fp)
        
        if result.entities or duplicates_found > 0:
            # Log clusters
            for cluster in report.clusters:
                self.db.save_cluster(last_id, cluster['reason'], cluster['multiplier'], ",".join(cluster['types']))
                
            # Cross-document Entity Indexing
            # Determine document name if available
            doc_name = "User_Input"
            if hasattr(self, '_last_file_path') and self._last_file_path:
                doc_name = self._last_file_path.split('/')[-1]
            self.cross_linker.index_scan_result(
                last_id, doc_name, result.entities, department=self.user_department
            )
                
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

    def on_review_entities(self):
        if not self._last_anon_result:
            QMessageBox.warning(self, "لا توجد نتيجة", "أجرِ فحصًا قبل مراجعة الكيانات.")
            return

        from .review_dialog import EntityReviewDialog
        result = self._last_anon_result
        automatic_entities = list(getattr(self, "_review_original_entities", result.entities))
        manual_entities = list(getattr(self, "_review_manual_entities", []))
        dialog_entities = automatic_entities + manual_entities
        dialog = EntityReviewDialog(
            result.original_text, dialog_entities, self, selected_entities=result.entities
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        reviewed_entities = dialog.reviewed_entities()
        self._verification_passed = False
        self._verification_target = None
        self.btn_copy.setEnabled(False)
        self.btn_export.setEnabled(False)
        self._review_manual_entities = [
            entity for entity in dialog.all_entities() if entity.source == "manual_review"
        ]
        updated_scan = replace(result.scan_result, entities=reviewed_entities)
        result.entities = reviewed_entities
        result.scan_result = updated_scan
        result.anonymized_text, result.html_highlighted = self.engine.anonymizer.anonymize(
            result.original_text, reviewed_entities, result.strategy
        )
        self._last_report = self.engine.generate_report(updated_scan)
        self.output_text.setHtml(result.html_highlighted)

        counts = {}
        for entity in reviewed_entities:
            counts[entity.entity_type] = counts.get(entity.entity_type, 0) + 1
        self._refresh_review_badges(self._last_report, counts)

        excluded = len(automatic_entities) - sum(
            1 for entity in reviewed_entities if entity.source != "manual_review"
        )
        added = sum(1 for entity in reviewed_entities if entity.source == "manual_review")
        if self._last_scan_id:
            self.db.update_scan_review(
                self._last_scan_id,
                len(reviewed_entities),
                self._last_report.risk_level,
                counts,
                self._last_report.sensitivity_label,
            )
            self.db.clear_indexed_entities_for_scan(self._last_scan_id)
            document_name = os.path.basename(self._last_file_path) if self._last_file_path else "User_Input"
            self.cross_linker.index_scan_result(
                self._last_scan_id, document_name, reviewed_entities, department=self.user_department
            )
            self.db.clear_clusters_for_scan(self._last_scan_id)
            for cluster in self._last_report.clusters:
                self.db.save_cluster(
                    self._last_scan_id, cluster['reason'], cluster['multiplier'], ",".join(cluster['types'])
                )
            self.db.log_audit(
                self.username,
                "SCAN_REVIEW",
                f"Reviewed scan {self._last_scan_id}: {excluded} detections excluded, {added} manual matches retained, {len(reviewed_entities)} entities retained.",
            )

        self.results_hint.setText(
            f"تم تحديث النتيجة بعد المراجعة: استُبعد {excluded} من النتائج الآلية وأُضيف {added} تطابق يدوي. "
            "النص المستبعد من الإخفاء سيبقى كما هو. سجل السياسات والحوادث يحتفظ بنتيجة الكشف الأصلية لأغراض التدقيق. راجع النتيجة ثم اضغط «تحقق» قبل التصدير."
        )
        self.status_lbl.setText("تم تطبيق المراجعة اليدوية.")

    def _refresh_review_badges(self, report, counts):
        for i in reversed(range(self.badges_layout.count())):
            item = self.badges_layout.takeAt(i)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        label_color = next(
            (policy['label_color'] for policy in self.labeling_policies if policy['label_name'] == report.sensitivity_label),
            COLORS['ACCENT'],
        )
        label_badge = EntityBadge("التصنيف: " + report.sensitivity_label, 0)
        label_badge.label.setText("التصنيف: " + report.sensitivity_label)
        label_badge.setStyleSheet(f"background-color: {label_color}; color: white; border-radius: 12px;")
        self.badges_layout.addWidget(label_badge)

        for entity_type, count in counts.items():
            self.badges_layout.addWidget(EntityBadge(entity_type, count))
        if report.clusters:
            self.badges_layout.addWidget(EntityBadge("عناقيد البيانات", len(report.clusters)))
        self.badges_layout.addStretch()

    def on_clear(self):
        self.input_text.clear()
        self._clear_previous_result()
        self._last_file_path = None
        self._last_ocr_used = False
        self.status_lbl.setText("تم مسح النص والنتيجة.")

    def on_copy(self):
        if not self._verification_passed:
            QMessageBox.warning(self, "التحقق مطلوب", "شغّل التحقق وانتظر نجاحه قبل نسخ النص المعالج.")
            return
        QApplication.clipboard().setText(self.output_text.toPlainText())
        self.status_lbl.setText("تم النسخ إلى الحافظة (Copied to Clipboard)")

    def on_export(self):
        if not hasattr(self, '_last_anon_result') or not self._last_anon_result:
            QMessageBox.warning(self, "تنبيه", "لا توجد نتائج للتصدير. يرجى الفحص أولاً.")
            return
        if not self._verification_passed:
            QMessageBox.warning(self, "التحقق مطلوب", "لا يمكن التصدير قبل نجاح التحقق من النص المعالج.")
            return
            
        formats = "PDF Report (*.pdf);;Word Document (*.docx);;Excel Spreadsheet (*.xlsx);;JSON Format (*.json);;XML Format (*.xml);;CSV Format (*.csv);;Text Files (*.txt)"
        path, _ = QFileDialog.getSaveFileName(self, "حفظ (Save)", "", formats)
        if path:
            try:
                from engine.exporters import ReportExporter
                if path.lower().endswith('.pdf'):
                    PDFExporter.export_report(self._last_anon_result, self._last_report, path)
                elif path.lower().endswith('.docx'):
                    ReportExporter.save_docx(self._last_anon_result.scan_result, self._last_report, path, self._last_anon_result.anonymized_text)
                elif path.lower().endswith('.xlsx'):
                    ReportExporter.save_xlsx(self._last_anon_result.scan_result, path, self._last_report, self._last_anon_result.anonymized_text)
                elif path.lower().endswith('.json'):
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(ReportExporter.to_json(self._last_anon_result.scan_result, self._last_report, self._last_anon_result.anonymized_text))
                elif path.lower().endswith('.xml'):
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(ReportExporter.to_xml(self._last_anon_result.scan_result, self._last_report, self._last_anon_result.anonymized_text))
                elif path.lower().endswith('.csv'):
                    with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                        f.write(ReportExporter.to_csv(self._last_anon_result.scan_result, self._last_report, self._last_anon_result.anonymized_text))
                else:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(self._last_anon_result.anonymized_text)
                QMessageBox.information(self, "نجاح", f"تم التصدير بنجاح إلى:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "خطأ", f"فشل التصدير:\n{str(e)}")

    def on_verify(self):
        if not hasattr(self, '_last_anon_result') or not self._last_anon_result:
            QMessageBox.warning(self, "تنبيه", "لا توجد نتائج للتحقق. يرجى الفحص أولاً.")
            return

        if getattr(self, "verification_worker", None) and self.verification_worker.isRunning():
            return
        current = self._last_anon_result
        self._verification_target = current
        self.status_ind.set_state('loading')
        self.status_lbl.setText("يعيد التحقق من النص المنقح بحثًا عن بيانات محتملة...")
        self.btn_verify.setEnabled(False)
        self.btn_scan.setEnabled(False)
        self.btn_export.setEnabled(False)
        self.btn_review.setEnabled(False)
        self.verification_worker = VerificationWorker(
            current.scan_result, current.anonymized_text, self.engine, self
        )
        self.verification_worker.verification_ready.connect(self._on_verification_ready)
        self.verification_worker.error.connect(self._on_verification_error)
        self.verification_worker.start()

    def _on_verification_ready(self, result):
        self.status_ind.set_state('ready')
        self.btn_verify.setEnabled(True)
        self.btn_scan.setEnabled(True)
        has_result = bool(self._last_anon_result)
        self._verification_passed = bool(
            result.is_successful and self._last_anon_result is self._verification_target
        )
        self.btn_export.setEnabled(has_result and self._verification_passed)
        self.btn_copy.setEnabled(has_result and self._verification_passed)
        self.btn_review.setEnabled(has_result)
        if self._last_anon_result is not self._verification_target:
            self.status_lbl.setText("تغيرت النتيجة أثناء التحقق؛ شغّل التحقق مجددًا.")
            return
        if result.is_successful:
            QMessageBox.information(
                self,
                "اكتمل التحقق",
                f"نسبة إخفاء الكيانات الأصلية: {result.masking_percentage:.1f}%\n{result.details}",
            )
            self.status_lbl.setText("انتهى التحقق؛ لم يعثر الفحص الثاني على كيانات إضافية.")
            return

        details = [
            f"نسبة إخفاء الكيانات الأصلية: {result.masking_percentage:.1f}%",
            result.details,
        ]
        if result.leaked_entities:
            details.append("قيم مكتشفة أصلًا بقيت كما هي: " + ", ".join(e.text for e in result.leaked_entities))
        if result.residual_entities:
            candidates = ", ".join(
                f"{entity.entity_type}: {entity.text}" for entity in result.residual_entities[:10]
            )
            details.append("كيانات محتملة في النص المنقح: " + candidates)
            details.append("راجعها يدويًا؛ قد تكون بعض النتائج إنذارات خاطئة.")
        QMessageBox.warning(self, "التحقق يحتاج مراجعة", "\n\n".join(details))
        self.status_lbl.setText("عثر التحقق الثاني على عناصر محتملة؛ راجعها قبل التصدير.")

    def _on_verification_error(self, message: str):
        self.status_ind.set_state('ready')
        self.btn_verify.setEnabled(True)
        self.btn_scan.setEnabled(True)
        has_result = bool(self._last_anon_result)
        self._verification_passed = False
        self._verification_target = None
        self.btn_export.setEnabled(False)
        self.btn_copy.setEnabled(False)
        self.btn_review.setEnabled(has_result)
        QMessageBox.critical(self, "تعذر التحقق", f"فشل فحص النص المنقح:\n{message}")
        self.status_lbl.setText("تعذر إكمال التحقق.")

    def on_settings(self):
        if self.user_role != "admin":
            QMessageBox.warning(self, "مرفوض", "فقط المشرف يمكنه الدخول للإعدادات.")
            return
            
        dlg = SettingsDialog(self.db, self.user_role, self)
        dlg.settings_changed.connect(self._apply_settings)
        dlg.exec()
        if getattr(dlg, "restore_staged", False):
            self.force_quit()
        
    def _apply_settings(self, settings: dict):
        if "session_idle_minutes" in settings:
            self.session_activity_monitor.set_timeout(settings["session_idle_minutes"])
        self.nlp_enabled = settings.get('nlp_enabled', False)
        self.model_path = settings.get('model_path', None)
        self.strategy = settings.get('anonymization_strategy', 'legal_mask')
        self.ocr_enabled = settings.get('ocr_enabled', True)
        self.ocr_language = settings.get('ocr_language', 'ara+eng')
        self.tesseract_cmd = settings.get('tesseract_cmd', '')
        DocumentParser.configure_ocr(self.ocr_enabled, self.ocr_language, self.tesseract_cmd)
        
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
