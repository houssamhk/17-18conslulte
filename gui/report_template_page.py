"""
Alg-PII Engine - Custom Report Template Builder (Feature #17)
Allows administrators to design and manage custom compliance report templates,
specifying included sections, default template settings, and report layouts.
"""

import json
import logging
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QCheckBox, QPushButton, QListWidget, QListWidgetItem,
    QMessageBox, QFrame, QSplitter, QGroupBox, QScrollArea
)
from PyQt6.QtCore import Qt
import qtawesome as qta
from storage.secure_db import SecureDatabase
from .theme import COLORS
from .widgets import AnimatedButton

logger = logging.getLogger(__name__)


class ReportTemplatePageWidget(QWidget):
    """
    Custom Report Template Builder Widget.
    Provides an interface to view, create, edit, and manage custom report templates.
    """

    SECTIONS_CONFIG = [
        {
            "key": "Header",
            "title_ar": "الترويسة وعنوان التقرير",
            "title_en": "Header & Organization Logo",
            "desc": "تضمين الترويسة الرسمية، التاريخ، وشعار المؤسسة",
            "icon": "fa5s.heading",
            "default": True
        },
        {
            "key": "Entity Table",
            "title_ar": "جدول الكيانات والبيانات الحساسة",
            "title_en": "Entity Table",
            "desc": "جدول مفصل لأنواع البيانات الشخصية المكتشفة وتوزيعها الإحصائي",
            "icon": "fa5s.table",
            "default": True
        },
        {
            "key": "Risk Summary",
            "title_ar": "ملخص تقييم المخاطر",
            "title_en": "Risk Summary",
            "desc": "مستوى الخطر الإجمالي ومقاييس حساسية البيانات المكتشفة",
            "icon": "fa5s.shield-alt",
            "default": True
        },
        {
            "key": "Legal References",
            "title_ar": "المراجع القانونية (قانون 18-07)",
            "title_en": "Legal References",
            "desc": "المواد القانونية المطبقة والأحكام التنظيمية ذات الصلة",
            "icon": "fa5s.balance-scale",
            "default": True
        },
        {
            "key": "Signature Block",
            "title_ar": "خانة التوقيع والمصادقة الرسمية",
            "title_en": "Signature Block",
            "desc": "كتلة التوقيع والختم الرسمي لمسؤول حماية البيانات (DPO)",
            "icon": "fa5s.file-signature",
            "default": False
        },
    ]

    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self.section_checkboxes = {}
        self._init_ui()
        self.load_templates()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # 1. Page Header
        header_widget = self._create_header_widget()
        main_layout.addWidget(header_widget)

        # 2. Splitter for Left and Right Panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {COLORS['BG_BUTTON']};
                width: 2px;
            }}
            QSplitter::handle:hover {{
                background-color: {COLORS['ACCENT']};
            }}
        """)

        # Left Panel: Existing Templates List & Details
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)

        # Right Panel: Template Creation Form
        right_panel = self._create_right_panel()
        splitter.addWidget(right_panel)

        # Proportions: ~40% left, ~60% right
        splitter.setSizes([400, 600])
        main_layout.addWidget(splitter, stretch=1)

    def _create_header_widget(self) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 8)

        # Icon + Titles
        icon_lbl = QLabel()
        icon_lbl.setPixmap(qta.icon('fa5s.file-invoice', color=COLORS['ACCENT']).pixmap(32, 32))
        layout.addWidget(icon_lbl)

        title_vbox = QVBoxLayout()
        title_vbox.setSpacing(2)

        title_lbl = QLabel("منشئ قوالب التقارير المخصصة (Custom Report Template Builder)")
        title_lbl.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        title_vbox.addWidget(title_lbl)

        subtitle_lbl = QLabel("تخصيص بنية وهيكل تقارير الامتثال وقانون 18-07 وتحديد الأقسام المطلوبة (Customize compliance report sections & layout)")
        subtitle_lbl.setStyleSheet(f"font-size: 12px; color: {COLORS['TEXT_SECONDARY']};")
        title_vbox.addWidget(subtitle_lbl)

        layout.addLayout(title_vbox)
        layout.addStretch()

        return container

    def _create_left_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("leftPanelCard")
        panel.setStyleSheet(f"""
            QFrame#leftPanelCard {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 8px;
                padding: 14px;
            }}
        """)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Header of left panel
        header_layout = QHBoxLayout()
        icon_lbl = QLabel()
        icon_lbl.setPixmap(qta.icon('fa5s.layer-group', color=COLORS['ACCENT_PURPLE']).pixmap(20, 20))
        header_layout.addWidget(icon_lbl)

        title = QLabel("القوالب المحفوظة (Saved Templates)")
        title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        header_layout.addWidget(title)
        header_layout.addStretch()

        self.count_badge = QLabel("0")
        self.count_badge.setStyleSheet(f"""
            background-color: {COLORS['BG_BUTTON']};
            color: {COLORS['ACCENT']};
            font-size: 11px;
            font-weight: bold;
            padding: 3px 8px;
            border-radius: 10px;
        """)
        header_layout.addWidget(self.count_badge)

        refresh_btn = QPushButton()
        refresh_btn.setIcon(qta.icon('fa5s.sync-alt', color=COLORS['TEXT_SECONDARY']))
        refresh_btn.setToolTip("تحديث القائمة (Refresh Templates)")
        refresh_btn.setFixedSize(30, 30)
        refresh_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['BG_BUTTON']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['ACCENT_PURPLE']};
            }}
        """)
        refresh_btn.clicked.connect(self.load_templates)
        header_layout.addWidget(refresh_btn)

        layout.addLayout(header_layout)

        # List Widget
        self.templates_list = QListWidget()
        self.templates_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {COLORS['BG_MAIN']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 6px;
                color: {COLORS['TEXT_PRIMARY']};
                padding: 6px;
            }}
            QListWidget::item {{
                padding: 10px;
                border-radius: 6px;
                margin-bottom: 6px;
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['BG_BUTTON']};
            }}
            QListWidget::item:hover {{
                background-color: #1f2b4d;
                border-color: {COLORS['ACCENT_PURPLE']};
            }}
            QListWidget::item:selected {{
                background-color: {COLORS['ACCENT_PURPLE']};
                border: 1px solid {COLORS['ACCENT']};
                color: #ffffff;
            }}
        """)
        self.templates_list.itemSelectionChanged.connect(self._on_template_selected)
        layout.addWidget(self.templates_list, stretch=1)

        # Details / Preview of selected template
        self.details_box = QGroupBox("تفاصيل القالب المحدد (Selected Template Details)")
        self.details_box.setStyleSheet(f"""
            QGroupBox {{
                background-color: {COLORS['BG_MAIN']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 6px;
                margin-top: 10px;
                padding: 12px;
                font-weight: bold;
                color: {COLORS['TEXT_PRIMARY']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top right;
                padding: 0 6px;
                color: {COLORS['ACCENT']};
            }}
        """)
        details_layout = QVBoxLayout(self.details_box)
        details_layout.setContentsMargins(10, 14, 10, 10)
        details_layout.setSpacing(8)

        self.tpl_name_lbl = QLabel("لم يتم تحديد قالب (No template selected)")
        self.tpl_name_lbl.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {COLORS['TEXT_PRIMARY']};")
        self.tpl_name_lbl.setWordWrap(True)
        details_layout.addWidget(self.tpl_name_lbl)

        self.tpl_desc_lbl = QLabel("")
        self.tpl_desc_lbl.setStyleSheet(f"font-size: 11px; color: {COLORS['TEXT_SECONDARY']};")
        self.tpl_desc_lbl.setWordWrap(True)
        details_layout.addWidget(self.tpl_desc_lbl)

        self.tpl_sections_lbl = QLabel("")
        self.tpl_sections_lbl.setStyleSheet(f"font-size: 11px; color: {COLORS['ACCENT']};")
        self.tpl_sections_lbl.setWordWrap(True)
        details_layout.addWidget(self.tpl_sections_lbl)

        self.tpl_meta_lbl = QLabel("")
        self.tpl_meta_lbl.setStyleSheet(f"font-size: 10px; color: {COLORS['TEXT_SECONDARY']};")
        details_layout.addWidget(self.tpl_meta_lbl)

        # Action buttons for selected template
        btn_box = QHBoxLayout()
        btn_box.setSpacing(8)

        self.btn_load = QPushButton("تحميل (Load)")
        self.btn_load.setIcon(qta.icon('fa5s.edit', color='white'))
        self.btn_load.setToolTip("تحميل بيانات هذا القالب في النموذج لتعديله أو استنساخه")
        self.btn_load.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['BG_BUTTON']};
                color: white;
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['ACCENT_PURPLE']};
            }}
        """)
        self.btn_load.clicked.connect(self.on_load_template_to_form)
        self.btn_load.setEnabled(False)
        btn_box.addWidget(self.btn_load)

        self.btn_set_default = QPushButton("افتراضي (Set Default)")
        self.btn_set_default.setIcon(qta.icon('fa5s.star', color='#f39c12'))
        self.btn_set_default.setToolTip("تعيين هذا القالب كقالب افتراضي لعمليات التصدير")
        self.btn_set_default.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['BG_BUTTON']};
                color: white;
                border: 1px solid {COLORS['WARNING']};
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background-color: #8c6812;
            }}
        """)
        self.btn_set_default.clicked.connect(self.on_set_as_default)
        self.btn_set_default.setEnabled(False)
        btn_box.addWidget(self.btn_set_default)

        self.btn_delete = QPushButton("حذف (Delete)")
        self.btn_delete.setIcon(qta.icon('fa5s.trash-alt', color='white'))
        self.btn_delete.setToolTip("حذف القالب المحدد نهائياً")
        self.btn_delete.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['ERROR']};
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background-color: #d73a49;
            }}
        """)
        self.btn_delete.clicked.connect(self.on_delete_template)
        self.btn_delete.setEnabled(False)
        btn_box.addWidget(self.btn_delete)

        details_layout.addLayout(btn_box)
        layout.addWidget(self.details_box)

        return panel

    def _create_right_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("rightPanelCard")
        panel.setStyleSheet(f"""
            QFrame#rightPanelCard {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 8px;
                padding: 14px;
            }}
        """)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(14)

        # Header of right panel
        header_layout = QHBoxLayout()
        icon_lbl = QLabel()
        icon_lbl.setPixmap(qta.icon('fa5s.plus-circle', color=COLORS['ACCENT']).pixmap(20, 20))
        header_layout.addWidget(icon_lbl)

        form_title = QLabel("إنشاء قالب تقرير جديد (Create New Report Template)")
        form_title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        header_layout.addWidget(form_title)
        header_layout.addStretch()

        layout.addLayout(header_layout)

        # Scroll area for form content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        form_content = QWidget()
        form_layout = QVBoxLayout(form_content)
        form_layout.setContentsMargins(4, 4, 4, 4)
        form_layout.setSpacing(14)

        # Field 1: Name
        name_group = QVBoxLayout()
        name_group.setSpacing(4)
        name_lbl = QLabel("اسم القالب (Template Name) * :")
        name_lbl.setStyleSheet(f"font-weight: bold; color: {COLORS['TEXT_PRIMARY']}; font-size: 12px;")
        name_group.addWidget(name_lbl)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("مثال: تقرير الامتثال التنفيذي (e.g. Executive Compliance Report)")
        self.name_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['BG_MAIN']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 6px;
                padding: 8px 12px;
                color: {COLORS['TEXT_PRIMARY']};
                font-size: 13px;
            }}
            QLineEdit:focus {{
                border-color: {COLORS['ACCENT']};
            }}
        """)
        name_group.addWidget(self.name_input)
        form_layout.addLayout(name_group)

        # Field 2: Description
        desc_group = QVBoxLayout()
        desc_group.setSpacing(4)
        desc_lbl = QLabel("الوصف (Description) :")
        desc_lbl.setStyleSheet(f"font-weight: bold; color: {COLORS['TEXT_PRIMARY']}; font-size: 12px;")
        desc_group.addWidget(desc_lbl)

        self.desc_input = QLineEdit()
        self.desc_input.setPlaceholderText("وصف موجز لنطاق واستخدام هذا القالب (Brief description of template purpose)")
        self.desc_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['BG_MAIN']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 6px;
                padding: 8px 12px;
                color: {COLORS['TEXT_PRIMARY']};
                font-size: 13px;
            }}
            QLineEdit:focus {{
                border-color: {COLORS['ACCENT']};
            }}
        """)
        desc_group.addWidget(self.desc_input)
        form_layout.addLayout(desc_group)

        # Field 3: Sections Checkboxes Group
        sections_group = QGroupBox("أقسام التقرير المضمنة (Report Sections) *")
        sections_group.setStyleSheet(f"""
            QGroupBox {{
                background-color: {COLORS['BG_MAIN']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 6px;
                margin-top: 12px;
                padding: 12px;
                font-weight: bold;
                color: {COLORS['TEXT_PRIMARY']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top right;
                padding: 0 6px;
                color: {COLORS['ACCENT']};
            }}
        """)
        sections_vbox = QVBoxLayout(sections_group)
        sections_vbox.setContentsMargins(10, 16, 10, 10)
        sections_vbox.setSpacing(10)

        # Quick select buttons
        quick_select_layout = QHBoxLayout()
        quick_lbl = QLabel("تحديد سريع (Quick Select):")
        quick_lbl.setStyleSheet(f"font-size: 11px; color: {COLORS['TEXT_SECONDARY']};")
        quick_select_layout.addWidget(quick_lbl)

        btn_select_all = QPushButton("تحديد الكل (Select All)")
        btn_select_all.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {COLORS['ACCENT']};
                border: none;
                font-size: 11px;
                font-weight: bold;
                text-decoration: underline;
                padding: 2px 6px;
            }}
            QPushButton:hover {{
                color: #ff6b81;
            }}
        """)
        btn_select_all.clicked.connect(self._select_all_sections)
        quick_select_layout.addWidget(btn_select_all)

        btn_deselect_all = QPushButton("إلغاء التحديد (Deselect All)")
        btn_deselect_all.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {COLORS['TEXT_SECONDARY']};
                border: none;
                font-size: 11px;
                font-weight: bold;
                text-decoration: underline;
                padding: 2px 6px;
            }}
            QPushButton:hover {{
                color: {COLORS['TEXT_PRIMARY']};
            }}
        """)
        btn_deselect_all.clicked.connect(self._deselect_all_sections)
        quick_select_layout.addWidget(btn_deselect_all)
        quick_select_layout.addStretch()

        sections_vbox.addLayout(quick_select_layout)

        # Checkboxes for each section
        self.section_checkboxes = {}
        for sec in self.SECTIONS_CONFIG:
            cb_container = QFrame()
            cb_container.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['BG_PANEL']};
                    border: 1px solid {COLORS['BG_BUTTON']};
                    border-radius: 6px;
                    padding: 6px;
                }}
                QFrame:hover {{
                    border-color: {COLORS['ACCENT_PURPLE']};
                }}
            """)
            cb_layout = QHBoxLayout(cb_container)
            cb_layout.setContentsMargins(6, 4, 6, 4)

            icon_lbl = QLabel()
            icon_lbl.setPixmap(qta.icon(sec["icon"], color=COLORS['ACCENT']).pixmap(18, 18))
            cb_layout.addWidget(icon_lbl)

            cb = QCheckBox(f"{sec['title_ar']} ({sec['title_en']})")
            cb.setChecked(sec["default"])
            cb.setStyleSheet(f"""
                QCheckBox {{
                    font-weight: bold;
                    color: {COLORS['TEXT_PRIMARY']};
                    font-size: 12px;
                }}
            """)
            cb.stateChanged.connect(self._update_preview)
            self.section_checkboxes[sec["key"]] = cb
            cb_layout.addWidget(cb, stretch=1)

            # Subtitle / description
            sub_lbl = QLabel(sec["desc"])
            sub_lbl.setStyleSheet(f"font-size: 10px; color: {COLORS['TEXT_SECONDARY']};")
            cb_layout.addWidget(sub_lbl)

            sections_vbox.addWidget(cb_container)

        form_layout.addWidget(sections_group)

        # Field 4: Default Template Checkbox
        opt_group = QGroupBox("خيارات القالب (Template Options)")
        opt_group.setStyleSheet(f"""
            QGroupBox {{
                background-color: {COLORS['BG_MAIN']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 6px;
                margin-top: 10px;
                padding: 10px;
                font-weight: bold;
                color: {COLORS['TEXT_PRIMARY']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top right;
                padding: 0 6px;
                color: {COLORS['ACCENT']};
            }}
        """)
        opt_layout = QVBoxLayout(opt_group)
        opt_layout.setContentsMargins(10, 14, 10, 8)

        self.default_cb = QCheckBox("تعيين كقالب افتراضي لتقارير الامتثال (Default Template)")
        self.default_cb.setStyleSheet(f"""
            QCheckBox {{
                font-size: 12px;
                font-weight: bold;
                color: {COLORS['TEXT_PRIMARY']};
            }}
        """)
        opt_layout.addWidget(self.default_cb)

        default_hint = QLabel("عند تفعيل هذا الخيار، سيتم تطبيق هذا القالب تلقائياً عند تصدير تقارير الامتثال.")
        default_hint.setStyleSheet(f"font-size: 10px; color: {COLORS['TEXT_SECONDARY']};")
        opt_layout.addWidget(default_hint)

        form_layout.addWidget(opt_group)

        # Field 5: Structure Layout Preview
        preview_group = QGroupBox("معاينة هيكل التقرير (Report Layout Flow Preview)")
        preview_group.setStyleSheet(f"""
            QGroupBox {{
                background-color: {COLORS['BG_MAIN']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 6px;
                margin-top: 10px;
                padding: 10px;
                font-weight: bold;
                color: {COLORS['TEXT_PRIMARY']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top right;
                padding: 0 6px;
                color: {COLORS['ACCENT']};
            }}
        """)
        preview_layout = QVBoxLayout(preview_group)
        preview_layout.setContentsMargins(10, 14, 10, 10)

        self.preview_lbl = QLabel("")
        self.preview_lbl.setWordWrap(True)
        preview_layout.addWidget(self.preview_lbl)

        form_layout.addWidget(preview_group)

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        self.btn_save = AnimatedButton("حفظ القالب (Save Template)", primary=True)
        self.btn_save.setIcon(qta.icon('fa5s.save', color='white'))
        self.btn_save.setFixedHeight(40)
        self.btn_save.clicked.connect(self.on_save_template)
        btn_layout.addWidget(self.btn_save, stretch=2)

        self.btn_reset = AnimatedButton("إعادة تعيين (Reset)", primary=False)
        self.btn_reset.setIcon(qta.icon('fa5s.undo', color=COLORS['TEXT_PRIMARY']))
        self.btn_reset.setFixedHeight(40)
        self.btn_reset.clicked.connect(self.on_reset_form)
        btn_layout.addWidget(self.btn_reset, stretch=1)

        form_layout.addLayout(btn_layout)

        scroll.setWidget(form_content)
        layout.addWidget(scroll, stretch=1)

        # Initial preview update
        self._update_preview()

        return panel

    def _select_all_sections(self):
        for cb in self.section_checkboxes.values():
            cb.setChecked(True)
        self._update_preview()

    def _deselect_all_sections(self):
        for cb in self.section_checkboxes.values():
            cb.setChecked(False)
        self._update_preview()

    def _update_preview(self):
        sections = self.get_selected_sections()
        if not sections:
            self.preview_lbl.setText("⚠️ لم يتم تحديد أي قسم بعد. يرجى اختيار قسم واحد على الأقل لتضمينه في التقرير.")
            self.preview_lbl.setStyleSheet(f"""
                color: {COLORS['WARNING']};
                background-color: {COLORS['BG_PANEL']};
                border: 1px dashed {COLORS['WARNING']};
                border-radius: 6px;
                padding: 10px;
                font-size: 11px;
            """)
            return

        flow_items = []
        for i, key in enumerate(sections, 1):
            sec_meta = next((s for s in self.SECTIONS_CONFIG if s["key"] == key), None)
            name = sec_meta["title_ar"] if sec_meta else key
            flow_items.append(f"<span style='color:{COLORS['ACCENT']}; font-weight:bold;'>[{i}]</span> {name}")

        flow_html = "  ➔  ".join(flow_items)
        self.preview_lbl.setText(f"📄 <b>المستند:</b> {flow_html}")
        self.preview_lbl.setStyleSheet(f"""
            color: {COLORS['TEXT_PRIMARY']};
            background-color: {COLORS['BG_PANEL']};
            border: 1px solid {COLORS['ACCENT_PURPLE']};
            border-radius: 6px;
            padding: 10px;
            font-size: 12px;
            line-height: 18px;
        """)

    def get_selected_sections(self) -> list:
        """Returns ordered list of selected section keys."""
        selected = []
        for sec in self.SECTIONS_CONFIG:
            key = sec["key"]
            if self.section_checkboxes.get(key) and self.section_checkboxes[key].isChecked():
                selected.append(key)
        return selected

    def load_templates(self):
        """Loads all templates from the database and updates the left list widget."""
        self.templates_list.clear()
        self.details_box.setVisible(True)

        try:
            templates = self.db.get_report_templates()
        except Exception as e:
            logger.error(f"Error fetching report templates: {e}")
            templates = []

        # If database has no templates, auto-seed a comprehensive default template
        if not templates:
            try:
                default_sections = ["Header", "Entity Table", "Risk Summary", "Legal References", "Signature Block"]
                self.db.save_report_template(
                    "التقرير القياسي الشامل (Standard Comprehensive Report)",
                    "القالب الافتراضي المعتمد لكافة تقارير مطابقة قانون حماية البيانات 18-07",
                    json.dumps(default_sections),
                    "",
                    True,
                    "admin"
                )
                templates = self.db.get_report_templates()
            except Exception as e:
                logger.error(f"Failed to auto-seed default template: {e}")

        self.count_badge.setText(str(len(templates)))

        if not templates:
            placeholder_item = QListWidgetItem("لا توجد قوالب محفوظة حالياً (No templates saved)")
            placeholder_item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.templates_list.addItem(placeholder_item)
            self._clear_details()
            return

        for row in templates:
            # row: id, name, description, template_json, logo_path, is_default, created_by, created_at
            tpl_id = row[0]
            name = row[1]
            desc = row[2] or ""
            tpl_json = row[3] or "[]"
            logo_path = row[4] or ""
            is_default = bool(row[5])
            created_by = row[6] or "admin"
            created_at = str(row[7] or "")

            try:
                sections = json.loads(tpl_json)
            except Exception:
                sections = []

            tpl_data = {
                "id": tpl_id,
                "name": name,
                "description": desc,
                "template_json": tpl_json,
                "sections": sections,
                "logo_path": logo_path,
                "is_default": is_default,
                "created_by": created_by,
                "created_at": created_at
            }

            display_text = f"★ [افتراضي / Default] {name}" if is_default else f"📋 {name}"
            item = QListWidgetItem(display_text)
            if is_default:
                item.setIcon(qta.icon('fa5s.star', color='#f39c12'))
            else:
                item.setIcon(qta.icon('fa5s.file-alt', color=COLORS['TEXT_SECONDARY']))

            tooltip = f"الاسم: {name}\nالوصف: {desc}\nالأقسام: {len(sections)}\nتاريخ الإنشاء: {created_at}\nأنشئ بواسطة: {created_by}"
            item.setToolTip(tooltip)
            item.setData(Qt.ItemDataRole.UserRole, tpl_data)

            self.templates_list.addItem(item)

        # Select first item by default
        if self.templates_list.count() > 0:
            self.templates_list.setCurrentRow(0)

    def _on_template_selected(self):
        item = self.templates_list.currentItem()
        if not item:
            self._clear_details()
            return

        tpl = item.data(Qt.ItemDataRole.UserRole)
        if not tpl:
            self._clear_details()
            return

        is_def = tpl.get("is_default", False)
        def_tag = " <span style='color:#f39c12; font-weight:bold;'>[قالب افتراضي / Default]</span>" if is_def else ""
        self.tpl_name_lbl.setText(f"📄 <b>{tpl['name']}</b>{def_tag}")
        self.tpl_desc_lbl.setText(tpl.get("description") or "بدون وصف إضافي (No description)")

        sections = tpl.get("sections", [])
        sec_names = []
        for s in sections:
            meta = next((m for m in self.SECTIONS_CONFIG if m["key"] == s), None)
            sec_names.append(meta["title_ar"] if meta else s)

        if sec_names:
            self.tpl_sections_lbl.setText("الأقسام: " + " • ".join(sec_names))
        else:
            self.tpl_sections_lbl.setText("الأقسام: لا توجد أقسام محددة")

        meta_info = f"أنشئ بواسطة: {tpl.get('created_by', 'admin')} | التاريخ: {tpl.get('created_at', '')[:19]}"
        self.tpl_meta_lbl.setText(meta_info)

        self.btn_load.setEnabled(True)
        self.btn_delete.setEnabled(True)
        self.btn_set_default.setEnabled(not is_def)

    def _clear_details(self):
        self.tpl_name_lbl.setText("لم يتم تحديد قالب (No template selected)")
        self.tpl_desc_lbl.setText("")
        self.tpl_sections_lbl.setText("")
        self.tpl_meta_lbl.setText("")
        self.btn_load.setEnabled(False)
        self.btn_delete.setEnabled(False)
        self.btn_set_default.setEnabled(False)

    def on_load_template_to_form(self):
        """Loads selected template values into the right-hand creation form."""
        item = self.templates_list.currentItem()
        if not item:
            return

        tpl = item.data(Qt.ItemDataRole.UserRole)
        if not tpl:
            return

        self.name_input.setText(tpl.get("name", ""))
        self.desc_input.setText(tpl.get("description", ""))
        self.default_cb.setChecked(bool(tpl.get("is_default", False)))

        sections = tpl.get("sections", [])
        for key, cb in self.section_checkboxes.items():
            cb.setChecked(key in sections)

        self._update_preview()

    def on_set_as_default(self):
        """Sets the selected template as the default report template."""
        item = self.templates_list.currentItem()
        if not item:
            return

        tpl = item.data(Qt.ItemDataRole.UserRole)
        if not tpl:
            return

        tpl_id = tpl.get("id")
        tpl_name = tpl.get("name")

        try:
            c = self.db.conn.cursor()
            c.execute("UPDATE report_templates SET is_default=0")
            c.execute("UPDATE report_templates SET is_default=1 WHERE id=?", (tpl_id,))
            self.db.conn.commit()
            self.load_templates()
            QMessageBox.information(
                self,
                "تم التعيين (Default Updated)",
                f"تم تعيين القالب '{tpl_name}' كقالب افتراضي بنجاح."
            )
        except Exception as e:
            logger.error(f"Error setting template as default: {e}")
            QMessageBox.critical(self, "خطأ (Error)", f"فشل في تعيين القالب كافتراضي:\n{e}")

    def on_delete_template(self):
        """Deletes the selected template after user confirmation."""
        item = self.templates_list.currentItem()
        if not item:
            return

        tpl = item.data(Qt.ItemDataRole.UserRole)
        if not tpl:
            return

        tpl_id = tpl.get("id")
        tpl_name = tpl.get("name")

        reply = QMessageBox.question(
            self,
            "تأكيد الحذف (Confirm Delete)",
            f"هل أنت متأكد من رغبتك في حذف قالب التقرير التالي؟\n\n'{tpl_name}'\n\n(Are you sure you want to delete this template?)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.db.delete_report_template(tpl_id)
                self.load_templates()
                QMessageBox.information(self, "تم الحذف (Deleted)", f"تم حذف القالب '{tpl_name}' بنجاح.")
            except Exception as e:
                logger.error(f"Error deleting template: {e}")
                QMessageBox.critical(self, "خطأ (Error)", f"فشل في حذف القالب:\n{e}")

    def on_save_template(self):
        """Validates inputs and saves the new report template into the database."""
        name = self.name_input.text().strip()
        desc = self.desc_input.text().strip()
        sections = self.get_selected_sections()
        is_default = self.default_cb.isChecked()

        if not name:
            QMessageBox.warning(
                self,
                "تنبيه (Warning)",
                "يرجى إدخال اسم القالب قبل الحفظ.\n(Please enter a template name)."
            )
            self.name_input.setFocus()
            return

        if not sections:
            QMessageBox.warning(
                self,
                "تنبيه (Warning)",
                "يرجى تحديد قسم واحد على الأقل في القالب.\n(Please select at least one section)."
            )
            return

        try:
            sections_json = json.dumps(sections)
            self.db.save_report_template(name, desc, sections_json, "", is_default, "admin")
            QMessageBox.information(
                self,
                "نجاح الحفظ (Template Saved)",
                f"تم حفظ قالب التقرير بنجاح:\n\n{name}\n(Report template saved successfully)."
            )
            self.on_reset_form()
            self.load_templates()
        except Exception as e:
            logger.error(f"Error saving report template: {e}")
            QMessageBox.critical(
                self,
                "خطأ (Error)",
                f"فشل في حفظ قالب التقرير في قاعدة البيانات:\n{e}"
            )

    def on_reset_form(self):
        """Resets the form fields to their default states."""
        self.name_input.clear()
        self.desc_input.clear()
        self.default_cb.setChecked(False)

        for sec in self.SECTIONS_CONFIG:
            key = sec["key"]
            if key in self.section_checkboxes:
                self.section_checkboxes[key].setChecked(sec["default"])

        self._update_preview()
