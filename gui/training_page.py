import json
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QDialog, QRadioButton, QButtonGroup, QMessageBox,
    QTabWidget, QFrame, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
import qtawesome as qta

from storage.secure_db import SecureDatabase
from gui.theme import COLORS
from gui.widgets import AnimatedButton


class QuizDialog(QDialog):
    """Dialog displaying a single quiz question with options as radio buttons."""
    def __init__(self, quiz_data, parent=None):
        super().__init__(parent)
        
        # Unpack quiz_data (supports both dict and tuple/list)
        if isinstance(quiz_data, dict):
            self.quiz_id = quiz_data.get('id', 1)
            self.question_ar = quiz_data.get('question_ar', '')
            options_raw = quiz_data.get('options_json', '[]')
            self.correct_option = int(quiz_data.get('correct_option', 0))
            self.difficulty = quiz_data.get('difficulty', 'Easy')
            self.category = quiz_data.get('category', 'General')
        else:
            self.quiz_id = quiz_data[0]
            self.question_ar = quiz_data[1]
            options_raw = quiz_data[2]
            self.correct_option = int(quiz_data[3])
            self.difficulty = quiz_data[4] if len(quiz_data) > 4 else 'Easy'
            self.category = quiz_data[5] if len(quiz_data) > 5 else 'General'

        # Parse options from JSON or list
        if isinstance(options_raw, list):
            self.options = options_raw
        else:
            try:
                self.options = json.loads(options_raw)
            except Exception:
                self.options = []

        self.score = 0.0
        self.passed = False
        self.selected_option = -1

        self.setWindowTitle(f"امتحان تدريبي #{self.quiz_id} (Quiz #{self.quiz_id})")
        self.setMinimumWidth(550)
        self.setModal(True)
        self._init_ui()

    def _init_ui(self):
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['BG_MAIN']};
                color: {COLORS['TEXT_PRIMARY']};
            }}
            QLabel {{
                color: {COLORS['TEXT_PRIMARY']};
            }}
        """)
        
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(16)
        main_layout.setContentsMargins(24, 24, 24, 24)

        # Header with category and difficulty badges
        header_layout = QHBoxLayout()
        
        title_lbl = QLabel(f"امتحان الامتثال #{self.quiz_id} (Compliance Quiz)")
        title_lbl.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        header_layout.addWidget(title_lbl)
        
        header_layout.addStretch()
        
        cat_badge = QLabel(f"الفئة: {self.category}")
        cat_badge.setStyleSheet(f"""
            background-color: {COLORS['BG_PANEL']};
            color: {COLORS['TEXT_PRIMARY']};
            border: 1px solid {COLORS['ACCENT_PURPLE']};
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 11px;
            font-weight: bold;
        """)
        header_layout.addWidget(cat_badge)
        
        # Difficulty color coding
        diff_color = COLORS['SUCCESS']
        diff_lower = str(self.difficulty).lower()
        if 'medium' in diff_lower or 'متوسط' in diff_lower:
            diff_color = COLORS['WARNING']
        elif 'hard' in diff_lower or 'صعب' in diff_lower:
            diff_color = COLORS['ERROR']
            
        diff_badge = QLabel(f"المستوى: {self.difficulty}")
        diff_badge.setStyleSheet(f"""
            background-color: {diff_color};
            color: white;
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 11px;
            font-weight: bold;
        """)
        header_layout.addWidget(diff_badge)
        
        main_layout.addLayout(header_layout)

        # Question Box (Card Frame)
        q_frame = QFrame()
        q_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 8px;
                padding: 16px;
            }}
        """)
        q_layout = QVBoxLayout(q_frame)
        
        q_label = QLabel(self.question_ar)
        q_label.setWordWrap(True)
        q_label.setStyleSheet(f"""
            font-size: 15px;
            font-weight: bold;
            color: {COLORS['TEXT_PRIMARY']};
            line-height: 1.4;
            background: transparent;
            border: none;
        """)
        q_layout.addWidget(q_label)
        main_layout.addWidget(q_frame)

        # Options Container Frame
        options_frame = QFrame()
        options_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 8px;
                padding: 14px;
            }}
        """)
        options_layout = QVBoxLayout(options_frame)
        options_layout.setSpacing(10)
        
        opt_header = QLabel("اختر الإجابة الصحيحة (Select Correct Option):")
        opt_header.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 12px; font-weight: bold; background: transparent; border: none;")
        options_layout.addWidget(opt_header)

        self.button_group = QButtonGroup(self)
        self.button_group.setExclusive(True)

        for idx, option_text in enumerate(self.options):
            radio = QRadioButton(str(option_text))
            radio.setCursor(Qt.CursorShape.PointingHandCursor)
            radio.setStyleSheet(f"""
                QRadioButton {{
                    color: {COLORS['TEXT_PRIMARY']};
                    font-size: 13px;
                    padding: 8px 12px;
                    border: 1px solid {COLORS['BG_BUTTON']};
                    border-radius: 6px;
                    background-color: {COLORS['BG_MAIN']};
                }}
                QRadioButton:hover {{
                    border-color: {COLORS['ACCENT']};
                    background-color: {COLORS['BG_PANEL']};
                }}
                QRadioButton:checked {{
                    border: 2px solid {COLORS['ACCENT']};
                    background-color: {COLORS['BG_BUTTON']};
                    color: #ffffff;
                    font-weight: bold;
                }}
            """)
            self.button_group.addButton(radio, idx)
            options_layout.addWidget(radio)

        main_layout.addWidget(options_frame)

        # Action Buttons Layout
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        btn_layout.addStretch()

        self.submit_btn = AnimatedButton("إرسال الإجابة (Submit)", primary=True)
        self.submit_btn.setIcon(qta.icon("fa5s.check", color="white"))
        self.submit_btn.clicked.connect(self._on_submit)
        btn_layout.addWidget(self.submit_btn)

        self.cancel_btn = AnimatedButton("إلغاء (Cancel)")
        self.cancel_btn.setIcon(qta.icon("fa5s.times", color=COLORS['TEXT_PRIMARY']))
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.cancel_btn)

        main_layout.addLayout(btn_layout)

    def _on_submit(self):
        checked_id = self.button_group.checkedId()
        if checked_id == -1:
            QMessageBox.warning(
                self,
                "تنبيه (Warning)",
                "يرجى تحديد إجابة قبل إرسال الامتحان.\n(Please select an option before submitting.)"
            )
            return

        self.selected_option = checked_id
        if self.selected_option == self.correct_option:
            self.score = 100.0
            self.passed = True
        else:
            self.score = 0.0
            self.passed = False

        self.accept()


class ComprehensiveExamDialog(QDialog):
    """Dialog administering all training quizzes sequentially in a single scrollable form."""
    def __init__(self, quizzes, parent=None):
        super().__init__(parent)
        self.quizzes = quizzes
        self.score = 0.0
        self.passed = False
        self.button_groups = {}  # quiz_id -> QButtonGroup

        self.setWindowTitle("الامتحان الشامل في الامتثال (Comprehensive Compliance Exam)")
        self.setMinimumSize(680, 600)
        self.setModal(True)
        self._init_ui()

    def _init_ui(self):
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['BG_MAIN']};
                color: {COLORS['TEXT_PRIMARY']};
            }}
            QLabel {{
                color: {COLORS['TEXT_PRIMARY']};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header_lbl = QLabel(f"الامتحان الشامل ({len(self.quizzes)} أسئلة) - Comprehensive Compliance Exam")
        header_lbl.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['ACCENT']};")
        layout.addWidget(header_lbl)

        info_lbl = QLabel("أجب على جميع الأسئلة أدناه. درجة النجاح هي 80% أو أعلى (Answer all questions. Pass mark is 80%+).")
        info_lbl.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 12px;")
        layout.addWidget(info_lbl)

        # Scroll Area for Questions
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet(f"""
            QScrollArea {{
                background-color: transparent;
                border: 1px solid {COLORS['BG_PANEL']};
                border-radius: 6px;
            }}
        """)

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(16)

        for q_idx, quiz in enumerate(self.quizzes):
            quiz_id = quiz[0]
            question_text = quiz[1]
            options_raw = quiz[2]
            difficulty = quiz[4] if len(quiz) > 4 else 'Easy'
            category = quiz[5] if len(quiz) > 5 else 'General'

            if isinstance(options_raw, list):
                options = options_raw
            else:
                try:
                    options = json.loads(options_raw)
                except Exception:
                    options = []

            # Question Card
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['BG_PANEL']};
                    border: 1px solid {COLORS['ACCENT_PURPLE']};
                    border-radius: 8px;
                    padding: 12px;
                }}
            """)
            card_layout = QVBoxLayout(card)
            card_layout.setSpacing(8)

            q_title = QLabel(f"السؤال {q_idx + 1}: {question_text}")
            q_title.setWordWrap(True)
            q_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']}; background: transparent; border: none;")
            card_layout.addWidget(q_title)

            meta_lbl = QLabel(f"الفئة: {category} | الصعوبة: {difficulty}")
            meta_lbl.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 11px; background: transparent; border: none;")
            card_layout.addWidget(meta_lbl)

            bg = QButtonGroup(self)
            bg.setExclusive(True)
            self.button_groups[quiz_id] = bg

            for opt_idx, opt_text in enumerate(options):
                rb = QRadioButton(str(opt_text))
                rb.setCursor(Qt.CursorShape.PointingHandCursor)
                rb.setStyleSheet(f"""
                    QRadioButton {{
                        color: {COLORS['TEXT_PRIMARY']};
                        font-size: 13px;
                        padding: 6px 10px;
                        border: 1px solid {COLORS['BG_BUTTON']};
                        border-radius: 4px;
                        background-color: {COLORS['BG_MAIN']};
                        margin: 2px 0px;
                    }}
                    QRadioButton:hover {{
                        border-color: {COLORS['ACCENT']};
                    }}
                    QRadioButton:checked {{
                        border: 2px solid {COLORS['ACCENT']};
                        background-color: {COLORS['BG_BUTTON']};
                        font-weight: bold;
                    }}
                """)
                bg.addButton(rb, opt_idx)
                card_layout.addWidget(rb)

            scroll_layout.addWidget(card)

        scroll_area.setWidget(scroll_content)
        layout.addWidget(scroll_area)

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.submit_btn = AnimatedButton("إرسال الامتحان الشامل (Submit Exam)", primary=True)
        self.submit_btn.setIcon(qta.icon("fa5s.check", color="white"))
        self.submit_btn.clicked.connect(self._on_submit)
        btn_layout.addWidget(self.submit_btn)

        self.cancel_btn = AnimatedButton("إلغاء (Cancel)")
        self.cancel_btn.setIcon(qta.icon("fa5s.times", color=COLORS['TEXT_PRIMARY']))
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.cancel_btn)

        layout.addLayout(btn_layout)

    def _on_submit(self):
        # Check all questions answered
        unanswered = []
        for q_idx, quiz in enumerate(self.quizzes):
            qid = quiz[0]
            if self.button_groups[qid].checkedId() == -1:
                unanswered.append(str(q_idx + 1))

        if unanswered:
            QMessageBox.warning(
                self,
                "تنبيه (Warning)",
                f"يرجى الإجابة على جميع الأسئلة قبل الإرسال.\n(الأسئلة المتبقية: {', '.join(unanswered)})\n"
                "Please answer all questions before submitting."
            )
            return

        correct_count = 0
        for quiz in self.quizzes:
            qid = quiz[0]
            correct_opt = int(quiz[3])
            if self.button_groups[qid].checkedId() == correct_opt:
                correct_count += 1

        total = len(self.quizzes)
        self.score = (correct_count / total * 100.0) if total > 0 else 0.0
        self.passed = bool(self.score >= 80.0)
        self.accept()


class TrainingPageWidget(QWidget):
    """Compliance Training Module Widget (Feature #32)."""
    def __init__(self, db: SecureDatabase, current_username: str = "admin", parent=None):
        super().__init__(parent)
        self.db = db
        self.current_username = current_username or "admin"
        self._quizzes_cache = []

        self._init_ui()
        self.load_quizzes()
        self.load_results()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # Page Header
        header_layout = QHBoxLayout()
        header_title_layout = QVBoxLayout()
        
        title = QLabel("وحدة التدريب على الامتثال (Compliance Training Module)")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        header_title_layout.addWidget(title)

        subtitle = QLabel("التدريب المستمر والتوعية بالقوانين والأنظمة لحماية البيانات (Law 18-07 & Law 18-05)")
        subtitle.setStyleSheet(f"font-size: 12px; color: {COLORS['TEXT_SECONDARY']};")
        header_title_layout.addWidget(subtitle)
        header_layout.addLayout(header_title_layout)

        header_layout.addStretch()

        user_badge = QLabel(f"المتدرب (Trainee): {self.current_username}")
        user_badge.setStyleSheet(f"""
            background-color: {COLORS['BG_PANEL']};
            color: {COLORS['ACCENT']};
            border: 1px solid {COLORS['ACCENT_PURPLE']};
            border-radius: 6px;
            padding: 6px 12px;
            font-weight: bold;
            font-size: 13px;
        """)
        header_layout.addWidget(user_badge)

        layout.addLayout(header_layout)

        # Main Tab Widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-radius: 6px;
                background-color: {COLORS['BG_MAIN']};
            }}
            QTabBar::tab {{
                background-color: {COLORS['BG_PANEL']};
                color: {COLORS['TEXT_PRIMARY']};
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                border: 1px solid {COLORS['BG_BUTTON']};
                margin-right: 4px;
                font-weight: bold;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['BG_BUTTON']};
                color: {COLORS['ACCENT']};
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                border-bottom: none;
            }}
        """)

        # Tab 1: "الامتحانات (Quizzes)"
        self.quizzes_tab = self._create_quizzes_tab()
        self.tabs.addTab(self.quizzes_tab, qta.icon("fa5s.graduation-cap", color=COLORS['TEXT_PRIMARY']), "الامتحانات (Quizzes)")

        # Tab 2: "النتائج (Results)"
        self.results_tab = self._create_results_tab()
        self.tabs.addTab(self.results_tab, qta.icon("fa5s.award", color=COLORS['TEXT_PRIMARY']), "النتائج (Results)")

        layout.addWidget(self.tabs)

    def _create_quizzes_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)

        # Toolbar
        toolbar = QHBoxLayout()
        section_title = QLabel("قائمة الامتحانات المتاحة (Available Compliance Quizzes)")
        section_title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        toolbar.addWidget(section_title)

        toolbar.addStretch()

        self.btn_start = AnimatedButton("ابدأ الامتحان (Start Quiz)", primary=True)
        self.btn_start.setIcon(qta.icon("fa5s.play", color="white"))
        self.btn_start.clicked.connect(self.on_start_quiz)
        toolbar.addWidget(self.btn_start)

        self.btn_comprehensive = AnimatedButton("امتحان شامل (Comprehensive Exam)")
        self.btn_comprehensive.setIcon(qta.icon("fa5s.clipboard-check", color=COLORS['TEXT_PRIMARY']))
        self.btn_comprehensive.clicked.connect(self.on_start_comprehensive)
        toolbar.addWidget(self.btn_comprehensive)

        self.btn_refresh_quizzes = AnimatedButton("تحديث (Refresh)")
        self.btn_refresh_quizzes.setIcon(qta.icon("fa5s.sync", color=COLORS['TEXT_PRIMARY']))
        self.btn_refresh_quizzes.clicked.connect(self.load_quizzes)
        toolbar.addWidget(self.btn_refresh_quizzes)

        layout.addLayout(toolbar)

        # Quizzes Table
        self.quizzes_table = QTableWidget(0, 5)
        self.quizzes_table.setHorizontalHeaderLabels([
            "المعرف (ID)",
            "الفئة (Category)",
            "الصعوبة (Difficulty)",
            "السؤال (Question)",
            "إجراء (Action)"
        ])
        self.quizzes_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.quizzes_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.quizzes_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.quizzes_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.quizzes_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

        self.quizzes_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.quizzes_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.quizzes_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.quizzes_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['BG_PANEL']};
                color: {COLORS['TEXT_PRIMARY']};
                gridline-color: {COLORS['BG_BUTTON']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 4px;
            }}
            QHeaderView::section {{
                background-color: {COLORS['BG_BUTTON']};
                color: {COLORS['ACCENT']};
                padding: 8px;
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                font-weight: bold;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['ACCENT_PURPLE']};
                color: white;
            }}
        """)
        self.quizzes_table.cellDoubleClicked.connect(self.on_quiz_cell_double_clicked)
        layout.addWidget(self.quizzes_table)

        # Help hint
        hint_lbl = QLabel("💡 تلميح: حدد امتحاناً واضغط 'ابدأ الامتحان' أو انقر مرتين على أي سؤال لبدء الاختبار.")
        hint_lbl.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 11px;")
        layout.addWidget(hint_lbl)

        return tab

    def _create_results_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)

        # Top Bar with Stats Summary
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)

        self.card_total = self._create_stat_card("إجمالي المحاولات (Total Attempts)", "0", COLORS['ACCENT_PURPLE'])
        self.card_passed = self._create_stat_card("الامتحانات المجتازة (Passed)", "0", COLORS['SUCCESS'])
        self.card_rate = self._create_stat_card("نسبة النجاح (Pass Rate)", "0.0%", COLORS['WARNING'])

        stats_layout.addWidget(self.card_total)
        stats_layout.addWidget(self.card_passed)
        stats_layout.addWidget(self.card_rate)

        layout.addLayout(stats_layout)

        # Results Toolbar
        toolbar = QHBoxLayout()
        section_title = QLabel("سجل نتائج الامتحانات السابقة (Exam History)")
        section_title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        toolbar.addWidget(section_title)

        toolbar.addStretch()

        self.btn_refresh_results = AnimatedButton("تحديث النتائج (Refresh Results)")
        self.btn_refresh_results.setIcon(qta.icon("fa5s.sync", color=COLORS['TEXT_PRIMARY']))
        self.btn_refresh_results.clicked.connect(self.load_results)
        toolbar.addWidget(self.btn_refresh_results)

        layout.addLayout(toolbar)

        # Results Table: Columns: Date, Score, Passed/Failed
        self.results_table = QTableWidget(0, 3)
        self.results_table.setHorizontalHeaderLabels([
            "التاريخ (Date)",
            "النتيجة (Score)",
            "الحالة (Passed/Failed)"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.results_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['BG_PANEL']};
                color: {COLORS['TEXT_PRIMARY']};
                gridline-color: {COLORS['BG_BUTTON']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 4px;
            }}
            QHeaderView::section {{
                background-color: {COLORS['BG_BUTTON']};
                color: {COLORS['ACCENT']};
                padding: 8px;
                border: 1px solid {COLORS['ACCENT_PURPLE']};
                font-weight: bold;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['ACCENT_PURPLE']};
                color: white;
            }}
        """)
        layout.addWidget(self.results_table)

        return tab

    def _create_stat_card(self, title: str, initial_value: str, accent_color: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 1px solid {COLORS['BG_BUTTON']};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(10, 8, 10, 8)
        card_layout.setSpacing(4)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; font-size: 11px; font-weight: bold; border: none;")
        card_layout.addWidget(title_lbl)

        val_lbl = QLabel(initial_value)
        val_lbl.setStyleSheet(f"color: {accent_color}; font-size: 20px; font-weight: bold; border: none;")
        card_layout.addWidget(val_lbl)

        # Attach label reference to card
        card.value_label = val_lbl
        return card

    def load_quizzes(self):
        """Fetch available quizzes from database and populate quizzes_table."""
        self.quizzes_table.setRowCount(0)
        try:
            self._quizzes_cache = self.db.get_training_quizzes()
        except Exception as e:
            self._quizzes_cache = []
            QMessageBox.warning(self, "خطأ (Error)", f"فشل في تحميل الامتحانات:\n{e}")
            return

        if not self._quizzes_cache:
            return

        self.quizzes_table.setRowCount(len(self._quizzes_cache))
        for row_idx, quiz in enumerate(self._quizzes_cache):
            # quiz format: (id, question_ar, options_json, correct_option, difficulty, category)
            qid = quiz[0]
            question = quiz[1]
            difficulty = quiz[4] if len(quiz) > 4 else 'Easy'
            category = quiz[5] if len(quiz) > 5 else 'General'

            # 0: ID
            id_item = QTableWidgetItem(str(qid))
            id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.quizzes_table.setItem(row_idx, 0, id_item)

            # 1: Category
            cat_item = QTableWidgetItem(str(category))
            cat_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.quizzes_table.setItem(row_idx, 1, cat_item)

            # 2: Difficulty
            diff_item = QTableWidgetItem(str(difficulty))
            diff_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            diff_lower = str(difficulty).lower()
            if 'easy' in diff_lower or 'سهل' in diff_lower:
                diff_item.setForeground(QColor(COLORS['SUCCESS']))
            elif 'medium' in diff_lower or 'متوسط' in diff_lower:
                diff_item.setForeground(QColor(COLORS['WARNING']))
            else:
                diff_item.setForeground(QColor(COLORS['ERROR']))
            self.quizzes_table.setItem(row_idx, 2, diff_item)

            # 3: Question
            q_item = QTableWidgetItem(str(question))
            self.quizzes_table.setItem(row_idx, 3, q_item)

            # 4: Action Button
            action_btn = AnimatedButton("ابدأ (Start)", primary=True)
            action_btn.setIcon(qta.icon("fa5s.play", color="white"))
            action_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS['BG_BUTTON']};
                    color: white;
                    padding: 4px 10px;
                    border-radius: 4px;
                    font-size: 11px;
                }}
                QPushButton:hover {{
                    background-color: {COLORS['ACCENT']};
                }}
            """)
            action_btn.clicked.connect(lambda _, q=quiz: self.launch_quiz(q))

            btn_container = QWidget()
            btn_layout = QHBoxLayout(btn_container)
            btn_layout.setContentsMargins(4, 2, 4, 2)
            btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            btn_layout.addWidget(action_btn)
            self.quizzes_table.setCellWidget(row_idx, 4, btn_container)

    def load_results(self):
        """Fetch score history for self.current_username and populate results_table."""
        self.results_table.setRowCount(0)
        try:
            results = self.db.get_training_results(self.current_username)
        except Exception as e:
            results = []
            QMessageBox.warning(self, "خطأ (Error)", f"فشل في تحميل النتائج:\n{e}")

        if not results:
            self._update_stats(0, 0, 0.0)
            return

        total_attempts = len(results)
        passed_count = sum(1 for r in results if bool(r[3]))
        success_rate = (passed_count / total_attempts * 100.0) if total_attempts > 0 else 0.0
        self._update_stats(total_attempts, passed_count, success_rate)

        self.results_table.setRowCount(total_attempts)
        for row_idx, row in enumerate(results):
            # row format: (id, username, score, passed, completed_at)
            score_val = float(row[2]) if row[2] is not None else 0.0
            passed_val = bool(row[3])
            date_str = str(row[4]) if row[4] else "—"

            # Column 0: Date
            date_item = QTableWidgetItem(date_str)
            date_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.results_table.setItem(row_idx, 0, date_item)

            # Column 1: Score
            score_item = QTableWidgetItem(f"{score_val:.0f}%")
            score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if score_val >= 80.0:
                score_item.setForeground(QColor(COLORS['SUCCESS']))
            elif score_val >= 50.0:
                score_item.setForeground(QColor(COLORS['WARNING']))
            else:
                score_item.setForeground(QColor(COLORS['ERROR']))
            self.results_table.setItem(row_idx, 1, score_item)

            # Column 2: Passed/Failed
            status_str = "ناجح (Passed) ✅" if passed_val else "راسب (Failed) ❌"
            status_item = QTableWidgetItem(status_str)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if passed_val:
                status_item.setForeground(QColor(COLORS['SUCCESS']))
            else:
                status_item.setForeground(QColor(COLORS['ERROR']))
            self.results_table.setItem(row_idx, 2, status_item)

    def _update_stats(self, total: int, passed: int, rate: float):
        if hasattr(self, 'card_total') and hasattr(self.card_total, 'value_label'):
            self.card_total.value_label.setText(str(total))
        if hasattr(self, 'card_passed') and hasattr(self.card_passed, 'value_label'):
            self.card_passed.value_label.setText(str(passed))
        if hasattr(self, 'card_rate') and hasattr(self.card_rate, 'value_label'):
            self.card_rate.value_label.setText(f"{rate:.1f}%")

    def on_quiz_cell_double_clicked(self, row: int, column: int):
        """Launch quiz when user double-clicks on a table row."""
        if 0 <= row < len(self._quizzes_cache):
            self.launch_quiz(self._quizzes_cache[row])

    def on_start_quiz(self):
        """Start the currently selected quiz from the table, or first quiz if none selected."""
        selected_row = self.quizzes_table.currentRow()
        if selected_row < 0:
            if self.quizzes_table.rowCount() > 0:
                selected_row = 0
                self.quizzes_table.selectRow(0)
            else:
                QMessageBox.warning(
                    self,
                    "تنبيه (Warning)",
                    "لا توجد امتحانات متاحة حالياً.\n(No quizzes available currently.)"
                )
                return

        if 0 <= selected_row < len(self._quizzes_cache):
            self.launch_quiz(self._quizzes_cache[selected_row])

    def launch_quiz(self, quiz_data):
        """Launch the single quiz question dialog and save result upon submission."""
        dlg = QuizDialog(quiz_data, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            quiz_id = str(dlg.quiz_id)
            score = float(dlg.score)
            passed = bool(score >= 80.0)

            # Save result using self.db.save_training_result(self.current_username, str(quiz_id), score, passed)
            try:
                self.db.save_training_result(self.current_username, str(quiz_id), score, passed)
            except Exception as e:
                QMessageBox.critical(self, "خطأ في الحفظ (Save Error)", f"فشل في حفظ نتيجة الامتحان:\n{e}")
                return

            # Display result feedback
            if passed:
                QMessageBox.information(
                    self,
                    "نتيجة الامتحان (Quiz Result)",
                    f"تهانينا! لقد اجتزت الامتحان بنجاح. 🎉\n\n"
                    f"الدرجة: {score:.0f}%\n"
                    f"الحالة: ناجح (Passed)\n"
                    f"تم تسجيل النتيجة في ملفك الشخصي."
                )
            else:
                QMessageBox.warning(
                    self,
                    "نتيجة الامتحان (Quiz Result)",
                    f"للأسف، لم تجتز الامتحان. ❌\n\n"
                    f"الدرجة: {score:.0f}%\n"
                    f"الحالة: راسب (Failed) - نسبة النجاح المطلوبة 80%\n"
                    f"يمكنك إعادة المحاولة لاحقاً لتحسين درجتك."
                )

            # Refresh results table and switch to Results tab
            self.load_results()
            self.tabs.setCurrentIndex(1)

    def on_start_comprehensive(self):
        """Launch comprehensive exam covering all available quizzes."""
        if not self._quizzes_cache:
            QMessageBox.warning(
                self,
                "تنبيه (Warning)",
                "لا توجد امتحانات متاحة حالياً للبدء.\n(No quizzes available currently.)"
            )
            return

        dlg = ComprehensiveExamDialog(self._quizzes_cache, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            score = float(dlg.score)
            passed = bool(score >= 80.0)
            quiz_ids = ",".join(str(q[0]) for q in self._quizzes_cache)

            try:
                self.db.save_training_result(self.current_username, quiz_ids, score, passed)
            except Exception as e:
                QMessageBox.critical(self, "خطأ في الحفظ (Save Error)", f"فشل في حفظ نتيجة الامتحان:\n{e}")
                return

            if passed:
                QMessageBox.information(
                    self,
                    "نتيجة الامتحان الشامل (Comprehensive Exam Result)",
                    f"تهانينا! لقد اجتزت الامتحان الشامل بنجاح! 🎉\n\n"
                    f"الدرجة: {score:.1f}%\n"
                    f"الحالة: ناجح (Passed)"
                )
            else:
                QMessageBox.warning(
                    self,
                    "نتيجة الامتحان الشامل (Comprehensive Exam Result)",
                    f"للأسف، لم تجتز الامتحان الشامل. ❌\n\n"
                    f"الدرجة: {score:.1f}%\n"
                    f"الحالة: راسب (Failed) - نسبة النجاح المطلوبة 80%\n"
                    f"يمكنك مراجعة مواد التوعية وإعادة المحاولة."
                )

            self.load_results()
            self.tabs.setCurrentIndex(1)
