import json
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QMessageBox, QTextEdit, 
                             QComboBox, QWizard, QWizardPage, QCheckBox)
from PyQt6.QtCore import Qt
from storage.secure_db import SecureDatabase
from gui.theme import COLORS

class PIAWizard(QWizard):
    """Wizard for creating Privacy Impact Assessments."""
    
    def __init__(self, db: SecureDatabase, department: str, username: str, parent=None):
        super().__init__(parent)
        self.db = db
        self.department = department or "Unknown"
        self.username = username
        
        self.setWindowTitle("تقييم أثر الخصوصية (PIA Wizard)")
        self.setFixedSize(650, 500)
        
        # Add Pages
        self.addPage(self.create_intro_page())
        self.addPage(self.create_data_page())
        self.addPage(self.create_risk_page())
        
        self.setStyleSheet(f"""
            QWizard {{ background-color: {COLORS['BG_MAIN']}; color: {COLORS['TEXT_PRIMARY']}; }}
            QLabel {{ color: {COLORS['TEXT_PRIMARY']}; }}
            QLineEdit, QTextEdit {{ background-color: {COLORS['BG_PANEL']}; color: {COLORS['TEXT_PRIMARY']}; border: 1px solid {COLORS['BG_BUTTON']}; border-radius: 4px; padding: 5px; }}
            QCheckBox {{ color: {COLORS['TEXT_PRIMARY']}; }}
        """)
        
    def create_intro_page(self):
        page = QWizardPage()
        page.setTitle("المعلومات الأساسية للمشروع")
        page.setSubTitle("أدخل تفاصيل المشروع الذي يتطلب معالجة بيانات شخصية.")
        
        layout = QVBoxLayout(page)
        
        layout.addWidget(QLabel("اسم المشروع (Project Name):"))
        self.project_name_edit = QLineEdit()
        page.registerField("project_name*", self.project_name_edit)
        layout.addWidget(self.project_name_edit)
        
        layout.addWidget(QLabel("الغرض من المعالجة (Processing Purpose):"))
        self.purpose_edit = QTextEdit()
        self.purpose_edit.setFixedHeight(80)
        layout.addWidget(self.purpose_edit)
        
        layout.addWidget(QLabel(f"القسم (Department): {self.department}"))
        layout.addWidget(QLabel(f"المقيِّم (Assessor): {self.username}"))
        
        return page
        
    def create_data_page(self):
        page = QWizardPage()
        page.setTitle("فئات البيانات (Data Categories)")
        page.setSubTitle("حدد أنواع البيانات الشخصية التي سيتم جمعها أو معالجتها.")
        
        layout = QVBoxLayout(page)
        
        self.data_types = []
        categories = ["رقم التعريف الوطني (NIN)", "أرقام هواتف (Phone)", 
                      "رسائل بريد إلكتروني (Email)", "بيانات مالية (CCP/RIB)", 
                      "أسماء أشخاص (Names)", "عناوين (Addresses)", "بيانات صحية (Health Data)"]
                      
        for cat in categories:
            cb = QCheckBox(cat)
            self.data_types.append(cb)
            layout.addWidget(cb)
            
        return page
        
    def create_risk_page(self):
        page = QWizardPage()
        page.setTitle("تقييم المخاطر والتخفيف (Risks & Mitigation)")
        page.setSubTitle("حدد مستوى الخطر والتدابير المتخذة لحماية هذه البيانات.")
        
        layout = QVBoxLayout(page)
        
        layout.addWidget(QLabel("مستوى الخطر الإجمالي (Overall Risk Level):"))
        self.risk_combo = QComboBox()
        self.risk_combo.addItems(["منخفض (LOW)", "متوسط (MEDIUM)", "مرتفع (HIGH)", "حرج (CRITICAL)"])
        self.risk_combo.setStyleSheet(f"background-color: {COLORS['BG_PANEL']}; color: {COLORS['TEXT_PRIMARY']};")
        layout.addWidget(self.risk_combo)
        
        layout.addWidget(QLabel("التدابير الأمنية المتخذة (Mitigation Steps):"))
        self.mitigation_edit = QTextEdit()
        self.mitigation_edit.setPlaceholderText("مثال: تشفير قاعدة البيانات، استخدام صلاحيات وصول محدودة...")
        layout.addWidget(self.mitigation_edit)
        
        return page
        
    def accept(self):
        # Save to DB
        project_name = self.project_name_edit.text()
        purpose = self.purpose_edit.toPlainText()
        
        selected_types = [cb.text() for cb in self.data_types if cb.isChecked()]
        data_types_json = json.dumps(selected_types)
        
        risk_level = self.risk_combo.currentText().split(" ")[-1].strip("()")
        mitigation = self.mitigation_edit.toPlainText()
        
        c = self.db.conn.cursor()
        c.execute('''INSERT INTO pia_assessments 
                     (project_name, department, assessor_name, data_types_json, 
                      processing_purpose, risk_level, mitigation_steps, status)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                  (project_name, self.department, self.username, data_types_json,
                   purpose, risk_level, mitigation, 'COMPLETED'))
        self.db.conn.commit()
        
        QMessageBox.information(self, "نجاح", "تم حفظ تقييم الأثر (PIA) بنجاح.")
        super().accept()
