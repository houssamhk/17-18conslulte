import json
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
                             QDialog, QLineEdit, QComboBox, QFormLayout, QDialogButtonBox,
                             QMessageBox, QGroupBox, QSpinBox)
from PyQt6.QtCore import Qt
from storage.secure_db import SecureDatabase
from .theme import COLORS


class PolicyBuilderDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("إنشاء سياسة امتثال (Create Policy)")
        self.resize(500, 400)
        
        layout = QVBoxLayout(self)
        
        # Details
        details_group = QGroupBox("تفاصيل السياسة (Policy Details)")
        form = QFormLayout(details_group)
        self.name_input = QLineEdit()
        self.desc_input = QLineEdit()
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["INFO", "WARNING", "CRITICAL", "BLOCKER"])
        self.remed_input = QLineEdit()
        
        form.addRow("اسم السياسة (Name):", self.name_input)
        form.addRow("الوصف (Description):", self.desc_input)
        form.addRow("الخطورة (Severity):", self.severity_combo)
        form.addRow("الإجراء التصحيحي (Remediation):", self.remed_input)
        layout.addWidget(details_group)
        
        # Condition Builder (Simplified for now)
        cond_group = QGroupBox("شروط السياسة (Conditions)")
        cond_layout = QFormLayout(cond_group)
        
        self.entity_combo = QComboBox()
        self.entity_combo.addItems(["NIN", "RIB", "PHONE", "EMAIL", "PER", "LOC", "total_entities"])
        
        self.operator_combo = QComboBox()
        self.operator_combo.addItems([">", "<", ">=", "<=", "==", "!="])
        
        self.value_input = QSpinBox()
        self.value_input.setRange(0, 1000)
        
        cond_layout.addRow("الحقل (Field):", self.entity_combo)
        cond_layout.addRow("الشرط (Operator):", self.operator_combo)
        cond_layout.addRow("القيمة (Value):", self.value_input)
        layout.addWidget(cond_group)
        
        # Buttons
        self.btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.btns.accepted.connect(self.accept)
        self.btns.rejected.connect(self.reject)
        layout.addWidget(self.btns)
        
    def get_policy_data(self):
        # Format the condition for the policy engine
        field = self.entity_combo.currentText()
        if field != "total_entities":
            field = f"count_{field}"
            
        condition = [{
            "field": field,
            "operator": self.operator_combo.currentText(),
            "value": self.value_input.value()
        }]
        
        return {
            "name": self.name_input.text(),
            "description": self.desc_input.text(),
            "severity": self.severity_combo.currentText(),
            "remediation": self.remed_input.text(),
            "conditions_json": json.dumps(condition)
        }


class PoliciesPageWidget(QWidget):
    def __init__(self, db: SecureDatabase, parent=None):
        super().__init__(parent)
        self.db = db
        self._init_ui()
        self.load_data()
        
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("سياسات الامتثال (Compliance Policies)")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        add_btn = QPushButton("إضافة سياسة (Add Policy)")
        add_btn.setStyleSheet(f"background-color: {COLORS['SUCCESS']}; color: white; padding: 8px;")
        add_btn.clicked.connect(self.on_add_policy)
        header_layout.addWidget(add_btn)
        layout.addLayout(header_layout)
        
        # Active Policies Table
        self.policies_table = QTableWidget(0, 5)
        self.policies_table.setHorizontalHeaderLabels(["الاسم", "الوصف", "الخطورة", "الشروط", "الإجراء الموصى به"])
        self.policies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.policies_table)
        
        # Violations Inbox
        inbox_lbl = QLabel("الانتهاكات المفتوحة (Open Violations Inbox)")
        inbox_lbl.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['WARNING']}; margin-top: 15px;")
        layout.addWidget(inbox_lbl)
        
        self.violations_table = QTableWidget(0, 6)
        self.violations_table.setHorizontalHeaderLabels(["ID", "السياسة", "الخطورة", "المستند", "التفاصيل", "إجراء"])
        self.violations_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.violations_table)
        
    def load_data(self):
        # Load Policies
        self.policies_table.setRowCount(0)
        policies = self.db.get_active_policies()
        for i, p in enumerate(policies):
            self.policies_table.insertRow(i)
            self.policies_table.setItem(i, 0, QTableWidgetItem(p[1]))
            self.policies_table.setItem(i, 1, QTableWidgetItem(p[2]))
            self.policies_table.setItem(i, 2, QTableWidgetItem(p[4]))
            self.policies_table.setItem(i, 3, QTableWidgetItem(p[3]))
            self.policies_table.setItem(i, 4, QTableWidgetItem(p[5]))
            
        # Load Violations
        self.violations_table.setRowCount(0)
        violations = self.db.get_open_violations()
        for i, v in enumerate(violations):
            self.violations_table.insertRow(i)
            self.violations_table.setItem(i, 0, QTableWidgetItem(str(v[0])))
            self.violations_table.setItem(i, 1, QTableWidgetItem(v[1]))
            self.violations_table.setItem(i, 2, QTableWidgetItem(v[2]))
            self.violations_table.setItem(i, 3, QTableWidgetItem(v[3]))
            self.violations_table.setItem(i, 4, QTableWidgetItem(v[4]))
            
            res_btn = QPushButton("حل (Resolve)")
            res_btn.clicked.connect(lambda checked, vid=v[0]: self.resolve_violation(vid))
            self.violations_table.setCellWidget(i, 5, res_btn)
            
    def on_add_policy(self):
        dlg = PolicyBuilderDialog(self)
        if dlg.exec():
            data = dlg.get_policy_data()
            if not data['name']:
                QMessageBox.warning(self, "خطأ", "يجب إدخال اسم السياسة.")
                return
                
            self.db.save_compliance_policy(
                data['name'], data['description'], data['conditions_json'],
                data['severity'], data['remediation'], "admin"
            )
            self.load_data()
            
    def resolve_violation(self, violation_id: int):
        self.db.resolve_violation(violation_id, "admin")
        self.load_data()
