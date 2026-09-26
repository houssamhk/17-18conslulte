import pyqtgraph as pg
import json
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QSplitter)
from PyQt6.QtCore import Qt
from storage.secure_db import SecureDatabase
from .theme import COLORS
from .widgets import ComplianceGauge

class StatCard(QFrame):
    def __init__(self, title: str, value: str, color: str):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 2px solid {color};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(self)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']}; border: none;")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.lbl_val = QLabel(value)
        self.lbl_val.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold; border: none;")
        self.lbl_val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(lbl_title)
        layout.addWidget(self.lbl_val)
        
    def set_value(self, val: str):
        self.lbl_val.setText(str(val))

class DashboardWidget(QWidget):
    """Analytics Dashboard visualizing audit logs from SecureDatabase."""
    
    def __init__(self, db: SecureDatabase, user_role: str = 'user', user_department: str = None, parent=None):
        super().__init__(parent)
        self.db = db
        self.user_role = user_role
        self.user_department = user_department
        self._init_ui()
        
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("لوحة الإحصائيات الشاملة (Analytics Dashboard)")
        header.setStyleSheet(f"color: {COLORS['ACCENT']}; font-size: 18px; font-weight: bold;")
        layout.addWidget(header)
        
        # Top Section: Cards and Gauge
        top_layout = QHBoxLayout()
        
        # Cards
        cards_layout = QVBoxLayout()
        self.card_scans = StatCard("إجمالي عمليات الفحص", "0", COLORS['ACCENT_PURPLE'])
        self.card_entities = StatCard("البيانات الحساسة المكتشفة", "0", COLORS['ERROR'])
        self.card_high_risk = StatCard("ملفات عالية الخطورة", "0", COLORS['WARNING'])
        self.card_anomalies = StatCard("حالات شذوذ غير مقروءة", "0", COLORS['ERROR'])
        cards_layout.addWidget(self.card_scans)
        cards_layout.addWidget(self.card_entities)
        cards_layout.addWidget(self.card_high_risk)
        cards_layout.addWidget(self.card_anomalies)
        
        top_layout.addLayout(cards_layout, stretch=1)
        
        # Gauge
        gauge_layout = QVBoxLayout()
        gauge_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gauge_header = QLabel("مؤشر الامتثال العام\n(Overall Compliance Score)")
        gauge_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gauge_header.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']};")
        self.gauge = ComplianceGauge()
        gauge_layout.addWidget(gauge_header)
        gauge_layout.addWidget(self.gauge)
        
        top_layout.addLayout(gauge_layout)
        layout.addLayout(top_layout)
        
        # Middle Section: Chart
        pg.setConfigOption('background', COLORS['BG_MAIN'])
        pg.setConfigOption('foreground', COLORS['TEXT_PRIMARY'])
        self.plot_widget = pg.PlotWidget(title="توزيع أنواع البيانات المكتشفة (Entity Types Distribution)")
        self.plot_widget.getAxis('bottom').setTicks([]) 
        self.plot_widget.setMinimumHeight(200)
        layout.addWidget(self.plot_widget, stretch=1)
        
        # Bottom Section: Splitter for Tables
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Scan History Table
        scan_panel = QWidget()
        scan_layout = QVBoxLayout(scan_panel)
        scan_lbl = QLabel("سجل الفحوصات (Scan History)")
        scan_lbl.setStyleSheet(f"color: {COLORS['ACCENT']}; font-weight: bold;")
        self.scan_table = QTableWidget(0, 4)
        self.scan_table.setHorizontalHeaderLabels(["التاريخ والوقت", "الملف", "البيانات المكتشفة", "مستوى الخطر"])
        self.scan_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        scan_layout.addWidget(scan_lbl)
        scan_layout.addWidget(self.scan_table)
        
        # Audit Log Table
        audit_panel = QWidget()
        audit_layout = QVBoxLayout(audit_panel)
        audit_lbl = QLabel("سجل النظام (Audit Log)")
        audit_lbl.setStyleSheet(f"color: {COLORS['ACCENT']}; font-weight: bold;")
        self.audit_table = QTableWidget(0, 4)
        self.audit_table.setHorizontalHeaderLabels(["التاريخ والوقت", "المستخدم", "الإجراء", "التفاصيل"])
        self.audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        audit_layout.addWidget(audit_lbl)
        audit_layout.addWidget(self.audit_table)
        
        # Anomalies Table
        anomaly_panel = QWidget()
        anomaly_layout = QVBoxLayout(anomaly_panel)
        anomaly_lbl = QLabel("تنبيهات الشذوذ (Anomaly Alerts)")
        anomaly_lbl.setStyleSheet(f"color: {COLORS['ERROR']}; font-weight: bold;")
        self.anomaly_table = QTableWidget(0, 4)
        self.anomaly_table.setHorizontalHeaderLabels(["الوقت", "النوع", "الوصف", "الأهمية"])
        self.anomaly_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        anomaly_layout.addWidget(anomaly_lbl)
        anomaly_layout.addWidget(self.anomaly_table)
        
        splitter.addWidget(scan_panel)
        splitter.addWidget(audit_panel)
        splitter.addWidget(anomaly_panel)
        layout.addWidget(splitter, stretch=2)
        
    def refresh_data(self):
        """Fetches latest data from DB and updates charts and tables."""
        try:
            # 1. Update Scans and Chart
            dept_filter = self.user_department if self.user_role != 'admin' else None
            history = self.db.get_scan_history(limit=50, department=dept_filter) 
            
            total_scans = len(history)
            total_entities = 0
            high_risk_count = 0
            type_counts = {}
            
            self.scan_table.setRowCount(0)
            
            for i, record in enumerate(history):
                # record: (id, timestamp, doc_name, total_ent, risk, strategy, summary_json)
                ts, doc_name, ent_count, risk = record[1], record[2], record[3], record[4]
                
                total_entities += ent_count
                if risk == "HIGH" or risk == "CRITICAL":
                    high_risk_count += 1
                    
                summary = json.loads(record[6]) if record[6] else {}
                for etype, count in summary.items():
                    type_counts[etype] = type_counts.get(etype, 0) + count
                    
                # Add to table
                self.scan_table.insertRow(i)
                self.scan_table.setItem(i, 0, QTableWidgetItem(str(ts)))
                self.scan_table.setItem(i, 1, QTableWidgetItem(str(doc_name)))
                self.scan_table.setItem(i, 2, QTableWidgetItem(str(ent_count)))
                
                risk_item = QTableWidgetItem(risk)
                if risk == "CRITICAL" or risk == "HIGH":
                    risk_item.setForeground(Qt.GlobalColor.red)
                elif risk == "LOW":
                    risk_item.setForeground(Qt.GlobalColor.green)
                self.scan_table.setItem(i, 3, risk_item)
            
            # Update Cards
            self.card_scans.set_value(str(total_scans))
            self.card_entities.set_value(str(total_entities))
            self.card_high_risk.set_value(str(high_risk_count))
            
            # 1.5 Update Anomalies
            anomalies = self.db.get_unacknowledged_anomalies()
            self.card_anomalies.set_value(str(len(anomalies)))
            
            self.anomaly_table.setRowCount(0)
            for i, anom in enumerate(anomalies):
                self.anomaly_table.insertRow(i)
                self.anomaly_table.setItem(i, 0, QTableWidgetItem(str(anom[5]))) # detected_at
                self.anomaly_table.setItem(i, 1, QTableWidgetItem(anom[1]))      # anomaly_type
                self.anomaly_table.setItem(i, 2, QTableWidgetItem(anom[2]))      # desc
                sev_item = QTableWidgetItem(anom[3])
                if anom[3] == "CRITICAL" or anom[3] == "HIGH":
                    sev_item.setForeground(Qt.GlobalColor.red)
                self.anomaly_table.setItem(i, 3, sev_item)
            
            # Calculate Compliance Score (100% means 0 high risk files, 0 open incidents, 0 open violations)
            # Fetch open incidents and violations to penalize score
            incidents = self.db.get_incidents()
            open_incidents = len([inc for inc in incidents if inc['status'] != 'CLOSED'])
            
            policies = self.db.get_active_policies()
            # simplified: each high risk scan = -5 points, open incident = -10 points, anomaly = -5 points
            score = 100
            score -= (high_risk_count * 5)
            score -= (open_incidents * 10)
            score -= (len(anomalies) * 5)
            
            score = max(0, min(100, score))
            self.gauge.set_value(score)
            
            # Update Chart
            self.plot_widget.clear()
            if type_counts:
                labels = list(type_counts.keys())
                values = list(type_counts.values())
                x = list(range(1, len(labels) + 1))
                
                bargraph = pg.BarGraphItem(x=x, height=values, width=0.6, brush=COLORS['ACCENT'])
                self.plot_widget.addItem(bargraph)
                
                ticks = [list(zip(x, labels))]
                self.plot_widget.getAxis('bottom').setTicks(ticks)
                
            # 2. Update Audit Log Table
            audits = self.db.get_audit_log(limit=50)
            self.audit_table.setRowCount(0)
            for i, log in enumerate(audits):
                self.audit_table.insertRow(i)
                self.audit_table.setItem(i, 0, QTableWidgetItem(str(log[0])))
                self.audit_table.setItem(i, 1, QTableWidgetItem(str(log[1])))
                self.audit_table.setItem(i, 2, QTableWidgetItem(str(log[2])))
                self.audit_table.setItem(i, 3, QTableWidgetItem(str(log[3])))
                
        except Exception as e:
            import logging
            logging.error(f"Failed to refresh dashboard: {e}")
