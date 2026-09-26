from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QMessageBox, QComboBox)
import sqlite3
import pandas as pd
import logging

class DatabaseScanDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("فحص قاعدة بيانات (Database Scanner)")
        self.setFixedSize(450, 300)
        
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("نوع قاعدة البيانات (DB Type):"))
        self.db_type = QComboBox()
        self.db_type.addItems(["SQLite", "MySQL", "PostgreSQL"])
        layout.addWidget(self.db_type)
        
        layout.addWidget(QLabel("مسار الملف (لـ SQLite) أو سلسلة الاتصال (لـ SQL):"))
        self.connection_string = QLineEdit()
        self.connection_string.setPlaceholderText("مثال: C:\\data\\mydb.sqlite أو user:pass@localhost/db")
        layout.addWidget(self.connection_string)
        
        layout.addWidget(QLabel("اسم الجدول (Table Name):"))
        self.table_name = QLineEdit()
        layout.addWidget(self.table_name)
        
        layout.addWidget(QLabel("الأعمدة المراد فحصها (Columns - مفصولة بفاصلة):"))
        self.columns = QLineEdit()
        self.columns.setPlaceholderText("مثال: user_notes, email, bio (اترك فارغاً لفحص الكل)")
        layout.addWidget(self.columns)
        
        btn_layout = QHBoxLayout()
        test_btn = QPushButton("اختبار الاتصال (Test)")
        test_btn.clicked.connect(self.test_connection)
        
        scan_btn = QPushButton("بدء الفحص (Start Scan)")
        scan_btn.clicked.connect(self.accept)
        
        btn_layout.addWidget(test_btn)
        btn_layout.addWidget(scan_btn)
        layout.addLayout(btn_layout)
        
        from gui.theme import COLORS
        self.setStyleSheet(f"""
            QDialog {{ background-color: {COLORS['BG_MAIN']}; color: {COLORS['TEXT_PRIMARY']}; }}
            QLabel {{ color: {COLORS['TEXT_PRIMARY']}; }}
            QLineEdit, QComboBox {{ background-color: {COLORS['BG_PANEL']}; color: {COLORS['TEXT_PRIMARY']}; padding: 5px; border-radius: 4px; border: 1px solid {COLORS['BG_BUTTON']}; }}
            QPushButton {{ background-color: {COLORS['ACCENT']}; color: white; padding: 5px 15px; border-radius: 4px; }}
        """)
        
    def test_connection(self):
        db_type = self.db_type.currentText()
        conn_str = self.connection_string.text()
        
        try:
            if db_type == "SQLite":
                import os
                if not os.path.exists(conn_str):
                    raise Exception("ملف قاعدة البيانات غير موجود.")
                conn = sqlite3.connect(conn_str)
                conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                conn.close()
            elif db_type == "MySQL":
                import pymysql
                # Assuming format user:pass@host/db
                user_pass, host_db = conn_str.split('@')
                user, password = user_pass.split(':')
                host, db = host_db.split('/')
                conn = pymysql.connect(host=host, user=user, password=password, database=db)
                conn.close()
            elif db_type == "PostgreSQL":
                import psycopg2
                conn = psycopg2.connect(conn_str)
                conn.close()
                
            QMessageBox.information(self, "نجاح", "تم الاتصال بقاعدة البيانات بنجاح.")
        except Exception as e:
            QMessageBox.critical(self, "خطأ", f"فشل الاتصال: {str(e)}")
            
    def fetch_data(self) -> str:
        """Connects and extracts all specified rows as a single text block for scanning."""
        db_type = self.db_type.currentText()
        conn_str = self.connection_string.text()
        table = self.table_name.text()
        cols = self.columns.text().strip()
        
        if not table:
            return ""
            
        select_clause = cols if cols else "*"
        query = f"SELECT {select_clause} FROM {table} LIMIT 1000" # Limit to avoid massive memory usage for now
        
        try:
            if db_type == "SQLite":
                conn = sqlite3.connect(conn_str)
                df = pd.read_sql_query(query, conn)
                conn.close()
            elif db_type == "MySQL":
                import pymysql
                user_pass, host_db = conn_str.split('@')
                user, password = user_pass.split(':')
                host, db = host_db.split('/')
                conn = pymysql.connect(host=host, user=user, password=password, database=db)
                df = pd.read_sql_query(query, conn)
                conn.close()
            elif db_type == "PostgreSQL":
                import psycopg2
                conn = psycopg2.connect(conn_str)
                df = pd.read_sql_query(query, conn)
                conn.close()
                
            # Convert dataframe to a formatted text document
            text_lines = []
            for idx, row in df.iterrows():
                line = " | ".join([f"{col}: {val}" for col, val in row.items() if pd.notna(val)])
                text_lines.append(f"Row {idx+1}: {line}")
                
            return "\n".join(text_lines)
            
        except Exception as e:
            logging.error(f"DB Extraction failed: {e}")
            return ""
