import json
import logging
import bcrypt
from typing import List, Dict, Optional, Tuple

try:
    from sqlcipher3 import dbapi2 as sqlite
    _has_sqlcipher = True
except ImportError:
    import sqlite3 as sqlite
    _has_sqlcipher = False

from .key_manager import KeyManager
from cryptography.fernet import Fernet

class SecureDatabase:
    """AES-256 Encrypted SQLite Database for Audit Logs, Settings, Users, and Keywords."""
    
    def __init__(self, db_path: str = 'alg_pii_engine.db'):
        self.db_path = db_path
        self._use_sqlcipher = _has_sqlcipher
        self.conn = None
        self.fernet = None
        self._connect()
        self._init_schema()

    def _connect(self):
        key = KeyManager.ensure_key()
        self.conn = sqlite.connect(self.db_path, check_same_thread=False)
        
        if self._use_sqlcipher:
            # PRAGMA key must be the first operation
            key_hex = key.hex()
            self.conn.execute(f"PRAGMA key = '{key_hex}'")
            # Verify key
            try:
                self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            except sqlite.DatabaseError:
                logging.error("Database encryption key is invalid or database is corrupt.")
                raise ValueError("Invalid Database Key")
        else:
            self.fernet = Fernet(key)

    def _encrypt_val(self, val: str) -> str:
        if self._use_sqlcipher or not self.fernet or not val:
            return val
        return self.fernet.encrypt(val.encode()).decode()

    def _decrypt_val(self, val: str) -> str:
        if self._use_sqlcipher or not self.fernet or not val:
            return val
        try:
            return self.fernet.decrypt(val.encode()).decode()
        except Exception:
            return val # Might not be encrypted

    def _init_schema(self):
        c = self.conn.cursor()
        
        # Scans
        c.execute('''CREATE TABLE IF NOT EXISTS scan_history
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                      document_name TEXT,
                      total_entities INTEGER,
                      risk_level TEXT,
                      strategy_used TEXT,
                      summary_json TEXT,
                      sensitivity_label TEXT DEFAULT 'UNCLASSIFIED',
                      ocr_used BOOLEAN DEFAULT 0,
                      duplicates_found INTEGER DEFAULT 0,
                      label_override_by TEXT,
                      label_override_reason TEXT,
                      department TEXT)''')
                      
        try:
            c.execute("ALTER TABLE scan_history ADD COLUMN department TEXT")
        except:
            pass
            
        # Labeling Policies
        c.execute('''CREATE TABLE IF NOT EXISTS labeling_policies
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      label_name TEXT UNIQUE,
                      label_color TEXT,
                      min_score INTEGER,
                      max_score INTEGER,
                      required_entity_types TEXT,
                      description_ar TEXT,
                      description_en TEXT)''')
                      
        # Regulatory Mappings
        c.execute('''CREATE TABLE IF NOT EXISTS regulatory_mappings
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      entity_type TEXT NOT NULL,
                      law_name TEXT NOT NULL,
                      law_number TEXT,
                      article_number TEXT,
                      article_title_ar TEXT,
                      article_summary_ar TEXT,
                      penalty_description_ar TEXT,
                      applicable_sectors TEXT,
                      is_active BOOLEAN DEFAULT 1)''')
                      
        # Settings
        c.execute('''CREATE TABLE IF NOT EXISTS settings
                     (key TEXT PRIMARY KEY, value TEXT)''')
                     
        # Users
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE,
                      password_hash TEXT,
                      role TEXT)''')
                      
        # Custom Keywords
        c.execute('''CREATE TABLE IF NOT EXISTS custom_keywords
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      keyword TEXT UNIQUE)''')
                      
        # Audit Log
        c.execute('''CREATE TABLE IF NOT EXISTS audit_log
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                      username TEXT,
                      action TEXT,
                      details TEXT)''')
                      
        # Document Fingerprints
        c.execute('''CREATE TABLE IF NOT EXISTS document_fingerprints
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scan_id INTEGER,
                      document_name TEXT,
                      fingerprint INTEGER,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY(scan_id) REFERENCES scan_history(id))''')
                      
        # PII Clusters
        c.execute('''CREATE TABLE IF NOT EXISTS pii_clusters
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scan_id INTEGER,
                      cluster_reason TEXT,
                      risk_multiplier REAL,
                      entity_types TEXT,
                      FOREIGN KEY(scan_id) REFERENCES scan_history(id))''')
                      
        # Compliance Policies
        c.execute('''CREATE TABLE IF NOT EXISTS compliance_policies
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      description_ar TEXT,
                      conditions_json TEXT NOT NULL,
                      severity TEXT CHECK(severity IN ('INFO','WARNING','CRITICAL','BLOCKER')),
                      remediation_ar TEXT,
                      is_active BOOLEAN DEFAULT 1,
                      created_by TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        # Policy Violations
        c.execute('''CREATE TABLE IF NOT EXISTS policy_violations
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      policy_id INTEGER REFERENCES compliance_policies(id),
                      scan_id INTEGER REFERENCES scan_history(id),
                      document_name TEXT,
                      violation_details TEXT,
                      status TEXT DEFAULT 'OPEN',
                      resolved_by TEXT,
                      resolved_at DATETIME,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        # Incident Management
        c.execute('''CREATE TABLE IF NOT EXISTS incidents
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      title TEXT NOT NULL,
                      description TEXT,
                      severity TEXT CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
                      status TEXT DEFAULT 'OPEN',
                      assigned_to TEXT,
                      source_type TEXT,
                      source_id INTEGER,
                      sla_deadline DATETIME,
                      resolved_at DATETIME,
                      resolution_notes TEXT,
                      created_by TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
                      
        c.execute('''CREATE TABLE IF NOT EXISTS incident_notes
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      incident_id INTEGER REFERENCES incidents(id),
                      note_text TEXT,
                      author TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
                      
        c.execute('''CREATE TABLE IF NOT EXISTS incident_evidence
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      incident_id INTEGER REFERENCES incidents(id),
                      scan_id INTEGER REFERENCES scan_history(id),
                      description TEXT)''')
                      
        # Scheduled Automated Scanning
        c.execute('''CREATE TABLE IF NOT EXISTS scheduled_tasks
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      directory_path TEXT NOT NULL,
                      cron_expression TEXT NOT NULL,
                      scan_strategy TEXT DEFAULT 'legal_mask',
                      is_enabled BOOLEAN DEFAULT 1,
                      last_run DATETIME,
                      last_run_files_count INTEGER,
                      last_run_violations INTEGER,
                      created_by TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
                      
        c.execute('''CREATE TABLE IF NOT EXISTS scan_manifest
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      task_id INTEGER REFERENCES scheduled_tasks(id),
                      file_path TEXT NOT NULL,
                      file_hash TEXT,
                      last_modified DATETIME,
                      last_scanned DATETIME)''')
                      
        # Data Retention Policies
        c.execute('''CREATE TABLE IF NOT EXISTS retention_policies
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      table_name TEXT NOT NULL,
                      retention_days INTEGER NOT NULL,
                      action TEXT DEFAULT 'DELETE',
                      is_active BOOLEAN DEFAULT 1)''')
                      
        c.execute('''CREATE TABLE IF NOT EXISTS retention_log
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      table_name TEXT,
                      records_deleted INTEGER,
                      execution_time DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        # Bulk Anonymization Templates
        c.execute('''CREATE TABLE IF NOT EXISTS anonymization_templates
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL UNIQUE,
                      strategy TEXT NOT NULL,
                      preset TEXT,
                      nlp_enabled BOOLEAN,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        # ===== PHASE 3: ADVANCED INTELLIGENCE TABLES =====
        
        # Feature #20 & #35: Cross-Document Entity Linking & Contextual Classification
        c.execute('''CREATE TABLE IF NOT EXISTS entity_index
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      entity_type TEXT NOT NULL,
                      entity_text TEXT NOT NULL,
                      entity_hash TEXT NOT NULL,
                      document_name TEXT,
                      scan_id INTEGER REFERENCES scan_history(id),
                      department TEXT,
                      context_snippet TEXT,
                      context_label TEXT,
                      context_keywords TEXT,
                      indexed_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        try:
            c.execute("ALTER TABLE entity_index ADD COLUMN context_label TEXT")
            c.execute("ALTER TABLE entity_index ADD COLUMN context_keywords TEXT")
        except:
            pass
            
        c.execute('CREATE INDEX IF NOT EXISTS idx_entity_hash ON entity_index(entity_hash)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_entity_type ON entity_index(entity_type)')
        
        # Feature #11: Multi-Department Isolation
        c.execute('''CREATE TABLE IF NOT EXISTS departments
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL UNIQUE,
                      description TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS user_departments
                     (user_id INTEGER REFERENCES users(id),
                      department_id INTEGER REFERENCES departments(id),
                      PRIMARY KEY (user_id, department_id))''')
                      
        # Feature #4: DSAR Manager
        c.execute('''CREATE TABLE IF NOT EXISTS dsar_requests
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      requester_name TEXT NOT NULL,
                      requester_contact TEXT,
                      subject_identity TEXT NOT NULL,
                      request_type TEXT DEFAULT 'ACCESS',
                      status TEXT DEFAULT 'OPEN',
                      assigned_to TEXT,
                      sla_deadline DATETIME,
                      entities_found INTEGER DEFAULT 0,
                      documents_affected INTEGER DEFAULT 0,
                      response_pdf_path TEXT,
                      resolution_notes TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                      resolved_at DATETIME)''')

        # Feature #19: Anomaly Detection
        c.execute('''CREATE TABLE IF NOT EXISTS anomaly_log
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      anomaly_type TEXT,
                      description TEXT,
                      severity TEXT,
                      scan_id INTEGER REFERENCES scan_history(id),
                      z_score REAL,
                      baseline_mean REAL,
                      observed_value REAL,
                      is_acknowledged BOOLEAN DEFAULT 0,
                      detected_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        # ===== PHASE 4: ENTERPRISE ECOSYSTEM TABLES =====
        
        # Feature #13: PIA Wizard
        c.execute('''CREATE TABLE IF NOT EXISTS pia_assessments
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      project_name TEXT NOT NULL,
                      department TEXT,
                      assessor_name TEXT,
                      data_types_json TEXT,
                      processing_purpose TEXT,
                      risk_level TEXT,
                      mitigation_steps TEXT,
                      status TEXT DEFAULT 'DRAFT',
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
                      
        # Feature #14: Consent Registry
        c.execute('''CREATE TABLE IF NOT EXISTS consent_registry
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      subject_id TEXT NOT NULL,
                      subject_name TEXT,
                      consent_type TEXT,
                      status TEXT CHECK(status IN ('OPT_IN', 'OPT_OUT')),
                      source TEXT,
                      expires_at DATETIME,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
                      
        # Feature #24: Secure Document Vault
        c.execute('''CREATE TABLE IF NOT EXISTS document_vault
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      original_filename TEXT NOT NULL,
                      vault_path TEXT NOT NULL,
                      encryption_iv TEXT NOT NULL,
                      uploaded_by TEXT,
                      department TEXT,
                      description TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        # Feature #22: Threat Intelligence Feed
        c.execute('''CREATE TABLE IF NOT EXISTS threat_intelligence
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      threat_name TEXT NOT NULL,
                      description_ar TEXT,
                      indicators_json TEXT,
                      severity TEXT,
                      remediation_ar TEXT,
                      source TEXT,
                      last_updated DATE)''')

        # Feature #28: Secure Inter-Department Document Transfer
        c.execute('''CREATE TABLE IF NOT EXISTS document_transfers
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      source_department_id INTEGER,
                      target_department_id INTEGER,
                      original_scan_id INTEGER,
                      anonymized_scan_id INTEGER,
                      strategy_used TEXT,
                      transfer_reason TEXT,
                      sender TEXT,
                      receiver TEXT,
                      status TEXT DEFAULT 'PENDING',
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        # Feature #32: Compliance Training Module
        c.execute('''CREATE TABLE IF NOT EXISTS training_quizzes
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      question_ar TEXT NOT NULL,
                      options_json TEXT NOT NULL,
                      correct_option INTEGER,
                      difficulty TEXT,
                      category TEXT)''')
                      
        c.execute('''CREATE TABLE IF NOT EXISTS training_results
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT,
                      quiz_ids TEXT,
                      score REAL,
                      passed BOOLEAN,
                      completed_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        # Feature #17: Custom Report Template Builder
        c.execute('''CREATE TABLE IF NOT EXISTS report_templates
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      description TEXT,
                      template_json TEXT NOT NULL,
                      logo_path TEXT,
                      is_default BOOLEAN DEFAULT 0,
                      created_by TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        self.conn.commit()
        
        # Check if admin exists
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            # Create default admin (password: admin)
            self.create_user("admin", "admin", "admin")

        # Initialize Default Labeling Policies
        self._init_default_labeling_policies()
        
        # Initialize Default Regulatory Mappings
        self._init_default_regulatory_mappings()

        # Initialize Default Threat Intel and Quizzes
        self._init_default_threat_intel()
        self._init_default_training_quizzes()
    def _init_default_regulatory_mappings(self):
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM regulatory_mappings")
        if c.fetchone()[0] == 0:
            mappings = [
                ("NIN", "قانون حماية البيانات الشخصية", "18-07", "المادة 12", "شروط المعالجة", "يجب أن تكون المعالجة مشروعة وموافقة للغرض.", "الحبس من سنة إلى 5 سنوات.", '["all"]'),
                ("NIN", "قانون حماية البيانات الشخصية", "18-07", "المادة 34", "حق الوصول", "يحق للشخص معرفة البيانات المعالجة عنه.", "غرامة مالية.", '["all"]'),
                ("RIB", "التجارة الإلكترونية", "18-05", "المادة 11", "سرية البيانات البنكية", "يمنع كشف أو تسريب بيانات الدفع والحسابات.", "الحبس ومصادرة المعدات.", '["banking", "ecommerce"]'),
                ("CCP", "التجارة الإلكترونية", "18-05", "المادة 11", "سرية البيانات البنكية", "يمنع كشف أو تسريب بيانات الدفع والحسابات.", "الحبس ومصادرة المعدات.", '["banking", "ecommerce"]'),
                ("IBAN", "التجارة الإلكترونية", "18-05", "المادة 11", "سرية البيانات البنكية", "يمنع كشف أو تسريب بيانات الدفع والحسابات.", "الحبس ومصادرة المعدات.", '["banking", "ecommerce"]')
            ]
            c.executemany('''INSERT INTO regulatory_mappings 
                             (entity_type, law_name, law_number, article_number, article_title_ar, article_summary_ar, penalty_description_ar, applicable_sectors) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', mappings)
            self.conn.commit()

    def _init_default_labeling_policies(self):
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM labeling_policies")
        if c.fetchone()[0] == 0:
            policies = [
                ("PUBLIC", "#2ea043", 0, 0, "[]", "عام", "Public"),
                ("INTERNAL", "#d29922", 1, 15, "[]", "داخلي", "Internal"),
                ("CONFIDENTIAL", "#f85149", 16, 40, "[]", "سري", "Confidential"),
                ("HIGHLY_CONFIDENTIAL", "#a00000", 41, 100, "[]", "سري جداً", "Highly Confidential"),
                ("TOP_SECRET", "#533483", 101, 999999, "[]", "سري للغاية", "Top Secret")
            ]
            c.executemany('''INSERT INTO labeling_policies 
                             (label_name, label_color, min_score, max_score, required_entity_types, description_ar, description_en) 
                             VALUES (?, ?, ?, ?, ?, ?, ?)''', policies)
            self.conn.commit()

    # --- USER MANAGEMENT ---
    
    def create_user(self, username: str, password: str, role: str) -> bool:
        """Creates a new user with bcrypt password hash."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        try:
            c = self.conn.cursor()
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                      (username, hashed, role))
            self.conn.commit()
            return True
        except sqlite.IntegrityError:
            return False # Username exists
            
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Authenticates user and returns (success, role, department_name)."""
        c = self.conn.cursor()
        c.execute("""
            SELECT u.password_hash, u.role, d.name 
            FROM users u
            LEFT JOIN user_departments ud ON u.id = ud.user_id
            LEFT JOIN departments d ON ud.department_id = d.id
            WHERE u.username=?
        """, (username,))
        row = c.fetchone()
        if not row:
            return False, None, None
            
        hashed_pw, role, dept = row
        if bcrypt.checkpw(password.encode('utf-8'), hashed_pw.encode('utf-8')):
            return True, role, dept
        return False, None, None
        
    def get_users(self) -> List[Dict]:
        """Returns list of users (excluding password hashes)."""
        c = self.conn.cursor()
        c.execute("SELECT username, role FROM users")
        return [{"username": r[0], "role": r[1]} for r in c.fetchall()]

    def delete_user(self, username: str) -> bool:
        c = self.conn.cursor()
        c.execute("DELETE FROM users WHERE username=? AND username!='admin'", (username,))
        self.conn.commit()
        return c.rowcount > 0

    # --- CUSTOM KEYWORDS ---
    
    def add_custom_keyword(self, keyword: str) -> bool:
        try:
            c = self.conn.cursor()
            c.execute("INSERT INTO custom_keywords (keyword) VALUES (?)", (keyword.strip(),))
            self.conn.commit()
            return True
        except sqlite.IntegrityError:
            return False
            
    def remove_custom_keyword(self, keyword: str) -> bool:
        c = self.conn.cursor()
        c.execute("DELETE FROM custom_keywords WHERE keyword=?", (keyword.strip(),))
        self.conn.commit()
        return c.rowcount > 0
        
    def get_custom_keywords(self) -> List[str]:
        c = self.conn.cursor()
        c.execute("SELECT keyword FROM custom_keywords")
        return [r[0] for r in c.fetchall()]

    # --- SCANS & SETTINGS ---

    def log_scan(self, document_name: str, total_entities: int, risk_level: str, strategy: str, summary: dict, sensitivity_label: str = 'UNCLASSIFIED', ocr_used: bool = False, duplicates_found: int = 0, department: str = None):
        c = self.conn.cursor()
        summary_str = self._encrypt_val(json.dumps(summary))
        doc_name_enc = self._encrypt_val(document_name)
        
        c.execute('''INSERT INTO scan_history 
                     (document_name, total_entities, risk_level, strategy_used, summary_json, sensitivity_label, ocr_used, duplicates_found, department)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                  (doc_name_enc, total_entities, risk_level, strategy, summary_str, sensitivity_label, ocr_used, duplicates_found, department))
        self.conn.commit()
        return c.lastrowid

    def get_scan_history(self, limit: int = 50, department: str = None) -> list:
        c = self.conn.cursor()
        if department:
            c.execute("SELECT id, timestamp, document_name, total_entities, risk_level, strategy_used, summary_json, sensitivity_label, ocr_used, duplicates_found, department FROM scan_history WHERE department=? ORDER BY timestamp DESC LIMIT ?", (department, limit))
        else:
            c.execute("SELECT id, timestamp, document_name, total_entities, risk_level, strategy_used, summary_json, sensitivity_label, ocr_used, duplicates_found, department FROM scan_history ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        
        decrypted_rows = []
        for r in rows:
            doc_name = self._decrypt_val(r[2])
            summary_dict = self._decrypt_val(r[6])
            # (id, timestamp, doc_name, total_entities, risk_level, strategy, summary, sensitivity_label, ocr_used, duplicates_found, department)
            decrypted_rows.append((r[0], r[1], doc_name, r[3], r[4], r[5], summary_dict, r[7], r[8], r[9], r[10]))
            
        return decrypted_rows

    def get_labeling_policies(self) -> List[Dict]:
        c = self.conn.cursor()
        c.execute("SELECT label_name, label_color, min_score, max_score, required_entity_types, description_ar, description_en FROM labeling_policies")
        rows = c.fetchall()
        return [
            {
                "label_name": r[0],
                "label_color": r[1],
                "min_score": r[2],
                "max_score": r[3],
                "required_entity_types": json.loads(r[4]) if r[4] else [],
                "description_ar": r[5],
                "description_en": r[6]
            }
            for r in rows
        ]
        
    def get_regulatory_mappings(self) -> List[Dict]:
        c = self.conn.cursor()
        c.execute("SELECT entity_type, law_name, law_number, article_number, article_title_ar, article_summary_ar, penalty_description_ar, applicable_sectors FROM regulatory_mappings WHERE is_active=1")
        rows = c.fetchall()
        return [
            {
                "entity_type": r[0],
                "law_name": r[1],
                "law_number": r[2],
                "article_number": r[3],
                "article_title_ar": r[4],
                "article_summary_ar": r[5],
                "penalty_description_ar": r[6],
                "applicable_sectors": json.loads(r[7]) if r[7] else []
            }
            for r in rows
        ]

    def save_setting(self, key: str, value):
        c = self.conn.cursor()
        val_str = json.dumps(value)
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, val_str))
        self.conn.commit()

    def get_setting(self, key: str, default=None):
        c = self.conn.cursor()
        c.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = c.fetchone()
        if row:
            return json.loads(row[0])
        return default

    def close(self):
        if self.conn:
            self.conn.close()

    # --- AUDIT LOG ---
    
    def log_audit(self, username: str, action: str, details: str = ""):
        """Records a timestamped audit trail entry."""
        try:
            c = self.conn.cursor()
            c.execute("INSERT INTO audit_log (username, action, details) VALUES (?, ?, ?)",
                      (username, action, details))
            self.conn.commit()
        except Exception as e:
            logging.error(f"Failed to write audit log: {e}")

    def get_audit_log(self, limit: int = 50) -> list:
        """Returns recent audit log entries."""
        c = self.conn.cursor()
        c.execute("SELECT timestamp, username, action, details FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
        return c.fetchall()

    # --- DOCUMENT FINGERPRINTS ---
    
    def save_fingerprint(self, scan_id: int, document_name: str, fingerprint: int):
        """Store a document fingerprint."""
        c = self.conn.cursor()
        c.execute("INSERT INTO document_fingerprints (scan_id, document_name, fingerprint) VALUES (?, ?, ?)",
                  (scan_id, document_name, fingerprint))
        self.conn.commit()

    def get_fingerprints(self) -> list:
        """Returns all stored fingerprints as list of (scan_id, document_name, fingerprint)."""
        c = self.conn.cursor()
        c.execute("SELECT scan_id, document_name, fingerprint FROM document_fingerprints")
        return c.fetchall()

    def get_last_scan_id(self) -> int:
        """Returns the ID of the most recently inserted scan."""
        c = self.conn.cursor()
        c.execute("SELECT MAX(id) FROM scan_history")
        row = c.fetchone()
        return row[0] if row and row[0] else 0

    # --- PII CLUSTERS ---
    
    def save_cluster(self, scan_id: int, reason: str, multiplier: float, entity_types: str):
        c = self.conn.cursor()
        c.execute("INSERT INTO pii_clusters (scan_id, cluster_reason, risk_multiplier, entity_types) VALUES (?, ?, ?, ?)",
                  (scan_id, reason, multiplier, entity_types))
        self.conn.commit()

    def get_clusters_for_scan(self, scan_id: int) -> list:
        c = self.conn.cursor()
        c.execute("SELECT cluster_reason, risk_multiplier, entity_types FROM pii_clusters WHERE scan_id=?", (scan_id,))
        return c.fetchall()

    # --- COMPLIANCE POLICIES & VIOLATIONS ---
    
    def save_compliance_policy(self, name: str, desc: str, conditions_json: str, severity: str, remediation: str, created_by: str):
        c = self.conn.cursor()
        c.execute('''INSERT INTO compliance_policies 
                     (name, description_ar, conditions_json, severity, remediation_ar, created_by) 
                     VALUES (?, ?, ?, ?, ?, ?)''', 
                  (name, desc, conditions_json, severity, remediation, created_by))
        self.conn.commit()
        
    def get_active_policies(self) -> list:
        c = self.conn.cursor()
        c.execute("SELECT id, name, description_ar, conditions_json, severity, remediation_ar FROM compliance_policies WHERE is_active=1")
        return c.fetchall()
        
    def log_policy_violation(self, policy_id: int, scan_id: int, document_name: str, details: str):
        c = self.conn.cursor()
        c.execute('''INSERT INTO policy_violations 
                     (policy_id, scan_id, document_name, violation_details) 
                     VALUES (?, ?, ?, ?)''', 
                  (policy_id, scan_id, document_name, details))
        self.conn.commit()
        
    def get_open_violations(self) -> list:
        c = self.conn.cursor()
        c.execute('''SELECT v.id, p.name, p.severity, v.document_name, v.violation_details, v.created_at, v.scan_id
                     FROM policy_violations v 
                     JOIN compliance_policies p ON v.policy_id = p.id 
                     WHERE v.status='OPEN' ORDER BY v.created_at DESC''')
        return c.fetchall()
        
    def resolve_violation(self, violation_id: int, resolved_by: str):
        c = self.conn.cursor()
        c.execute('''UPDATE policy_violations 
                     SET status='RESOLVED', resolved_by=?, resolved_at=CURRENT_TIMESTAMP 
                     WHERE id=?''', (resolved_by, violation_id))
        self.conn.commit()
        
    # --- INCIDENT MANAGEMENT ---
    
    def create_incident(self, title: str, description: str, severity: str, source_type: str, source_id: int, created_by: str) -> int:
        c = self.conn.cursor()
        
        # Calculate SLA based on severity
        sla_hours = {"CRITICAL": 4, "HIGH": 24, "MEDIUM": 72, "LOW": 168}.get(severity, 24)
        c.execute('''INSERT INTO incidents 
                     (title, description, severity, source_type, source_id, created_by, sla_deadline) 
                     VALUES (?, ?, ?, ?, ?, ?, datetime('now', '+' || ? || ' hours'))''', 
                  (title, description, severity, source_type, source_id, created_by, sla_hours))
        self.conn.commit()
        return c.lastrowid
        
    def get_incidents(self) -> list:
        c = self.conn.cursor()
        c.execute('''SELECT id, title, description, severity, status, assigned_to, 
                            source_type, sla_deadline, created_at 
                     FROM incidents ORDER BY created_at DESC''')
        return c.fetchall()
        
    def update_incident_status(self, incident_id: int, status: str, assigned_to: str = None, resolution_notes: str = None):
        c = self.conn.cursor()
        updates = ["status=?"]
        params = [status]
        
        if assigned_to:
            updates.append("assigned_to=?")
            params.append(assigned_to)
            
        if status == 'CLOSED':
            updates.append("resolved_at=CURRENT_TIMESTAMP")
            if resolution_notes:
                updates.append("resolution_notes=?")
                params.append(resolution_notes)
                
        c.execute(f"UPDATE incidents SET {','.join(updates)} WHERE id=?", (*params, incident_id))
        self.conn.commit()

    # --- SCHEDULED TASKS ---
    
    def save_scheduled_task(self, name: str, directory_path: str, cron_expression: str, scan_strategy: str, created_by: str):
        c = self.conn.cursor()
        c.execute('''INSERT INTO scheduled_tasks 
                     (name, directory_path, cron_expression, scan_strategy, created_by) 
                     VALUES (?, ?, ?, ?, ?)''', 
                  (name, directory_path, cron_expression, scan_strategy, created_by))
        self.conn.commit()
        
    def get_scheduled_tasks(self) -> list:
        c = self.conn.cursor()
        c.execute('''SELECT id, name, directory_path, cron_expression, scan_strategy, 
                            is_enabled, last_run, last_run_files_count, last_run_violations 
                     FROM scheduled_tasks ORDER BY created_at DESC''')
        return c.fetchall()
        
    def update_task_last_run(self, task_id: int, files_count: int, violations: int):
        c = self.conn.cursor()
        c.execute('''UPDATE scheduled_tasks 
                     SET last_run=CURRENT_TIMESTAMP, last_run_files_count=?, last_run_violations=? 
                     WHERE id=?''', (files_count, violations, task_id))
        self.conn.commit()
        
    def get_scan_manifest(self, task_id: int) -> dict:
        """Returns dict mapping file_path to last_modified timestamp string."""
        c = self.conn.cursor()
        c.execute("SELECT file_path, last_modified FROM scan_manifest WHERE task_id=?", (task_id,))
        return {row[0]: row[1] for row in c.fetchall()}
        
    def update_scan_manifest(self, task_id: int, file_path: str, file_hash: str, last_modified: str):
        c = self.conn.cursor()
        # Insert or replace
        c.execute("SELECT id FROM scan_manifest WHERE task_id=? AND file_path=?", (task_id, file_path))
        row = c.fetchone()
        if row:
            c.execute("UPDATE scan_manifest SET file_hash=?, last_modified=?, last_scanned=CURRENT_TIMESTAMP WHERE id=?", (file_hash, last_modified, row[0]))
        else:
            c.execute("INSERT INTO scan_manifest (task_id, file_path, file_hash, last_modified, last_scanned) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)", 
                      (task_id, file_path, file_hash, last_modified))
        self.conn.commit()

    # --- RETENTION POLICIES ---
    
    def run_retention_purge(self):
        """Purges old records according to retention_policies table."""
        c = self.conn.cursor()
        c.execute("SELECT table_name, retention_days, action FROM retention_policies WHERE is_active=1")
        policies = c.fetchall()
        
        for table, days, action in policies:
            # Only allow specific tables to prevent SQL injection
            allowed_tables = ['scan_history', 'audit_log', 'policy_violations', 'incidents']
            if table not in allowed_tables:
                continue
                
            try:
                # Use strftime and date logic for sqlite
                query = f"DELETE FROM {table} WHERE created_at < datetime('now', '-{days} days')"
                c.execute(query)
                deleted_count = c.rowcount
                if deleted_count > 0:
                    c.execute("INSERT INTO retention_log (table_name, records_deleted) VALUES (?, ?)", (table, deleted_count))
            except Exception as e:
                import logging
                logging.error(f"Retention purge failed for {table}: {e}")
                
        self.conn.commit()
        
    def save_retention_policy(self, table_name: str, days: int, action: str = 'DELETE'):
        c = self.conn.cursor()
        # Upsert
        c.execute("SELECT id FROM retention_policies WHERE table_name=?", (table_name,))
        if c.fetchone():
            c.execute("UPDATE retention_policies SET retention_days=?, action=?, is_active=1 WHERE table_name=?", (days, action, table_name))
        else:
            c.execute("INSERT INTO retention_policies (table_name, retention_days, action) VALUES (?, ?, ?)", (table_name, days, action))
        self.conn.commit()
        
    def get_retention_policies(self) -> dict:
        c = self.conn.cursor()
        c.execute("SELECT table_name, retention_days FROM retention_policies WHERE is_active=1")
        return {row[0]: row[1] for row in c.fetchall()}

    # --- ANONYMIZATION TEMPLATES ---
    
    def save_template(self, name: str, strategy: str, preset: str, nlp_enabled: bool):
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO anonymization_templates (name, strategy, preset, nlp_enabled) VALUES (?, ?, ?, ?)", 
                  (name, strategy, preset, nlp_enabled))
        self.conn.commit()
        
    def get_templates(self) -> list:
        c = self.conn.cursor()
        c.execute("SELECT id, name, strategy, preset, nlp_enabled FROM anonymization_templates")
        return c.fetchall()

    # ===== PHASE 3: ADVANCED INTELLIGENCE METHODS =====

    # --- Feature #20 & #35: Entity Indexing & Contextual Classification ---
    def index_entities(self, scan_id: int, document_name: str, entities: list, department: str = None):
        c = self.conn.cursor()
        import hashlib
        for ent in entities:
            # We encrypt the text to avoid raw PII in the DB
            enc_text = self._encrypt_val(ent.text)
            # Create a deterministic hash for cross-linking (use raw text, lowercased to group case variants)
            ent_hash = hashlib.sha256(ent.text.lower().encode('utf-8')).hexdigest()
            
            context_label = getattr(ent, 'context_label', 'GENERAL')
            context_keywords = getattr(ent, 'context_keywords', '')
            
            c.execute('''INSERT INTO entity_index 
                         (entity_type, entity_text, entity_hash, document_name, scan_id, department, context_label, context_keywords) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (ent.entity_type, enc_text, ent_hash, document_name, scan_id, department, context_label, context_keywords))
        self.conn.commit()

    def find_cross_linked_entities(self) -> list:
        """Find entities that appear in multiple different documents."""
        c = self.conn.cursor()
        # Find hashes that appear in > 1 distinct document
        c.execute('''SELECT entity_hash, entity_type, COUNT(DISTINCT document_name) as doc_count 
                     FROM entity_index 
                     GROUP BY entity_hash 
                     HAVING doc_count > 1 
                     ORDER BY doc_count DESC LIMIT 100''')
        results = []
        for row in c.fetchall():
            ent_hash, ent_type, count = row
            # Get the actual documents and encrypted texts
            c.execute('SELECT document_name, entity_text FROM entity_index WHERE entity_hash=?', (ent_hash,))
            docs = c.fetchall()
            decrypted_text = self._decrypt_val(docs[0][1]) if docs else "Unknown"
            doc_names = list(set([d[0] for d in docs]))
            results.append({
                'entity_type': ent_type,
                'entity_text': decrypted_text,
                'document_count': count,
                'documents': doc_names
            })
        return results

    # --- Feature #11: Departments ---
    def save_department(self, name: str, description: str = ""):
        c = self.conn.cursor()
        c.execute("INSERT OR IGNORE INTO departments (name, description) VALUES (?, ?)", (name, description))
        self.conn.commit()

    def get_departments(self) -> list:
        c = self.conn.cursor()
        c.execute("SELECT id, name, description FROM departments")
        return c.fetchall()

    def assign_user_to_department(self, user_id: int, department_id: int):
        c = self.conn.cursor()
        c.execute("INSERT OR IGNORE INTO user_departments (user_id, department_id) VALUES (?, ?)", (user_id, department_id))
        self.conn.commit()

    def get_user_departments(self, user_id: int) -> list:
        c = self.conn.cursor()
        c.execute('''SELECT d.name FROM departments d 
                     JOIN user_departments ud ON d.id = ud.department_id 
                     WHERE ud.user_id=?''', (user_id,))
        return [r[0] for r in c.fetchall()]

    # --- Feature #4: DSAR Manager ---
    def create_dsar_request(self, requester: str, contact: str, subject: str, req_type: str = 'ACCESS') -> int:
        c = self.conn.cursor()
        enc_subject = self._encrypt_val(subject)
        enc_requester = self._encrypt_val(requester)
        enc_contact = self._encrypt_val(contact)
        c.execute('''INSERT INTO dsar_requests 
                     (requester_name, requester_contact, subject_identity, request_type, sla_deadline) 
                     VALUES (?, ?, ?, ?, datetime('now', '+30 days'))''',
                  (enc_requester, enc_contact, enc_subject, req_type))
        self.conn.commit()
        return c.lastrowid

    def get_dsar_requests(self) -> list:
        c = self.conn.cursor()
        c.execute("SELECT id, requester_name, subject_identity, request_type, status, sla_deadline FROM dsar_requests")
        results = []
        for row in c.fetchall():
            results.append({
                'id': row[0],
                'requester_name': self._decrypt_val(row[1]),
                'subject_identity': self._decrypt_val(row[2]),
                'request_type': row[3],
                'status': row[4],
                'sla_deadline': row[5]
            })
        return results

    def update_dsar_status(self, req_id: int, status: str, resolution_notes: str = ""):
        c = self.conn.cursor()
        if status == 'CLOSED':
            c.execute("UPDATE dsar_requests SET status=?, resolution_notes=?, resolved_at=CURRENT_TIMESTAMP WHERE id=?", 
                      (status, resolution_notes, req_id))
        else:
            c.execute("UPDATE dsar_requests SET status=?, resolution_notes=? WHERE id=?", 
                      (status, resolution_notes, req_id))
        self.conn.commit()

    # --- Feature #19: Anomaly Detection ---
    def log_anomaly(self, anomaly_type: str, desc: str, severity: str, scan_id: int, z_score: float, mean: float, obs: float):
        c = self.conn.cursor()
        c.execute('''INSERT INTO anomaly_log 
                     (anomaly_type, description, severity, scan_id, z_score, baseline_mean, observed_value) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (anomaly_type, desc, severity, scan_id, z_score, mean, obs))
        self.conn.commit()

    def get_unacknowledged_anomalies(self) -> list:
        c = self.conn.cursor()
        c.execute("SELECT id, anomaly_type, description, severity, z_score, detected_at FROM anomaly_log WHERE is_acknowledged=0")
        return c.fetchall()

    def acknowledge_anomaly(self, anomaly_id: int):
        c = self.conn.cursor()
        c.execute("UPDATE anomaly_log SET is_acknowledged=1 WHERE id=?", (anomaly_id,))
        self.conn.commit()

    # --- Feature #22: Threat Intelligence ---
    def _init_default_threat_intel(self):
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM threat_intelligence")
        if c.fetchone()[0] == 0:
            threats = [
                ("تسريب هويات متعددة (Bulk Identity Leak)", "اكتشاف أرقام تعريف وطنية متعددة في ملف واحد، مما يدل على قاعدة بيانات عملاء.", '["NIN"]', "HIGH", "التحقق من صلاحية وصول المستخدم وحذف الملف إذا لم يكن ضرورياً.", "Alg-PII Threat Feed", "2024-03-20"),
                ("بيانات دفع غير مشفرة (Unencrypted Payment Data)", "اكتشاف أرقام RIB أو CCP مكشوفة.", '["RIB", "CCP"]', "CRITICAL", "تشفير الملف فوراً أو إخفاء الأرقام.", "Alg-PII Threat Feed", "2024-03-20"),
            ]
            c.executemany('''INSERT INTO threat_intelligence 
                             (threat_name, description_ar, indicators_json, severity, remediation_ar, source, last_updated) 
                             VALUES (?, ?, ?, ?, ?, ?, ?)''', threats)
            self.conn.commit()

    def get_threat_intel(self) -> list:
        c = self.conn.cursor()
        c.execute("SELECT id, threat_name, description_ar, indicators_json, severity, remediation_ar, source FROM threat_intelligence")
        results = []
        for row in c.fetchall():
            results.append({
                'id': row[0],
                'threat_name': row[1],
                'description_ar': row[2],
                'indicators': json.loads(row[3]) if row[3] else [],
                'severity': row[4],
                'remediation_ar': row[5],
                'source': row[6]
            })
        return results

    # --- Feature #32: Compliance Training ---
    def _init_default_training_quizzes(self):
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM training_quizzes")
        if c.fetchone()[0] == 0:
            import json
            quizzes = [
                ("ما هو القانون الجزائري الذي يحمي البيانات الشخصية؟", json.dumps(["قانون 18-05", "قانون 18-07", "قانون 09-04", "قانون 15-02"]), 1, "Easy", "Law 18-07"),
                ("ما هي العقوبة القصوى لتسريب البيانات البنكية حسب المادة 11 من قانون التجارة الإلكترونية؟", json.dumps(["غرامة مالية فقط", "الحبس من 6 أشهر إلى سنة", "الحبس ومصادرة المعدات", "لا توجد عقوبة"]), 2, "Medium", "Law 18-05"),
                ("هل رقم التعريف الوطني (NIN) يعتبر بيانات حساسة؟", json.dumps(["نعم، ويجب تشفيره", "لا، هو متاح للعموم", "فقط إذا كان مرفقاً بالاسم", "حسب القطاع"]), 0, "Easy", "General")
            ]
            c.executemany("INSERT INTO training_quizzes (question_ar, options_json, correct_option, difficulty, category) VALUES (?, ?, ?, ?, ?)", quizzes)
            self.conn.commit()

    def get_training_quizzes(self) -> list:
        c = self.conn.cursor()
        c.execute("SELECT id, question_ar, options_json, correct_option, difficulty, category FROM training_quizzes")
        return c.fetchall()

    def save_training_result(self, username: str, quiz_ids: str, score: float, passed: bool):
        c = self.conn.cursor()
        c.execute("INSERT INTO training_results (username, quiz_ids, score, passed) VALUES (?, ?, ?, ?)", 
                  (username, quiz_ids, score, passed))
        self.conn.commit()

    def get_training_results(self, username: str = None) -> list:
        c = self.conn.cursor()
        if username:
            c.execute("SELECT id, username, score, passed, completed_at FROM training_results WHERE username=? ORDER BY completed_at DESC", (username,))
        else:
            c.execute("SELECT id, username, score, passed, completed_at FROM training_results ORDER BY completed_at DESC")
        return c.fetchall()

    # --- Feature #28: Document Transfers ---
    def create_transfer(self, source_dept: int, target_dept: int, orig_scan: int, anon_scan: int, strategy: str, reason: str, sender: str, receiver: str):
        c = self.conn.cursor()
        c.execute('''INSERT INTO document_transfers 
                     (source_department_id, target_department_id, original_scan_id, anonymized_scan_id, strategy_used, transfer_reason, sender, receiver) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (source_dept, target_dept, orig_scan, anon_scan, strategy, reason, sender, receiver))
        self.conn.commit()
        return c.lastrowid

    def get_transfers(self, department_id: int = None) -> list:
        c = self.conn.cursor()
        if department_id:
            c.execute('''SELECT t.id, d1.name, d2.name, t.original_scan_id, t.anonymized_scan_id, t.strategy_used, 
                                t.transfer_reason, t.sender, t.receiver, t.status, t.created_at 
                         FROM document_transfers t
                         LEFT JOIN departments d1 ON t.source_department_id = d1.id
                         LEFT JOIN departments d2 ON t.target_department_id = d2.id
                         WHERE t.source_department_id=? OR t.target_department_id=? ORDER BY t.created_at DESC''', 
                      (department_id, department_id))
        else:
            c.execute('''SELECT t.id, d1.name, d2.name, t.original_scan_id, t.anonymized_scan_id, t.strategy_used, 
                                t.transfer_reason, t.sender, t.receiver, t.status, t.created_at 
                         FROM document_transfers t
                         LEFT JOIN departments d1 ON t.source_department_id = d1.id
                         LEFT JOIN departments d2 ON t.target_department_id = d2.id
                         ORDER BY t.created_at DESC''')
        return c.fetchall()

    def update_transfer_status(self, transfer_id: int, status: str):
        c = self.conn.cursor()
        c.execute("UPDATE document_transfers SET status=? WHERE id=?", (status, transfer_id))
        self.conn.commit()

    # --- Feature #18: Data Flow Mapping ---
    def get_data_flow_stats(self) -> dict:
        c = self.conn.cursor()
        # Source to target transfers
        c.execute('''SELECT d1.name, d2.name, COUNT(*) 
                     FROM document_transfers t
                     JOIN departments d1 ON t.source_department_id = d1.id
                     JOIN departments d2 ON t.target_department_id = d2.id
                     GROUP BY d1.name, d2.name''')
        transfers = c.fetchall()
        
        # Scans per department
        c.execute("SELECT department, COUNT(*) FROM scan_history WHERE department IS NOT NULL GROUP BY department")
        scans = c.fetchall()
        
        return {"transfers": transfers, "scans": scans}

    # --- Feature #17: Report Templates ---
    def save_report_template(self, name: str, desc: str, template_json: str, logo_path: str, is_default: bool, created_by: str):
        c = self.conn.cursor()
        if is_default:
            c.execute("UPDATE report_templates SET is_default=0")
        c.execute('''INSERT INTO report_templates (name, description, template_json, logo_path, is_default, created_by) 
                     VALUES (?, ?, ?, ?, ?, ?)''', (name, desc, template_json, logo_path, is_default, created_by))
        self.conn.commit()

    def get_report_templates(self) -> list:
        c = self.conn.cursor()
        c.execute("SELECT id, name, description, template_json, logo_path, is_default, created_by, created_at FROM report_templates ORDER BY is_default DESC, created_at DESC")
        return c.fetchall()

    def delete_report_template(self, template_id: int):
        c = self.conn.cursor()
        c.execute("DELETE FROM report_templates WHERE id=?", (template_id,))
        self.conn.commit()

    # --- Feature #21: Compliance Calendar ---
    def get_calendar_deadlines(self, month: int, year: int) -> list:
        c = self.conn.cursor()
        start_date = f"{year}-{month:02d}-01"
        if month == 12:
            end_date = f"{year+1}-01-01"
        else:
            end_date = f"{year}-{month+1:02d}-01"
            
        deadlines = []
        
        # DSAR SLAs
        c.execute("SELECT requester_name, sla_deadline, status FROM dsar_requests WHERE sla_deadline >= ? AND sla_deadline < ?", (start_date, end_date))
        for r in c.fetchall():
            req_name = self._decrypt_val(r[0]) if r[0] else ""
            deadlines.append({"title": f"DSAR Request: {req_name}", "date": r[1], "status": r[2], "type": "DSAR"})
            
        # Incident SLAs
        c.execute("SELECT 'Incident: ' || title, sla_deadline, status FROM incidents WHERE sla_deadline >= ? AND sla_deadline < ?", (start_date, end_date))
        for r in c.fetchall():
            deadlines.append({"title": r[0], "date": r[1], "status": r[2], "type": "Incident"})
            
        return deadlines
