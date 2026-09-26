import os
import hashlib
import time
from datetime import datetime
from PyQt6.QtCore import QThread, pyqtSignal
from storage.secure_db import SecureDatabase
from engine.compliance_engine import AlgComplianceEngine
from engine.document_parser import DocumentParser

class TaskScheduler(QThread):
    """
    Background thread that monitors scheduled tasks and executes delta scans.
    """
    task_started = pyqtSignal(str) # Task name
    task_finished = pyqtSignal(str, int, int) # Task name, files processed, violations
    
    def __init__(self, db: SecureDatabase, engine: AlgComplianceEngine, parent=None):
        super().__init__(parent)
        self.db = db
        self.engine = engine
        self._is_running = True
        
    def stop(self):
        self._is_running = False
        
    def _compute_file_hash(self, filepath: str) -> str:
        hasher = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                buf = f.read(65536)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = f.read(65536)
            return hasher.hexdigest()
        except Exception:
            return ""
            
    def _should_run_task(self, task_data: tuple) -> bool:
        # Simplification for MVP: We check if it hasn't run in the last 24h
        # Real implementation would use croniter(cron_expr)
        last_run = task_data[6] # last_run DATETIME
        if not last_run:
            return True
            
        try:
            # SQLite format: YYYY-MM-DD HH:MM:SS
            if isinstance(last_run, str):
                dt = datetime.strptime(last_run.split('.')[0], "%Y-%m-%d %H:%M:%S")
            else:
                dt = last_run
                
            delta = datetime.now() - dt
            # If cron is daily, run if > 23 hours
            return delta.total_seconds() > 23 * 3600
        except Exception:
            return True

    def run(self):
        iterations = 0
        while self._is_running:
            try:
                # Run retention purge once an hour (every 60 iterations of 1 minute)
                if iterations % 60 == 0:
                    self.db.run_retention_purge()
                    
                tasks = self.db.get_scheduled_tasks()
                for task in tasks:
                    if not self._is_running:
                        break
                        
                    task_id, name, path, cron, strategy, enabled = task[0:6]
                    if not enabled:
                        continue
                        
                    if self._should_run_task(task):
                        self.task_started.emit(name)
                        self._execute_task(task_id, name, path, strategy)
            except Exception as e:
                import logging
                logging.error(f"Scheduler error: {e}")
                
            iterations += 1
            # Sleep for 1 minute
            for _ in range(60):
                if not self._is_running:
                    break
                time.sleep(1)
                
    def _execute_task(self, task_id: int, name: str, directory_path: str, strategy: str):
        if not os.path.exists(directory_path):
            return
            
        manifest = self.db.get_scan_manifest(task_id)
        supported_exts = ('.txt', '.pdf', '.docx', '.xlsx', '.csv', '.png', '.jpg', '.eml', '.msg')
        
        files_processed = 0
        violations_found = 0
        
        from engine.policy_engine import PolicyEngine
        policy_engine = PolicyEngine(self.db)
        
        for root, _, files in os.walk(directory_path):
            for f in files:
                if not self._is_running:
                    return
                    
                if f.lower().endswith(supported_exts):
                    file_path = os.path.join(root, f)
                    
                    try:
                        mtime = str(os.path.getmtime(file_path))
                    except Exception:
                        continue
                        
                    # Delta check
                    if file_path in manifest and manifest[file_path] == mtime:
                        continue # Unchanged
                        
                    file_hash = self._compute_file_hash(file_path)
                    
                    # Scan file
                    try:
                        text, ocr_used = DocumentParser.extract_text(file_path)
                        if text.strip():
                            res = self.engine.anonymize(text, strategy)
                            report = self.engine.generate_report(res.scan_result)
                            
                            violations = policy_engine.evaluate(res.scan_result, f)
                            if violations:
                                violations_found += len(violations)
                                
                                # Log it all
                                self.db.log_scan(f, len(res.entities), report.risk_level, strategy, {}, report.sensitivity_label, ocr_used, 0)
                                scan_id = self.db.get_last_scan_id()
                                
                                # Index for cross-linking
                                from engine.cross_linker import CrossLinker
                                cross_linker = CrossLinker(self.db)
                                cross_linker.index_scan_result(scan_id, f, res.entities)
                                
                                for v in violations:
                                    self.db.log_policy_violation(v.policy_id, scan_id, f, v.details)
                                    if v.severity in ["CRITICAL", "BLOCKER", "HIGH"]:
                                        mapped_sev = "CRITICAL" if v.severity == "BLOCKER" else v.severity
                                        self.db.create_incident(f"Scheduled Task Violation: {v.name}", v.details, mapped_sev, "scheduled_scan", scan_id, "system")
                                        
                                # Run Anomaly Detection
                                from engine.anomaly_detector import AnomalyDetector
                                anomaly_detector = AnomalyDetector(self.db)
                                anomaly_detector.analyze_scan(scan_id, len(res.entities))
                                
                        files_processed += 1
                        self.db.update_scan_manifest(task_id, file_path, file_hash, mtime)
                    except Exception as e:
                        import logging
                        logging.error(f"Scheduled scan failed for {file_path}: {e}")
                        
        self.db.update_task_last_run(task_id, files_processed, violations_found)
        self.task_finished.emit(name, files_processed, violations_found)
