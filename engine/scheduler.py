import os
import hashlib
import time
import logging
import threading
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
    task_finished = pyqtSignal(str, int, int, int) # Task name, files processed, violations, failed files
    
    def __init__(self, db: SecureDatabase, engine: AlgComplianceEngine, parent=None):
        super().__init__(parent)
        self._db_path = db.db_path
        self.db = None
        self.engine = engine
        self._is_running = True
        self._scheduler_lock = threading.Lock()
        self._manual_run_ids = set()
        self._active_task_ids = set()
        self._wake_event = threading.Event()
        
    def stop(self):
        self._is_running = False
        self._wake_event.set()

    def request_task_run(self, task_id: int) -> bool:
        """Queue an enabled task for an immediate scheduler-thread run."""
        if not self._is_running or not self.isRunning():
            return False
        with self._scheduler_lock:
            if task_id in self._active_task_ids or task_id in self._manual_run_ids:
                return False
            self._manual_run_ids.add(task_id)
        self._wake_event.set()
        return True

    def _consume_manual_run(self, task_id: int) -> bool:
        with self._scheduler_lock:
            if task_id in self._manual_run_ids:
                self._manual_run_ids.remove(task_id)
                return True
            return False
        
    def _compute_file_hash(self, filepath: str) -> str:
        hasher = hashlib.sha256()
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
        try:
            from croniter import croniter
            now = datetime.now()
            last_run = task_data[6]
            base_time = last_run or task_data[9]
            if not base_time:
                return False
            if isinstance(base_time, str):
                base_time = datetime.strptime(base_time.split('.')[0], "%Y-%m-%d %H:%M:%S")
            due_at = croniter(task_data[3], base_time).get_next(datetime)
            return due_at <= now
        except Exception as exc:
            logging.error("Invalid schedule for task %s: %s", task_data[1], exc)
            return False

    def run(self):
        try:
            self.db = SecureDatabase(self._db_path)
        except Exception:
            logging.exception("Could not open scheduler database")
            self._is_running = False
            return
        recovered = self.db.recover_interrupted_scheduled_tasks()
        if recovered:
            logging.warning("Cleared %s abandoned scheduled-task run claim(s)", recovered)
        iterations = 0
        try:
            while self._is_running:
                try:
                    if iterations % 60 == 0:
                        self.db.run_retention_purge()
                    if iterations % 60 == 0:
                        self._run_automatic_backup_if_due()

                    tasks = self.db.get_scheduled_tasks()
                    task_ids = {task[0] for task in tasks}
                    with self._scheduler_lock:
                        self._manual_run_ids.intersection_update(task_ids)
                    for task in tasks:
                        if not self._is_running:
                            break
                        task_id, name, path, cron, strategy, enabled = task[0:6]
                        manual_requested = self._consume_manual_run(task_id)
                        if enabled and (manual_requested or self._should_run_task(task)) and self.db.mark_scheduled_task_started(task_id):
                            with self._scheduler_lock:
                                self._active_task_ids.add(task_id)
                            self.task_started.emit(name)
                            department = task[10] if len(task) > 10 else None
                            try:
                                self._execute_task(task_id, name, path, strategy, department)
                            except Exception as exc:
                                logging.exception("Scheduled task %s failed (%s)", name, type(exc).__name__)
                                self.db.update_task_last_run(task_id, 0, 0, "FAILED", 1)
                                self.task_finished.emit(name, 0, 0, 1)
                            finally:
                                self.db.clear_scheduled_task_run(task_id)
                                with self._scheduler_lock:
                                    self._active_task_ids.discard(task_id)
                                    self._manual_run_ids.discard(task_id)
                except Exception:
                    logging.exception("Scheduler error")

                iterations += 1
                for _ in range(60):
                    if not self._is_running:
                        break
                    if self._wake_event.wait(1):
                        self._wake_event.clear()
                        with self._scheduler_lock:
                            if self._manual_run_ids:
                                break
        finally:
            if self.db:
                self.db.close()
                self.db = None

    def _run_automatic_backup_if_due(self):
        """Create a scheduled encrypted backup and rotate only app-created files."""
        try:
            if not self.db.get_setting("auto_backup_enabled", False):
                return
            configured_directory = self.db.get_setting("auto_backup_dir", "")
            if not configured_directory or not str(configured_directory).strip():
                return
            directory = os.path.abspath(str(configured_directory).strip())
            interval_days = max(1, min(int(self.db.get_setting("auto_backup_interval_days", 1)), 365))
            keep_count = max(1, min(int(self.db.get_setting("auto_backup_keep_count", 7)), 100))
            now = datetime.now()
            last_value = self.db.get_setting("auto_backup_last_run", "")
            if last_value:
                try:
                    last_run = datetime.fromisoformat(last_value)
                    if (now - last_run).total_seconds() < interval_days * 86400:
                        return
                except (TypeError, ValueError):
                    logging.warning("Invalid automatic backup timestamp; creating a fresh backup")

            from storage.backup_manager import SecureBackupManager
            os.makedirs(directory, exist_ok=True)
            filename = f"AlgPII-auto-{now.strftime('%Y%m%d-%H%M%S')}.apibak"
            destination = os.path.join(directory, filename)
            if os.path.exists(destination):
                filename = f"AlgPII-auto-{now.strftime('%Y%m%d-%H%M%S')}-{int(time.time())}.apibak"
                destination = os.path.join(directory, filename)
            result = SecureBackupManager.create_backup(self.db, destination)

            self.db.save_setting("auto_backup_last_run", now.isoformat(timespec="seconds"))
            self.db.log_audit("system", "AUTO_BACKUP_SUCCESS", f"Encrypted automatic backup created: {filename} ({result['size']} bytes).")

            managed_files = sorted(
                os.path.join(directory, name)
                for name in os.listdir(directory)
                if name.startswith("AlgPII-auto-") and name.endswith(".apibak") and os.path.isfile(os.path.join(directory, name))
            )
            for old_path in managed_files[:-keep_count]:
                try:
                    os.remove(old_path)
                except OSError:
                    logging.exception("Could not rotate automatic backup %s", old_path)
        except Exception as exc:
            logging.exception("Automatic encrypted backup failed")
            try:
                self.db.log_audit("system", "AUTO_BACKUP_FAILURE", f"Automatic encrypted backup failed: {type(exc).__name__}.")
            except Exception:
                logging.exception("Could not record automatic backup failure")
                
    def _execute_task(self, task_id: int, name: str, directory_path: str, strategy: str, department: str = None):
        if not os.path.exists(directory_path):
            self.db.update_task_last_run(task_id, 0, 0, "FAILED", 1)
            self.task_finished.emit(name, 0, 0, 1)
            return
            
        manifest = self.db.get_scan_manifest(task_id)
        supported_exts = ('.txt', '.pdf', '.docx', '.xlsx', '.csv', '.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.eml', '.msg')
        
        files_processed = 0
        violations_found = 0
        files_failed = 0
        
        from engine.policy_engine import PolicyEngine
        policy_engine = PolicyEngine(self.db)
        
        for root, _, files in os.walk(directory_path):
            for f in files:
                if not self._is_running:
                    self.db.update_task_last_run(task_id, files_processed, violations_found, "INTERRUPTED", files_failed)
                    self.task_finished.emit(name, files_processed, violations_found, files_failed)
                    return
                    
                if f.lower().endswith(supported_exts):
                    file_path = os.path.join(root, f)
                    
                    try:
                        mtime = str(os.stat(file_path).st_mtime_ns)
                    except Exception:
                        files_failed += 1
                        continue
                        
                    file_hash = self._compute_file_hash(file_path)
                    prior_hash, prior_mtime = manifest.get(file_path, (None, None))
                    if prior_hash == file_hash:
                        if prior_mtime != mtime:
                            self.db.update_scan_manifest(task_id, file_path, file_hash, mtime)
                            manifest[file_path] = (file_hash, mtime)
                        continue
                    
                    # Scan file
                    try:
                        text, ocr_used = DocumentParser.extract_text(file_path)
                        if not text.strip():
                            raise ValueError("لم يُستخرج نص من الملف المدعوم.")
                        if text.strip():
                            res = self.engine.anonymize(text, strategy)
                            report = self.engine.generate_report(res.scan_result)
                            
                            violations = policy_engine.evaluate(res.scan_result, f)
                            violations_found += len(violations)
                            counts = {}
                            for entity in res.entities:
                                counts[entity.entity_type] = counts.get(entity.entity_type, 0) + 1
                            from engine.fingerprint import FingerprintEngine
                            fingerprint_engine = FingerprintEngine(self.db)
                            fingerprint = fingerprint_engine.compute_fingerprint(text)
                            duplicates = fingerprint_engine.find_duplicates(
                                fingerprint, department=department
                            ) if department else fingerprint_engine.find_duplicates(fingerprint)
                            self.db.log_scan(
                                f, len(res.entities), report.risk_level, strategy, counts,
                                report.sensitivity_label, ocr_used, len(duplicates), department
                            )
                            scan_id = self.db.get_last_scan_id()
                            fingerprint_engine.store_fingerprint(scan_id, f, fingerprint)

                            from engine.cross_linker import CrossLinker
                            CrossLinker(self.db).index_scan_result(
                                scan_id, f, res.entities, department=department
                            )
                            for violation in violations:
                                self.db.log_policy_violation(violation.policy_id, scan_id, f, violation.details)
                                if violation.severity in ["CRITICAL", "BLOCKER", "HIGH"]:
                                    mapped_severity = "CRITICAL" if violation.severity == "BLOCKER" else violation.severity
                                    self.db.create_incident(
                                        f"Scheduled Task Violation: {violation.name}", violation.details,
                                        mapped_severity, "scheduled_scan", scan_id, "system"
                                    )

                            from engine.anomaly_detector import AnomalyDetector
                            AnomalyDetector(self.db).analyze_scan(scan_id, len(res.entities))
                                
                        files_processed += 1
                        self.db.update_scan_manifest(task_id, file_path, file_hash, mtime)
                    except Exception as e:
                        import logging
                        files_failed += 1
                        logging.error("Scheduled scan failed for a file (%s)", type(e).__name__)
                        
        run_status = "FAILED" if files_failed and not files_processed else "PARTIAL" if files_failed else "SUCCESS"
        self.db.update_task_last_run(task_id, files_processed, violations_found, run_status, files_failed)
        self.task_finished.emit(name, files_processed, violations_found, files_failed)
