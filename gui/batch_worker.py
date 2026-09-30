import os
import json
from datetime import datetime, timezone
from PyQt6.QtCore import QThread, pyqtSignal
from engine.compliance_engine import AlgComplianceEngine
from engine.document_parser import DocumentParser
from engine.pdf_exporter import PDFExporter
from engine.cross_linker import CrossLinker

class BatchWorker(QThread):
    """Background thread for batch processing multiple documents."""
    progress = pyqtSignal(int, int)  # current, total
    file_completed = pyqtSignal(str) # filename
    finished = pyqtSignal(int)       # total processed
    error = pyqtSignal(str)
    
    def __init__(self, input_dir: str, output_dir: str, engine: AlgComplianceEngine, strategy: str = 'legal', db = None, user_department: str = None, parent=None, user_role: str = 'user'):
        super().__init__(parent)
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.engine = engine
        self.strategy = strategy
        self._db_path = db.db_path if db else None
        self.db = None
        self.user_department = user_department
        self.user_role = user_role
        self.cross_linker = None
        self.fingerprint_engine = None
        self._is_cancelled = False
        self.failure_details = []
        self.file_results = []
        self.review_details = []
        
    def cancel(self):
        self._is_cancelled = True
        
    def run(self):
        try:
            input_root = os.path.normcase(os.path.realpath(self.input_dir))
            output_root = os.path.normcase(os.path.realpath(self.output_dir))
            try:
                shared_root = os.path.commonpath([input_root, output_root])
            except ValueError:
                shared_root = ""
            if shared_root == input_root:
                raise ValueError("مجلد المخرجات يجب أن يكون خارج مجلد المصدر لتجنب إعادة فحص الملفات الناتجة.")

            os.makedirs(self.output_dir, exist_ok=True)
            if self._db_path:
                from storage.secure_db import SecureDatabase
                from engine.fingerprint import FingerprintEngine
                self.db = SecureDatabase(self._db_path)
                self.cross_linker = CrossLinker(self.db)
                self.fingerprint_engine = FingerprintEngine(self.db)
            supported_exts = ('.txt', '.pdf', '.docx', '.xlsx', '.csv', '.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.eml', '.msg')
            files_to_process = []
            
            # Find all supported files
            for root, _, files in os.walk(self.input_dir):
                for f in files:
                    if f.lower().endswith(supported_exts):
                        files_to_process.append(os.path.join(root, f))
                        
            total = len(files_to_process)
            if total == 0:
                self._write_manifest(total)
                self.finished.emit(0)
                return
                
            processed_count = 0
            
            for idx, file_path in enumerate(files_to_process, 1):
                if self._is_cancelled:
                    break
                    
                filename = os.path.basename(file_path)
                relative_path = os.path.relpath(file_path, self.input_dir)
                text_output_written = False
                report_output_written = False
                anonymized_path = None
                report_path = None
                original_format_path = None
                original_format_verification = None
                try:
                    # 1. Extract and redact supported office files in place.
                    if file_path.lower().endswith('.xlsx'):
                        from engine.spreadsheet_redactor import redact_xlsx
                        original_format_path = os.path.join(self.output_dir, f"{relative_path}.anonymized.xlsx")
                        res = redact_xlsx(file_path, original_format_path, self.engine, self.strategy)
                        text, ocr_used = res.original_text, False
                    elif file_path.lower().endswith('.docx'):
                        from engine.word_redactor import redact_docx
                        original_format_path = os.path.join(self.output_dir, f"{relative_path}.anonymized.docx")
                        res = redact_docx(file_path, original_format_path, self.engine, self.strategy)
                        text, ocr_used = res.original_text, False
                    elif file_path.lower().endswith('.csv'):
                        from engine.csv_redactor import redact_csv
                        original_format_path = os.path.join(self.output_dir, f"{relative_path}.anonymized.csv")
                        res = redact_csv(file_path, original_format_path, self.engine, self.strategy)
                        text, ocr_used = res.original_text, False
                    elif file_path.lower().endswith('.pdf'):
                        from engine.pdf_redactor import redact_pdf
                        original_format_path = os.path.join(self.output_dir, f"{relative_path}.anonymized.pdf")
                        res = redact_pdf(file_path, original_format_path, self.engine, self.strategy)
                        text, ocr_used = res.original_text, False
                    elif file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff', '.bmp')):
                        from engine.image_redactor import redact_image
                        extension = os.path.splitext(file_path)[1].lower()
                        original_format_path = os.path.join(self.output_dir, f"{relative_path}.anonymized{extension}")
                        res = redact_image(file_path, original_format_path, self.engine, self.strategy)
                        text, ocr_used = res.original_text, True
                    else:
                        text, ocr_used = DocumentParser.extract_text(file_path)
                        res = self.engine.anonymize(text, self.strategy) if text.strip() else None
                    if text.strip():
                        # 3. Generate report for PDF export
                        report = self.engine.generate_report(res.scan_result)
                        
                        # 4. Export to PDF
                        anonymized_path = os.path.join(self.output_dir, f"{relative_path}.anonymized.txt")
                        report_path = os.path.join(self.output_dir, f"{relative_path}.report.pdf")
                        os.makedirs(os.path.dirname(anonymized_path), exist_ok=True)

                        with open(anonymized_path, "w", encoding="utf-8-sig", newline="") as output_file:
                            output_file.write(res.anonymized_text)
                        text_output_written = True
                        PDFExporter.export_report(res, report, report_path)
                        report_output_written = True

                        from engine.redaction_verifier import RedactionVerifier
                        text_residuals = self.engine.scan(res.anonymized_text).entities
                        text_check = RedactionVerifier.verify(
                            res.scan_result, res.anonymized_text, text_residuals
                        )
                        text_verification = {
                            "passed": text_check.is_successful,
                            "remaining_original_count": len(text_check.leaked_entities),
                            "additional_candidate_count": len(text_check.residual_entities),
                            "details": text_check.details,
                        }

                        if original_format_path:
                            from engine.original_format_verifier import verify_original_format
                            extension = os.path.splitext(file_path)[1]
                            original_format_verification = verify_original_format(
                                original_format_path, extension, res.scan_result, self.engine
                            )
                        format_passed = (
                            original_format_verification is None
                            or original_format_verification.get("passed", False)
                        )
                        verification_passed = text_verification["passed"] and format_passed
                        if not verification_passed:
                            remaining = text_verification["remaining_original_count"]
                            candidates = text_verification["additional_candidate_count"]
                            if original_format_verification:
                                remaining = max(remaining, original_format_verification.get("remaining_original_count", 0))
                                candidates = max(candidates, original_format_verification.get("additional_candidate_count", 0))
                            self.review_details.append((relative_path, remaining, candidates))
                            quarantined = self._quarantine_artifacts(
                                anonymized_path, report_path, original_format_path
                            )
                            anonymized_path = quarantined.get(anonymized_path, anonymized_path)
                            report_path = quarantined.get(report_path, report_path)
                            original_format_path = quarantined.get(original_format_path, original_format_path)
                        
                        if self.db:
                            fingerprint = self.fingerprint_engine.compute_fingerprint(text)
                            if self.user_role == "admin":
                                duplicates = self.fingerprint_engine.find_duplicates(fingerprint)
                            elif self.user_department:
                                duplicates = self.fingerprint_engine.find_duplicates(
                                    fingerprint, department=self.user_department
                                )
                            else:
                                duplicates = []
                            duplicates_found = len(duplicates)

                            # Log scan
                            counts = {}
                            for ent in res.entities:
                                counts[ent.entity_type] = counts.get(ent.entity_type, 0) + 1
                            
                            self.db.log_scan(filename, len(res.entities), report.risk_level, self.strategy, counts, report.sensitivity_label, ocr_used, duplicates_found, self.user_department)
                            scan_id = self.db.get_last_scan_id()
                            self.fingerprint_engine.store_fingerprint(scan_id, filename, fingerprint)
                            
                            # Index entities
                            if self.cross_linker:
                                self.cross_linker.index_scan_result(
                                    scan_id, filename, res.entities, department=self.user_department
                                )
                                
                        processed_count += int(verification_passed)
                        self.file_results.append({
                            "source": relative_path,
                            "status": "success" if verification_passed else "review_required",
                            "entity_count": len(res.entities),
                            "duplicates_found": duplicates_found if self.db else 0,
                            "risk_level": report.risk_level,
                            "sensitivity_label": report.sensitivity_label,
                            "text_verification": text_verification,
                            "anonymized_text": os.path.relpath(anonymized_path, self.output_dir),
                            "report_pdf": os.path.relpath(report_path, self.output_dir),
                        })
                        if original_format_path:
                            self.file_results[-1]["anonymized_original_format"] = os.path.relpath(original_format_path, self.output_dir)
                            self.file_results[-1]["original_format_verification"] = original_format_verification
                            if original_format_path.lower().endswith('.xlsx'):
                                self.file_results[-1]["format_notes"] = [
                                    "تم تمويه القيم النصية والرقمية المكتشفة في الخلايا.",
                                    "المعادلات والتعليقات والروابط وخصائص المصنف لا تُنقح؛ راجعها يدويًا قبل مشاركة النسخة.",
                                ]
                            elif original_format_path.lower().endswith('.csv'):
                                self.file_results[-1]["format_notes"] = [
                                    "تم تمويه القيم المكتشفة مع الإبقاء على الصفوف والأعمدة.",
                                    "قد يعاد تنسيق علامات الاقتباس ونهايات الأسطر عند حفظ CSV.",
                                ]
                            elif original_format_path.lower().endswith('.pdf'):
                                self.file_results[-1]["format_notes"] = [
                                    "تم تطبيق حجب دائم على مواضع النص القابل للبحث التي حددها الكاشف.",
                                    "أُزيلت المرفقات وخصائص الملف؛ ملفات PDF الممسوحة أو المواضع غير القابلة للتحديد تُرفض. راجع الملف يدويًا.",
                                ]
                            elif original_format_path.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff', '.bmp')):
                                self.file_results[-1]["format_notes"] = [
                                    "تم حجب مناطق النص التي حددها OCR؛ أزيلت بيانات EXIF والبيانات الوصفية عند حفظ النسخة.",
                                    "راجع جودة OCR والنسخة بصريًا؛ قد لا يكتشف OCR كل النصوص أو الكتابات اليدوية.",
                                ]
                            else:
                                self.file_results[-1]["format_notes"] = [
                                    "تم تمويه النص المكتشف في الفقرات والجداول والرؤوس والتذييلات مع محاولة الحفاظ على تنسيق المقاطع.",
                                    "مربعات النص والتعليقات والحواشي وخصائص المستند لا تُنقح؛ راجعها يدويًا قبل مشاركة النسخة.",
                                ]
                    else:
                        reason = "لم يُستخرج نص من الملف."
                        self.failure_details.append((filename, reason))
                        failure = {"source": relative_path, "status": "failed", "error": reason}
                        if original_format_path and os.path.exists(original_format_path):
                            quarantined = self._quarantine_artifacts(original_format_path)
                            original_format_path = quarantined.get(original_format_path, original_format_path)
                            failure["anonymized_original_format"] = os.path.relpath(original_format_path, self.output_dir)
                        self.file_results.append(failure)
                        
                except Exception as e:
                    import logging
                    logging.error(f"Failed to process {filename} in batch: {e}")
                    reason = str(e)
                    quarantined = self._quarantine_artifacts(
                        anonymized_path if text_output_written else None,
                        report_path if report_output_written else None,
                        original_format_path,
                    )
                    anonymized_path = quarantined.get(anonymized_path, anonymized_path)
                    report_path = quarantined.get(report_path, report_path)
                    original_format_path = quarantined.get(original_format_path, original_format_path)
                    if text_output_written:
                        if report_output_written:
                            reason += " — أُنشئت ملفات النص والتقرير، لكن تعذر إكمال تسجيل نتيجة الفحص."
                        else:
                            reason += " — تم إنشاء النص المنقح، لكن تعذر إنشاء تقرير PDF."
                    self.failure_details.append((filename, reason))
                    self.file_results.append({
                        "source": relative_path,
                        "status": "failed",
                        "error": reason,
                        "anonymized_text": os.path.relpath(anonymized_path, self.output_dir) if text_output_written else None,
                        "report_pdf": os.path.relpath(report_path, self.output_dir) if report_output_written else None,
                        "anonymized_original_format": os.path.relpath(original_format_path, self.output_dir) if original_format_path and os.path.exists(original_format_path) else None,
                    })
                    # Continue to next file
                    
                self.file_completed.emit(filename)
                self.progress.emit(idx, total)
                
            self._write_manifest(total)
            self.finished.emit(processed_count)
            
        except Exception as e:
            self.error.emit(str(e))
        finally:
            if self.db:
                self.db.close()
                self.db = None

    def _write_manifest(self, discovered_count):
        """Write a machine-readable summary without exposing absolute file paths."""
        manifest_files = []
        for result in self.file_results:
            safe_result = dict(result)
            # Library exceptions can embed local absolute paths, document content,
            # or other machine-specific details. Keep those details in the live
            # review UI only; the portable manifest gets a stable error code.
            if "error" in safe_result:
                safe_result["error"] = "processing_failed"
            manifest_files.append(safe_result)

        manifest = {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "discovered_files": discovered_count,
            "processed_files": sum(1 for item in self.file_results if item["status"] == "success"),
            "failed_files": sum(1 for item in self.file_results if item["status"] == "failed"),
            "review_required_files": sum(1 for item in self.file_results if item["status"] == "review_required"),
            "cancelled": self._is_cancelled,
            "files": manifest_files,
        }
        manifest_path = os.path.join(self.output_dir, "batch_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as manifest_file:
            json.dump(manifest, manifest_file, ensure_ascii=False, indent=2)

    def _quarantine_artifacts(self, *paths):
        """Move unverified or incomplete artifacts under a dedicated review folder."""
        moved = {}
        review_root = os.path.join(self.output_dir, "needs_review")
        for path in paths:
            if not path or not os.path.isfile(path):
                continue
            absolute_path = os.path.abspath(path)
            relative_path = os.path.relpath(absolute_path, os.path.abspath(self.output_dir))
            destination = os.path.join(review_root, relative_path)
            if os.path.normcase(absolute_path) == os.path.normcase(os.path.abspath(destination)):
                moved[path] = path
                continue
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            os.replace(absolute_path, destination)
            moved[path] = destination
        return moved
