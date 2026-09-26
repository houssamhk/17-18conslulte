import os
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
    
    def __init__(self, input_dir: str, output_dir: str, engine: AlgComplianceEngine, strategy: str = 'legal', db = None, user_department: str = None, parent=None):
        super().__init__(parent)
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.engine = engine
        self.strategy = strategy
        self.db = db
        self.user_department = user_department
        self.cross_linker = CrossLinker(db) if db else None
        self._is_cancelled = False
        
    def cancel(self):
        self._is_cancelled = True
        
    def run(self):
        try:
            supported_exts = ('.txt', '.pdf', '.docx', '.xlsx', '.csv', '.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.eml', '.msg')
            files_to_process = []
            
            # Find all supported files
            for root, _, files in os.walk(self.input_dir):
                for f in files:
                    if f.lower().endswith(supported_exts):
                        files_to_process.append(os.path.join(root, f))
                        
            total = len(files_to_process)
            if total == 0:
                self.finished.emit(0)
                return
                
            processed_count = 0
            
            for idx, file_path in enumerate(files_to_process, 1):
                if self._is_cancelled:
                    break
                    
                filename = os.path.basename(file_path)
                try:
                    # 1. Extract
                    text, ocr_used = DocumentParser.extract_text(file_path)
                    if text.strip():
                        # 2. Anonymize
                        res = self.engine.anonymize(text, self.strategy)
                        
                        # 3. Generate report for PDF export
                        report = self.engine.generate_report(res.scan_result)
                        
                        # 4. Export to PDF
                        base_name = os.path.splitext(filename)[0]
                        output_path = os.path.join(self.output_dir, f"{base_name}_anonymized.pdf")
                        
                        PDFExporter.export_report(res, report, output_path)
                        
                        if self.db:
                            # Log scan
                            counts = {}
                            for ent in res.entities:
                                counts[ent.entity_type] = counts.get(ent.entity_type, 0) + 1
                            
                            self.db.log_scan(filename, len(res.entities), report.risk_level, self.strategy, counts, report.sensitivity_label, ocr_used, 0, self.user_department)
                            scan_id = self.db.get_last_scan_id()
                            
                            # Index entities
                            if self.cross_linker:
                                self.cross_linker.index_scan_result(scan_id, filename, res.entities)
                                
                        processed_count += 1
                        
                except Exception as e:
                    import logging
                    logging.error(f"Failed to process {filename} in batch: {e}")
                    # Continue to next file
                    
                self.file_completed.emit(filename)
                self.progress.emit(idx, total)
                
            self.finished.emit(processed_count)
            
        except Exception as e:
            self.error.emit(str(e))
