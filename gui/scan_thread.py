from PyQt6.QtCore import QThread, pyqtSignal
from engine.compliance_engine import AlgComplianceEngine, AnonymizedResult
from engine.secure_memory import force_gc
import traceback

class NLPModelLoadWorker(QThread):
    """Load the optional local NLP model without freezing the desktop UI."""
    load_finished = pyqtSignal(bool)

    def __init__(self, engine: AlgComplianceEngine, model_path=None, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.model_path = model_path

    def run(self):
        self.load_finished.emit(self.engine.load_nlp_model(self.model_path))


class VerificationWorker(QThread):
    """Verify prior detections and rescan the processed text for residual candidates."""
    verification_ready = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, original_scan, processed_text: str, engine: AlgComplianceEngine, parent=None):
        super().__init__(parent)
        self.original_scan = original_scan
        self.processed_text = processed_text
        self.engine = engine

    def run(self):
        try:
            from engine.redaction_verifier import RedactionVerifier
            residual_scan = self.engine.scan(self.processed_text)
            result = RedactionVerifier.verify(
                self.original_scan, self.processed_text, residual_scan.entities
            )
            self.verification_ready.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.processed_text = ""


class ScanWorker(QThread):
    """Background thread for executing the compliance scan without blocking the GUI."""
    progress = pyqtSignal(int)
    result = pyqtSignal(object)  # AnonymizedResult
    error = pyqtSignal(str)
    
    def __init__(self, text: str, engine: AlgComplianceEngine, strategy: str = 'legal', parent=None):
        super().__init__(parent)
        self.text = text
        self.engine = engine
        self.strategy = strategy
        self._is_cancelled = False
        
    def cancel(self):
        self._is_cancelled = True
        
    def run(self):
        try:
            self.progress.emit(10) # Starting
            
            if self._is_cancelled:
                return
                
            self.progress.emit(40) # Regex phase 
            
            # Since the engine currently does everything in one `anonymize` call,
            # we just run it. For granular progress, we'd need to modify the engine.
            # But the NLP is the slow part.
            
            if self._is_cancelled:
                return
                
            res: AnonymizedResult = self.engine.anonymize(self.text, self.strategy)
            
            self.progress.emit(90) # Finishing up
            
            if not self._is_cancelled:
                self.result.emit(res)
                
            self.progress.emit(100) # Done
            
        except Exception as e:
            traceback.print_exc()
            self.error.emit(str(e))
        finally:
            # Clear sensitive text references in thread and force GC
            self.text = ""
            force_gc()
