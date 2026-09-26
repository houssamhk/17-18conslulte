from .regex_detector import DetectedEntity, ScanResult, AnonymizedResult, ComplianceReport, RegexDetector
from .nlp_detector import NLPDetector
from .anonymizer import Anonymizer
from .redaction_verifier import RedactionVerifier, VerificationResult
from .compliance_engine import AlgComplianceEngine
from .secure_memory import secure_wipe, SecureString, force_gc
from .document_parser import DocumentParser
from .presets import INDUSTRY_PRESETS
from .fingerprint import FingerprintEngine
from .proximity_analyzer import ProximityAnalyzer
from .policy_engine import PolicyEngine, PolicyViolation
from .scheduler import TaskScheduler
from .cross_linker import CrossLinker
from .dsar_manager import DSARManager
from .anomaly_detector import AnomalyDetector
from .evidence_packager import EvidencePackager
from .threat_intel import ThreatIntelEngine

# Optional heavy deps - imported lazily to allow the package to load even if missing
try:
    from .pdf_exporter import PDFExporter
except ImportError:
    PDFExporter = None  # type: ignore

try:
    from .exporters import ReportExporter
except ImportError:
    ReportExporter = None  # type: ignore

__all__ = [
    "DetectedEntity",
    "ScanResult",
    "AnonymizedResult",
    "ComplianceReport",
    "RegexDetector",
    "NLPDetector",
    "Anonymizer",
    "AlgComplianceEngine",
    "secure_wipe",
    "SecureString",
    "force_gc",
    "DocumentParser",
    "LabelingEngine",
    "LabelingPolicy",
    "RegulatoryMapper",
    "FingerprintEngine",
    "ProximityAnalyzer",
    "PolicyEngine",
    "PolicyViolation",
    "TaskScheduler",
    "ReportExporter",
    "CrossLinker",
    "DSARManager",
    "AnomalyDetector",
    "EvidencePackager",
    "ThreatIntelEngine"
]
