from dataclasses import dataclass, field
from typing import List, Dict
import regex as re

@dataclass
class DetectedEntity:
    text: str
    entity_type: str  
    start: int
    end: int
    confidence: float  
    source: str
    context_label: str = ""       # HR, FINANCIAL, MEDICAL, LEGAL, GENERAL
    context_keywords: str = ""    # Matched keywords that determined the context

@dataclass
class ScanResult:
    entities: List[DetectedEntity]
    text_length: int
    scan_time_ms: float
    regex_count: int
    nlp_count: int

@dataclass
class AnonymizedResult:
    original_text: str
    anonymized_text: str
    html_highlighted: str
    entities: List[DetectedEntity]
    strategy: str
    scan_result: ScanResult = None

@dataclass
class ComplianceReport:
    scan_result: ScanResult
    risk_level: str  
    sensitivity_label: str
    entity_summary: Dict[str, int]
    recommendations: List[str]
    law_references: List[str]
    applicable_articles: List[Dict] = field(default_factory=list)
    clusters: List[Dict] = field(default_factory=list)

class RegexDetector:
    """
    Deterministic PII Detection Layer using high-precision regex patterns calibrated for Algerian data.
    """
    
    def __init__(self, custom_keywords: List[str] = None):
        self.custom_keywords = custom_keywords or []
        
    PATTERNS = {
        "NIN": re.compile(r'\b\d{18}\b'),
        "PHONE": re.compile(r'\b0[567]\d{8}\b'),
        "PHONE_INTL": re.compile(r'(?:\+213|00213)[567]\d{8}\b'),
        "CCP": re.compile(r'\b\d{10}\s*(?:clé|cle|/)?\s*\d{2}\b'),
        "RIB": re.compile(r'\b\d{20}\b'),
        "NIF": re.compile(r'\b\d{15}(?:\d{5})?\b'),
        "IBAN": re.compile(r'\bDZ\d{24}\b'),
        "EMAIL": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
        "PASSPORT": re.compile(r'\b[A-Z]\d{8}\b')
    }

    TYPE_LABELS = {
        "NIN": {"en": "National ID", "ar": "رقم التعريف الوطني"},
        "PHONE": {"en": "Phone Number", "ar": "رقم الهاتف"},
        "PHONE_INTL": {"en": "Phone Number", "ar": "رقم الهاتف"},
        "CCP": {"en": "Postal Account", "ar": "رقم الحساب البريدي"},
        "RIB": {"en": "Bank Account", "ar": "الهوية المصرفية"},
        "NIF": {"en": "Tax ID", "ar": "رقم التعريف الجبائي"},
        "IBAN": {"en": "IBAN", "ar": "رقم الحساب المصرفي الدولي"},
        "EMAIL": {"en": "Email Address", "ar": "البريد الإلكتروني"},
        "PASSPORT": {"en": "Passport Number", "ar": "رقم جواز السفر"},
        "CUSTOM": {"en": "Custom Keyword", "ar": "كلمة مخصصة"}
    }

    def detect(self, text: str) -> List[DetectedEntity]:
        """
        Scan text using deterministic regex patterns and custom keywords.
        """
        matches = []
        
        # 1. Custom Keywords
        for kw in self.custom_keywords:
            if not kw.strip(): continue
            # Basic word boundary search, ignoring case
            pattern = re.compile(rf'\b{re.escape(kw.strip())}\b', re.IGNORECASE)
            for match in pattern.finditer(text):
                matches.append(DetectedEntity(
                    text=match.group(),
                    entity_type="CUSTOM",
                    start=match.start(),
                    end=match.end(),
                    confidence=1.0,
                    source="custom_keyword"
                ))
                
        # 2. Standard Patterns
        for entity_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                # Standardize phone type
                if entity_type == "PHONE_INTL":
                    reported_type = "PHONE"
                else:
                    reported_type = entity_type
                    
                matches.append(DetectedEntity(
                    text=match.group(),
                    entity_type=reported_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=1.0,
                    source="regex"
                ))
        
        # Deduplicate/handle overlapping matches
        # Sort by start position (ascending), then end position (descending) so longer matches come first
        matches.sort(key=lambda x: (x.start, -x.end))
        
        filtered_matches = []
        last_end = -1
        
        for match in matches:
            # Simple overlap resolution: if it starts after the last one ended, it's non-overlapping
            if match.start >= last_end:
                filtered_matches.append(match)
                last_end = match.end
                
        return filtered_matches
