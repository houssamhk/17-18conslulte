import time
from typing import Optional, List
from .regex_detector import RegexDetector, DetectedEntity, ScanResult, AnonymizedResult, ComplianceReport
from .nlp_detector import NLPDetector
from .anonymizer import Anonymizer
from .secure_memory import force_gc
from .labeling_engine import LabelingEngine
from .regulatory_mapper import RegulatoryMapper
from .proximity_analyzer import ProximityAnalyzer

class AlgComplianceEngine:
    """
    Main orchestrator class for the Alg-PII Engine.
    Combines deterministic regex and contextual NLP detection.
    """
    def __init__(self, use_nlp: bool = True, model_path: Optional[str] = None, custom_keywords: List[str] = None, labeling_policies: List[dict] = None, regulatory_mappings: List[dict] = None):
        self.regex_detector = RegexDetector(custom_keywords=custom_keywords)
        self.nlp_detector = NLPDetector(model_path) if use_nlp else None
        self.anonymizer = Anonymizer()
        self.labeling_engine = LabelingEngine(labeling_policies) if labeling_policies else None
        self.regulatory_mapper = RegulatoryMapper(regulatory_mappings) if regulatory_mappings else None
        
    def update_custom_keywords(self, keywords: List[str]):
        """Dynamically update custom keywords."""
        self.regex_detector.custom_keywords = keywords

    def update_labeling_policies(self, policies: List[dict]):
        self.labeling_engine = LabelingEngine(policies)
        
    def update_regulatory_mappings(self, mappings: List[dict]):
        self.regulatory_mapper = RegulatoryMapper(mappings)

    def is_nlp_available(self) -> bool:
        return self.nlp_detector is not None and self.nlp_detector.is_available()
        
    def load_nlp_model(self, model_path: Optional[str] = None) -> bool:
        if self.nlp_detector:
            return self.nlp_detector.load_model(model_path)
        return False

    # Context Classification Rules (Arabic keyword → context label)
    CONTEXT_RULES = {
        "HR": ["موظف", "عقد عمل", "راتب", "توظيف", "إجازة", "ترقية", "تقاعد", "أجر", "عامل", "مدير", "وظيفة"],
        "FINANCIAL": ["حساب", "قرض", "دفع", "فاتورة", "بنك", "مصرف", "تحويل", "رصيد", "مالي", "ضريبة", "إيداع"],
        "MEDICAL": ["مريض", "تشخيص", "علاج", "مستشفى", "طبيب", "دواء", "صحة", "عيادة", "فحص طبي", "مرض", "وصفة"],
        "LEGAL": ["شكوى", "محكمة", "قضية", "محامي", "حكم", "قانون", "دعوى", "تحقيق", "شهادة", "جريمة", "عقوبة"]
    }

    def scan(self, text: str) -> ScanResult:
        """Runs both detectors, deduplicates results, classifies context, and sorts them."""
        start_time = time.time()
        
        # 1. Regex Detection
        regex_entities = self.regex_detector.detect(text)
        
        # 2. NLP Detection
        nlp_entities = []
        if self.is_nlp_available():
            nlp_entities = self.nlp_detector.detect(text)
            
        # 3. Deduplication and Merge
        all_entities = self._deduplicate(regex_entities, nlp_entities)
        
        # 4. Contextual Entity Classification (Feature #35)
        self._classify_context(text, all_entities)
        
        # Sort by start position
        all_entities.sort(key=lambda x: x.start)
        
        scan_time_ms = (time.time() - start_time) * 1000
        
        return ScanResult(
            entities=all_entities,
            text_length=len(text),
            scan_time_ms=scan_time_ms,
            regex_count=len(regex_entities),
            nlp_count=len(nlp_entities)
        )

    def _deduplicate(self, regex_entities: List[DetectedEntity], nlp_entities: List[DetectedEntity]) -> List[DetectedEntity]:
        """
        Merge and resolve overlapping entities.
        Regex matches have higher confidence for structured data.
        """
        merged = []
        
        # Start with all regex entities (they are deterministic)
        merged.extend(regex_entities)
        
        # Add NLP entities only if they don't overlap with regex ones
        for nlp_ent in nlp_entities:
            overlap = False
            for reg_ent in regex_entities:
                # Check for overlap: max(start1, start2) < min(end1, end2)
                if max(nlp_ent.start, reg_ent.start) < min(nlp_ent.end, reg_ent.end):
                    overlap = True
                    break
            
            if not overlap:
                merged.append(nlp_ent)
                
        return merged

    def _classify_context(self, text: str, entities: List[DetectedEntity]):
        """Feature #35: Classify the surrounding context of each detected entity."""
        text_lower = text.lower()
        for entity in entities:
            # Extract context window (±100 chars)
            ctx_start = max(0, entity.start - 100)
            ctx_end = min(len(text), entity.end + 100)
            context_window = text_lower[ctx_start:ctx_end]
            
            best_label = "GENERAL"
            best_count = 0
            matched_kws = []
            
            for label, keywords in self.CONTEXT_RULES.items():
                hits = [kw for kw in keywords if kw in context_window]
                if len(hits) > best_count:
                    best_count = len(hits)
                    best_label = label
                    matched_kws = hits
            
            entity.context_label = best_label
            entity.context_keywords = ",".join(matched_kws)

    def anonymize(self, text: str, strategy: str = 'legal') -> AnonymizedResult:
        """Scans the text and applies the selected anonymization strategy."""
        scan_res = self.scan(text)
        plain_text, html_text = self.anonymizer.anonymize(text, scan_res.entities, strategy)
        
        # Clean up memory if possible
        force_gc()
        
        return AnonymizedResult(
            original_text=text,
            anonymized_text=plain_text,
            html_highlighted=html_text,
            entities=scan_res.entities,
            strategy=strategy,
            scan_result=scan_res
        )

    def generate_report(self, result: ScanResult) -> ComplianceReport:
        """Generates a structured compliance audit report from scan results."""
        total_entities = len(result.entities)
        
        # Proximity and Cluster Analysis
        cluster_analysis = ProximityAnalyzer.analyze(result)
        max_multiplier = cluster_analysis.get('max_risk_multiplier', 1.0)
        
        # Calculate Base Risk Level
        has_critical_pii = any(e.entity_type in ['NIN', 'RIB', 'PASSPORT'] for e in result.entities)
        
        # Adjust entity count by cluster risk multiplier
        effective_entities = total_entities * max_multiplier
        
        if effective_entities > 10 or has_critical_pii:
            risk_level = "CRITICAL"
        elif effective_entities >= 5:
            risk_level = "HIGH"
        elif effective_entities >= 2:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        # Summary
        summary = {}
        for ent in result.entities:
            summary[ent.entity_type] = summary.get(ent.entity_type, 0) + 1
            
        # Law References
        law_refs = ["Law 18-07: General Personal Data Protection"]
        if "RIB" in summary or "CCP" in summary or "IBAN" in summary:
            law_refs.append("Law 18-05: Electronic Commerce / Banking Secrecy")
            
        # Sensitivity Label
        sensitivity_label = "UNCLASSIFIED"
        if self.labeling_engine:
            sensitivity_label = self.labeling_engine.evaluate(result)
            
        applicable_articles = []
        if self.regulatory_mapper:
            applicable_articles = self.regulatory_mapper.get_applicable_articles(result)
            
        return ComplianceReport(
            scan_result=result,
            risk_level=risk_level,
            sensitivity_label=sensitivity_label,
            entity_summary=summary,
            recommendations=["Anonymize immediately before storage.", "Do not export outside national borders."],
            law_references=law_refs,
            applicable_articles=applicable_articles,
            clusters=cluster_analysis.get('clusters', [])
        )
