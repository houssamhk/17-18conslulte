from dataclasses import dataclass, field
from typing import List
import re
from .regex_detector import ScanResult, DetectedEntity

@dataclass
class VerificationResult:
    is_successful: bool
    masking_percentage: float
    leaked_entities: List[DetectedEntity]
    details: str
    residual_entities: List[DetectedEntity] = field(default_factory=list)

class RedactionVerifier:
    """
    Verifies that the anonymized text does not leak any of the original sensitive entities.
    """
    
    MASK_PLACEHOLDER = re.compile(
        r"\[بيانات محمية بموجب القانون 18-07\]|\[(?:[A-Z][A-Z0-9_]*-[A-F0-9]{16}|MASKED)\]"
    )

    @classmethod
    def verify(
        cls,
        original_scan: ScanResult,
        anonymized_text: str,
        residual_entities: List[DetectedEntity] = None,
    ) -> VerificationResult:
        leaked_entities = []
        
        # Check if each detected entity's raw text is still present in the anonymized output
        for entity in original_scan.entities:
            # We do a basic substring check. More advanced checks could handle partial masks.
            if entity.text in anonymized_text:
                leaked_entities.append(entity)
                
        total_entities = len(original_scan.entities)
        masked_count = total_entities - len(leaked_entities)
        
        masking_percentage = (masked_count / total_entities * 100) if total_entities > 0 else 100.0
        
        residual_entities = residual_entities or []
        residual_entities = [
            entity for entity in residual_entities
            if not any(
                placeholder.start() <= entity.start and entity.end <= placeholder.end()
                for placeholder in cls.MASK_PLACEHOLDER.finditer(anonymized_text)
            )
        ]
        is_successful = not leaked_entities and not residual_entities
        
        if is_successful:
            details = "لم تبق القيم المكتشفة أصلًا، ولم يرصد الكاشف الحالي كيانات إضافية."
        else:
            issues = []
            if leaked_entities:
                issues.append(f"{len(leaked_entities)} original detected values remain unchanged")
            if residual_entities:
                issues.append(f"{len(residual_entities)} possible entities were detected in the processed text")
            details = "Review required: " + "; ".join(issues) + "."
            
        return VerificationResult(
            is_successful=is_successful,
            masking_percentage=masking_percentage,
            leaked_entities=leaked_entities,
            details=details,
            residual_entities=residual_entities,
        )
