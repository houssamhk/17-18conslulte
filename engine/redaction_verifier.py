from dataclasses import dataclass
from typing import List, Tuple
from .regex_detector import ScanResult, DetectedEntity

@dataclass
class VerificationResult:
    is_successful: bool
    masking_percentage: float
    leaked_entities: List[DetectedEntity]
    details: str

class RedactionVerifier:
    """
    Verifies that the anonymized text does not leak any of the original sensitive entities.
    """
    
    @staticmethod
    def verify(original_scan: ScanResult, anonymized_text: str) -> VerificationResult:
        leaked_entities = []
        
        # Check if each detected entity's raw text is still present in the anonymized output
        for entity in original_scan.entities:
            # We do a basic substring check. More advanced checks could handle partial masks.
            if entity.text in anonymized_text:
                leaked_entities.append(entity)
                
        total_entities = len(original_scan.entities)
        masked_count = total_entities - len(leaked_entities)
        
        masking_percentage = (masked_count / total_entities * 100) if total_entities > 0 else 100.0
        
        is_successful = len(leaked_entities) == 0
        
        if is_successful:
            details = "All detected entities were successfully redacted."
        else:
            details = f"Warning: {len(leaked_entities)} entities leaked in the anonymized output."
            
        return VerificationResult(
            is_successful=is_successful,
            masking_percentage=masking_percentage,
            leaked_entities=leaked_entities,
            details=details
        )
