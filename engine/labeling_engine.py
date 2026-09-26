import json
from typing import List, Dict, Any
from .regex_detector import ScanResult

class LabelingEngine:
    """
    Evaluates scan results against labeling policies to determine the document's sensitivity label.
    """
    
    # Base weights for entity types
    ENTITY_WEIGHTS = {
        "NIN": 10,
        "PASSPORT": 10,
        "RIB": 8,
        "IBAN": 8,
        "CCP": 6,
        "NIF": 5,
        "PHONE": 3,
        "PHONE_INTL": 4,
        "EMAIL": 2,
        "PER": 3,
        "LOC": 1,
        "ORG": 2,
        "CUSTOM": 10
    }

    def __init__(self, policies: List[Dict[str, Any]]):
        """
        Initialize with policies from the database.
        policies: List of dicts with keys: label_name, min_score, max_score, required_entity_types
        """
        self.policies = policies
        # Sort policies from highest sensitivity to lowest (assuming max_score implies sensitivity)
        self.policies.sort(key=lambda x: x['min_score'], reverse=True)

    def calculate_score(self, scan_result: ScanResult) -> int:
        score = 0
        for entity in scan_result.entities:
            weight = self.ENTITY_WEIGHTS.get(entity.entity_type, 1)
            score += weight
        return score

    def evaluate(self, scan_result: ScanResult) -> str:
        """
        Evaluate the scan result and return the appropriate label name.
        """
        score = self.calculate_score(scan_result)
        
        found_entity_types = {e.entity_type for e in scan_result.entities}

        for policy in self.policies:
            # Check score range
            if policy['min_score'] <= score <= policy['max_score']:
                # Check required entities if any
                required = set(policy.get('required_entity_types', []))
                if required:
                    if required.issubset(found_entity_types):
                        return policy['label_name']
                else:
                    return policy['label_name']
                    
        return "UNCLASSIFIED"
