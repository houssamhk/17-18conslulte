import json
from typing import List, Dict
from .regex_detector import ScanResult

class ThreatIntelEngine:
    """
    Offline Threat Intelligence Feed.
    Compares scan findings against known data breach patterns and Algerian-specific threat indicators.
    """
    def __init__(self, db):
        self.db = db
        self.threat_patterns = self.db.get_threat_intel()

    def evaluate(self, scan_result: ScanResult) -> List[Dict]:
        """
        Evaluates the scan result against loaded threat patterns.
        Returns a list of matched threats with severity and remediation advice.
        """
        if not scan_result.entities:
            return []

        # Summarize detected entities
        detected_types = {}
        for ent in scan_result.entities:
            detected_types[ent.entity_type] = detected_types.get(ent.entity_type, 0) + 1

        matched_threats = []
        for threat in self.threat_patterns:
            indicators = threat.get("indicators", [])
            
            # Check if all required indicator types are present in the document
            # E.g., if indicators = ["NIN"], check if "NIN" is in detected_types
            # If indicators = ["RIB", "CCP"], check if BOTH or ANY? We'll treat it as ANY for broad matching,
            # or we can treat as ALL for specific combo. Let's do ANY for now.
            match = False
            for ind in indicators:
                if ind in detected_types and detected_types[ind] > 0:
                    # Specific condition for "Bulk Identity Leak": needs multiple NINs
                    if threat["threat_name"] == "تسريب هويات متعددة (Bulk Identity Leak)" and ind == "NIN":
                        if detected_types[ind] >= 3:
                            match = True
                            break
                    else:
                        match = True
                        break

            if match:
                matched_threats.append(threat)

        return matched_threats
