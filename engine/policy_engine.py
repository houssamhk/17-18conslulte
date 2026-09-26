import json
from typing import List, Dict, Any
from .regex_detector import ScanResult


class PolicyViolation:
    def __init__(self, policy_id: int, name: str, severity: str, remediation: str, details: str):
        self.policy_id = policy_id
        self.name = name
        self.severity = severity
        self.remediation = remediation
        self.details = details


class PolicyEngine:
    """
    Evaluates scan results against compliance policies.
    Conditions are defined in JSON format.
    Example condition JSON:
    [
        {"field": "entity_type", "operator": "in", "value": ["NIN", "RIB"]},
        {"field": "total_entities", "operator": ">", "value": 5}
    ]
    Supported operators: ==, !=, >, <, >=, <=, in, not_in
    """
    
    def __init__(self, db):
        self.db = db
        
    def evaluate(self, scan_result: ScanResult, document_name: str) -> List[PolicyViolation]:
        """
        Evaluates the ScanResult against all active compliance policies.
        Returns a list of PolicyViolations if any policies are breached.
        """
        violations = []
        
        if not self.db:
            return violations
            
        active_policies = self.db.get_active_policies()
        
        # Prepare context data for evaluation
        # We need counts per entity type, and total entities
        entity_counts = {}
        for ent in scan_result.entities:
            entity_counts[ent.entity_type] = entity_counts.get(ent.entity_type, 0) + 1
            
        context = {
            "total_entities": len(scan_result.entities),
            "document_name": document_name,
            "entity_types": list(entity_counts.keys()),
            "entity_counts": entity_counts
        }
        
        for p_id, p_name, p_desc, cond_json, p_sev, p_remed in active_policies:
            try:
                conditions = json.loads(cond_json)
                if self._evaluate_conditions(conditions, context):
                    # Policy matched (violated)
                    details = f"Violated policy '{p_name}': "
                    details += ", ".join([f"{c['field']} {c['operator']} {c['value']}" for c in conditions])
                    violations.append(PolicyViolation(p_id, p_name, p_sev, p_remed, details))
            except Exception as e:
                import logging
                logging.error(f"Failed to evaluate policy {p_name}: {e}")
                
        # Phase 4 Feature 14: Consent Registry Check
        # If any entity's text is in consent_registry with OPT_OUT status, trigger a violation
        try:
            c = self.db.conn.cursor()
            for ent in scan_result.entities:
                if ent.entity_type in ['NIN', 'EMAIL', 'PHONE']:
                    c.execute("SELECT consent_type FROM consent_registry WHERE subject_id=? AND status='OPT_OUT'", (ent.text,))
                    opt_out = c.fetchone()
                    if opt_out:
                        violations.append(PolicyViolation(
                            policy_id=-1, # System policy
                            name=f"Consent Withdrawal (Opt-Out)",
                            severity="BLOCKER",
                            remediation="Delete this data immediately. Subject has withdrawn consent.",
                            details=f"Found {ent.entity_type} ({ent.text}) for a subject who opted out of {opt_out[0]}."
                        ))
        except Exception as e:
            import logging
            logging.error(f"Failed to check consent registry: {e}")
                
        return violations
        
    def _evaluate_conditions(self, conditions: List[Dict[str, Any]], context: Dict[str, Any]) -> bool:
        """
        Evaluates a list of conditions (AND logic between conditions).
        Returns True if ALL conditions are met.
        """
        if not conditions:
            return False
            
        for cond in conditions:
            field = cond.get("field")
            operator = cond.get("operator")
            expected = cond.get("value")
            
            # Extract actual value from context
            actual = None
            if field == "total_entities":
                actual = context["total_entities"]
            elif field == "document_name":
                actual = context["document_name"]
            elif field == "entity_types":
                actual = context["entity_types"] # List of strings
            elif field.startswith("count_"):
                # e.g., count_NIN
                etype = field.replace("count_", "")
                actual = context["entity_counts"].get(etype, 0)
            else:
                return False # Unknown field
                
            # Evaluate operator
            if not self._compare(actual, operator, expected):
                return False
                
        return True
        
    def _compare(self, actual: Any, operator: str, expected: Any) -> bool:
        if operator == "==": return actual == expected
        if operator == "!=": return actual != expected
        
        if operator == ">": return actual > expected
        if operator == "<": return actual < expected
        if operator == ">=": return actual >= expected
        if operator == "<=": return actual <= expected
        
        if operator == "in":
            # If actual is a list (like entity_types), check if any expected item is in actual
            if isinstance(actual, list):
                if isinstance(expected, list):
                    return any(e in actual for e in expected)
                return expected in actual
            # If actual is string, check if it's in expected list
            return actual in expected
            
        if operator == "not_in":
            if isinstance(actual, list):
                if isinstance(expected, list):
                    return not any(e in actual for e in expected)
                return expected not in actual
            return actual not in expected
            
        if operator == "contains":
            if isinstance(actual, str):
                return str(expected).lower() in actual.lower()
            if isinstance(actual, list):
                return expected in actual
                
        return False
