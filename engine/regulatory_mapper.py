from typing import List, Dict, Any
from .regex_detector import ScanResult

class RegulatoryMapper:
    """
    Maps detected PII entities to their corresponding legal articles.
    """
    def __init__(self, mappings: List[Dict[str, Any]]):
        """
        Initialize with regulatory mappings from the database.
        mappings: List of dicts with keys: entity_type, law_name, law_number, article_number, etc.
        """
        self.mappings = mappings
        self._map = {}
        for m in mappings:
            etype = m['entity_type']
            if etype not in self._map:
                self._map[etype] = []
            self._map[etype].append(m)

    def get_applicable_articles(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """
        Returns a deduplicated list of all applicable regulatory articles for the given scan result.
        """
        found_entity_types = {e.entity_type for e in scan_result.entities}
        applicable = []
        seen = set()
        
        for etype in found_entity_types:
            if etype in self._map:
                for article in self._map[etype]:
                    # Create a unique key for deduplication
                    key = f"{article['law_number']}_{article['article_number']}"
                    if key not in seen:
                        seen.add(key)
                        applicable.append(article)
                        
        return applicable
