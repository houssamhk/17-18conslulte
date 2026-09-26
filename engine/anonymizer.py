import html
from typing import List, Tuple, Dict
from .regex_detector import DetectedEntity

class Anonymizer:
    """
    Multi-Strategy Anonymization Engine.
    Provides various masking techniques and HTML highlighting for detected entities.
    """
    
    # CSS Colors for HTML highlighting
    COLORS = {
        "NIN": "#e94560",      # Crimson Rose
        "PHONE": "#533483",    # Purple
        "CCP": "#d29922",      # Amber
        "RIB": "#d29922",      # Amber
        "NIF": "#d29922",      # Amber
        "IBAN": "#d29922",     # Amber
        "EMAIL": "#2ea043",    # Green
        "PASSPORT": "#e94560", # Crimson Rose
        "PER": "#1a8870",      # Teal
        "LOC": "#0f3460",      # Navy
        "ORG": "#533483",      # Purple
        "CUSTOM": "#ff6b6b",   # Coral Red (Custom Keywords)
        "MISC": "#a0a0a0"      # Gray
    }

    # Consistent fake data for pseudonymization (simple mock mapping)
    PSEUDO_MAP = {
        "NIN": "100000000000000000",
        "PHONE": "0550000000",
        "CCP": "0000000000 00",
        "RIB": "00000000000000000000",
        "NIF": "000000000000000",
        "IBAN": "DZ0000000000000000000000",
        "EMAIL": "user@example.dz",
        "PASSPORT": "A00000000",
        "PER": "فلان الفلاني",
        "LOC": "الجزائر العاصمة",
        "ORG": "مؤسسة وطنية",
        "CUSTOM": "[محتوى محظور]",
        "MISC": "بيانات"
    }

    def anonymize(self, text: str, entities: List[DetectedEntity], strategy: str = 'legal') -> Tuple[str, str]:
        """
        Anonymizes the text based on the detected entities and the chosen strategy.
        Returns a tuple of (plain_anonymized_text, html_highlighted_text).
        """
        # Sort entities by start index descending to avoid index shifting when replacing
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        
        plain_text = text
        html_text = text
        
        # HTML escape the base text first? No, because we need exact indices.
        # We must insert HTML tags carefully or escape afterwards.
        # Safest approach for HTML: build it backwards based on original indices, escaping text in between.
        
        plain_parts = []
        html_parts = []
        last_index = len(text)
        
        for entity in sorted_entities:
            # Add the text after the entity
            tail = text[entity.end:last_index]
            plain_parts.insert(0, tail)
            html_parts.insert(0, html.escape(tail))
            
            # Determine replacement string
            replacement = self._get_replacement(entity, strategy)
            plain_parts.insert(0, replacement)
            
            # HTML version
            color = self.COLORS.get(entity.entity_type, self.COLORS["MISC"])
            html_replacement = f'<span style="background-color: {color}; color: white; padding: 2px 4px; border-radius: 3px; font-weight: bold;" title="{entity.entity_type}">{html.escape(replacement)}</span>'
            html_parts.insert(0, html_replacement)
            
            last_index = entity.start
            
        # Add the remaining text before the first entity
        head = text[0:last_index]
        plain_parts.insert(0, head)
        html_parts.insert(0, html.escape(head))
        
        return "".join(plain_parts), "".join(html_parts).replace('\n', '<br>')

    def _get_replacement(self, entity: DetectedEntity, strategy: str) -> str:
        if strategy == "full_mask":
            return "██████████"
            
        elif strategy == "legal_mask":
            return "[بيانات محمية بموجب القانون 18-07]"
            
        elif strategy == "partial_mask":
            # Show first and last char, mask middle
            text = entity.text
            if len(text) <= 2:
                return "██"
            return f"{text[0]}████{text[-1]}"
            
        elif strategy == "pseudonymize":
            # Replace with generic fake data based on type
            return self.PSEUDO_MAP.get(entity.entity_type, "[PSEUDO]")
            
        # Default fallback
        return "[MASKED]"
