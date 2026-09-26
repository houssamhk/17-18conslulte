from typing import List, Dict
from storage.secure_db import SecureDatabase

class CrossLinker:
    """
    Analyzes indexed entities across multiple documents to find linkages
    and identify widespread data exposure.
    """
    def __init__(self, db: SecureDatabase):
        self.db = db

    def get_widespread_entities(self, min_documents: int = 2) -> List[Dict]:
        """
        Returns a list of entities that appear in at least `min_documents`.
        Results are ordered by the number of documents they appear in.
        """
        # We can leverage the existing DB method, filtering by min_documents if needed
        cross_linked = self.db.find_cross_linked_entities()
        return [c for c in cross_linked if c['document_count'] >= min_documents]

    def index_scan_result(self, scan_id: int, document_name: str, entities: list, department: str = None):
        """Indexes all entities from a scan result for cross-document tracking."""
        if not entities:
            return
        self.db.index_entities(scan_id, document_name, entities, department)

    def find_documents_by_entity(self, entity_text: str) -> List[str]:
        """Finds all document names containing a specific entity text."""
        import hashlib
        ent_hash = hashlib.sha256(entity_text.lower().encode('utf-8')).hexdigest()
        
        c = self.db.conn.cursor()
        c.execute("SELECT DISTINCT document_name FROM entity_index WHERE entity_hash=?", (ent_hash,))
        return [row[0] for row in c.fetchall()]
