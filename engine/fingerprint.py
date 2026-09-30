"""
SimHash-based Document Fingerprinting & Duplicate Detection.
Uses SimHash to generate locality-sensitive hashes for text documents,
enabling near-duplicate detection via Hamming distance comparison.
"""
import hashlib
import re
from typing import List, Tuple


class SimHash:
    """
    SimHash implementation for generating locality-sensitive fingerprints.
    Documents that are similar will have fingerprints with small Hamming distance.
    """
    
    HASH_BITS = 64  # 64-bit fingerprint
    
    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Extract shingles (character n-grams) from text."""
        # Remove extra whitespace, normalize
        text = re.sub(r'\s+', ' ', text.strip().lower())
        
        # Generate 3-grams (shingles) for better locality sensitivity
        n = 3
        tokens = []
        words = text.split()
        for i in range(len(words) - n + 1):
            tokens.append(' '.join(words[i:i + n]))
            
        # Also add individual words for short texts
        tokens.extend(words)
        return tokens
    
    @staticmethod
    def _hash_token(token: str) -> int:
        """Hash a single token to a 64-bit integer."""
        digest = hashlib.md5(token.encode('utf-8')).hexdigest()
        return int(digest[:16], 16)  # Use first 64 bits
    
    @classmethod
    def compute(cls, text: str) -> int:
        """
        Compute the SimHash fingerprint for the given text.
        Returns a 64-bit integer fingerprint.
        """
        tokens = cls._tokenize(text)
        if not tokens:
            return 0
            
        # Initialize vector of weighted bits
        v = [0] * cls.HASH_BITS
        
        for token in tokens:
            token_hash = cls._hash_token(token)
            for i in range(cls.HASH_BITS):
                bit = (token_hash >> i) & 1
                if bit:
                    v[i] += 1
                else:
                    v[i] -= 1
        
        # Build final fingerprint from sign of each component
        fingerprint = 0
        for i in range(cls.HASH_BITS):
            if v[i] > 0:
                fingerprint |= (1 << i)
                
        return fingerprint
    
    @staticmethod
    def hamming_distance(fp1: int, fp2: int) -> int:
        """
        Compute the Hamming distance between two fingerprints.
        Lower distance = more similar documents.
        """
        xor = fp1 ^ fp2
        distance = 0
        while xor:
            distance += xor & 1
            xor >>= 1
        return distance
    
    @classmethod
    def similarity(cls, fp1: int, fp2: int) -> float:
        """
        Compute similarity score (0.0 to 1.0) between two fingerprints.
        1.0 = identical, 0.0 = completely different.
        """
        dist = cls.hamming_distance(fp1, fp2)
        return 1.0 - (dist / cls.HASH_BITS)


class FingerprintEngine:
    """
    High-level fingerprint engine that computes, stores, and compares 
    document fingerprints for duplicate detection.
    """
    
    # Documents with similarity >= this threshold are considered duplicates
    DUPLICATE_THRESHOLD = 0.85  # 85% similarity
    
    def __init__(self, db=None):
        """
        Initialize the fingerprint engine.
        db: SecureDatabase instance for storing/retrieving fingerprints.
        """
        self.db = db
    
    def compute_fingerprint(self, text: str) -> int:
        """Compute the fingerprint for a document text."""
        return SimHash.compute(text)
    
    def find_duplicates(self, fingerprint: int, department: str = None) -> List[Tuple[int, str, float]]:
        """
        Compare a fingerprint against all stored fingerprints.
        Returns list of (scan_id, document_name, similarity_score) for matches above threshold.
        """
        if self.db is None:
            return []
            
        stored = self.db.get_fingerprints(department=department)
        duplicates = []
        
        for scan_id, doc_name, stored_fp in stored:
            sim = SimHash.similarity(fingerprint, stored_fp)
            if sim >= self.DUPLICATE_THRESHOLD:
                duplicates.append((scan_id, doc_name, sim))
                
        # Sort by similarity descending
        duplicates.sort(key=lambda x: x[2], reverse=True)
        return duplicates
    
    def store_fingerprint(self, scan_id: int, document_name: str, fingerprint: int):
        """Store a fingerprint in the database."""
        if self.db is not None:
            self.db.save_fingerprint(scan_id, document_name, fingerprint)
