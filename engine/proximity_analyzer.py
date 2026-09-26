from typing import List, Dict, Tuple
from .regex_detector import DetectedEntity, ScanResult


class ProximityAnalyzer:
    """
    Analyzes the proximity and co-occurrence of PII entities.
    Identifies high-risk clusters where multiple sensitive entities 
    (e.g., Name + NIN + Phone) appear close to each other.
    """
    
    # Distance in characters to consider entities as part of the same cluster
    WINDOW_SIZE = 150 
    
    @classmethod
    def find_clusters(cls, entities: List[DetectedEntity]) -> List[List[DetectedEntity]]:
        """
        Groups entities into clusters based on their character proximity using a sliding window.
        Returns a list of clusters (each cluster is a list of DetectedEntity).
        """
        if not entities:
            return []
            
        # Sort entities by their start position
        sorted_entities = sorted(entities, key=lambda e: e.start)
        
        clusters = []
        current_cluster = [sorted_entities[0]]
        
        for i in range(1, len(sorted_entities)):
            prev_entity = current_cluster[-1]
            curr_entity = sorted_entities[i]
            
            # Check if current entity is within WINDOW_SIZE of the previous entity
            distance = curr_entity.start - prev_entity.end
            
            if distance <= cls.WINDOW_SIZE:
                current_cluster.append(curr_entity)
            else:
                # Break cluster
                if len(current_cluster) > 1:
                    clusters.append(current_cluster)
                current_cluster = [curr_entity]
                
        # Don't forget the last cluster
        if len(current_cluster) > 1:
            clusters.append(current_cluster)
            
        return clusters

    @classmethod
    def calculate_cluster_risk(cls, cluster: List[DetectedEntity]) -> Tuple[float, str]:
        """
        Calculates a risk multiplier based on the composition of a cluster.
        Returns (multiplier, risk_reason).
        """
        types_in_cluster = {e.entity_type for e in cluster}
        
        # High risk: Identity combination
        if "PER" in types_in_cluster and "NIN" in types_in_cluster:
            return 2.5, "Identity Cluster (Name + National ID)"
            
        # High risk: Financial identity
        if "PER" in types_in_cluster and ("RIB" in types_in_cluster or "CCP" in types_in_cluster):
            return 2.0, "Financial Identity Cluster (Name + Bank Account)"
            
        # Medium risk: Contact identity
        if "PER" in types_in_cluster and ("PHONE" in types_in_cluster or "EMAIL" in types_in_cluster or "LOC" in types_in_cluster):
            return 1.5, "Contact Identity Cluster (Name + Contact/Location)"
            
        # General cluster risk based on density
        return 1.2, f"Dense Data Cluster ({len(cluster)} entities)"
        
    @classmethod
    def analyze(cls, scan_result: ScanResult) -> Dict:
        """
        Performs full proximity analysis on a ScanResult.
        """
        clusters = cls.find_clusters(scan_result.entities)
        
        analyzed_clusters = []
        max_multiplier = 1.0
        
        for cluster in clusters:
            multiplier, reason = cls.calculate_cluster_risk(cluster)
            max_multiplier = max(max_multiplier, multiplier)
            
            analyzed_clusters.append({
                "entities": [e.text for e in cluster],
                "types": list({e.entity_type for e in cluster}),
                "start": cluster[0].start,
                "end": cluster[-1].end,
                "multiplier": multiplier,
                "reason": reason
            })
            
        return {
            "total_clusters": len(clusters),
            "max_risk_multiplier": max_multiplier,
            "clusters": analyzed_clusters
        }
