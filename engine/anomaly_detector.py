import math
from typing import Optional, Dict
from storage.secure_db import SecureDatabase

class AnomalyDetector:
    """
    Detects abnormal data processing patterns (e.g. suddenly scanning a document
    with 1000x more PII than the historical average).
    """
    def __init__(self, db: SecureDatabase, z_score_threshold: float = 3.0):
        self.db = db
        self.z_score_threshold = z_score_threshold
        
    def _get_baseline_stats(self) -> tuple[float, float]:
        """Calculates the mean and standard deviation of entities per scan."""
        c = self.db.conn.cursor()
        c.execute("SELECT total_entities FROM scan_history WHERE total_entities > 0 ORDER BY timestamp DESC LIMIT 1000")
        rows = c.fetchall()
        
        if not rows or len(rows) < 10:
            return 0.0, 0.0 # Not enough data for baseline
            
        values = [r[0] for r in rows]
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)
        
        return mean, std_dev

    def analyze_scan(self, scan_id: int, total_entities: int) -> Optional[Dict]:
        """
        Analyzes a single scan against historical baselines.
        Returns anomaly info dict if anomalous, otherwise None.
        """
        if total_entities == 0:
            return None
            
        mean, std_dev = self._get_baseline_stats()
        
        # We need enough data and non-zero std_dev to calculate Z-score
        if mean == 0.0 or std_dev == 0.0:
            return None
            
        z_score = (total_entities - mean) / std_dev
        
        if z_score >= self.z_score_threshold:
            anomaly_type = "HIGH_VOLUME_PII"
            desc = f"Scan {scan_id} detected {total_entities} entities, which is {z_score:.1f} standard deviations above the average ({mean:.1f})."
            severity = "HIGH" if z_score < 5.0 else "CRITICAL"
            
            # Log to DB
            self.db.log_anomaly(anomaly_type, desc, severity, scan_id, z_score, mean, total_entities)
            
            # Auto-create incident
            self.db.create_incident(f"Anomaly Detected: {anomaly_type}", desc, severity, "anomaly_detector", scan_id, "system")
            
            return {
                'type': anomaly_type,
                'z_score': z_score,
                'mean': mean,
                'observed': total_entities,
                'severity': severity
            }
            
        return None
