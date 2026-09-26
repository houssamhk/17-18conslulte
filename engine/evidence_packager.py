import os
import json
import zipfile
import datetime
from storage.secure_db import SecureDatabase

class EvidencePackager:
    """
    Generates a secure ZIP archive containing all forensic evidence 
    related to a specific security incident.
    """
    def __init__(self, db: SecureDatabase):
        self.db = db
        
    def generate_package(self, incident_id: int, output_dir: str) -> str:
        """
        Gathers incident data and writes it to a ZIP file.
        Returns the path to the generated ZIP file.
        """
        # Fetch incident
        c = self.db.conn.cursor()
        c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,))
        inc_row = c.fetchone()
        if not inc_row:
            raise ValueError(f"Incident {incident_id} not found.")
            
        incident = {
            'id': inc_row[0],
            'title': inc_row[1],
            'description': inc_row[2],
            'severity': inc_row[3],
            'status': inc_row[4],
            'assigned_to': inc_row[5],
            'source': inc_row[6],       # source_type
            'source_id': inc_row[7],
            'sla_deadline': inc_row[8],
            'resolved_at': inc_row[9],
            'resolution_notes': inc_row[10],
            'created_by': inc_row[11],
            'created_at': inc_row[12],
        }
        
        # Fetch notes
        c.execute("SELECT author, note_text, created_at FROM incident_notes WHERE incident_id=?", (incident_id,))
        notes = [{'author': r[0], 'content': r[1], 'timestamp': r[2]} for r in c.fetchall()]
        
        # Fetch evidence records
        c.execute("SELECT scan_id, description FROM incident_evidence WHERE incident_id=?", (incident_id,))
        evidence = [{'scan_id': r[0], 'description': r[1]} for r in c.fetchall()]
        
        # If source is scan_alert or policy_violation, fetch scan info
        scan_info = None
        if incident['source'] in ['scan_alert', 'policy_violation', 'anomaly_detector', 'scheduled_scan']:
            scan_id = incident['source_id']
            c.execute("SELECT * FROM scan_history WHERE id=?", (scan_id,))
            s_row = c.fetchone()
            if s_row:
                scan_info = {
                    'id': s_row[0],
                    'timestamp': s_row[1],
                    'document_name': s_row[2],
                    'total_entities': s_row[3],
                    'risk_level': s_row[4],
                    'strategy_used': s_row[5],
                    'summary_json': s_row[6],
                    'sensitivity_label': s_row[7]
                }
                
        # Build the JSON payload
        package_data = {
            'export_timestamp': datetime.datetime.now().isoformat(),
            'incident': incident,
            'notes': notes,
            'evidence': evidence,
            'related_scan': scan_info
        }
        
        # Write to ZIP
        filename = f"Incident_{incident_id}_Evidence_{datetime.datetime.now().strftime('%Y%m%d%H%M')}.zip"
        filepath = os.path.join(output_dir, filename)
        
        with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.writestr("incident_report.json", json.dumps(package_data, indent=2, ensure_ascii=False))
            
            # Create a simple text summary
            summary = f"INCIDENT REPORT: {incident['title']}\n"
            summary += f"Severity: {incident['severity']}\n"
            summary += f"Status: {incident['status']}\n"
            summary += f"Created: {incident['created_at']}\n\n"
            summary += f"Description: {incident['description']}\n\n"
            if scan_info:
                summary += f"Related Document: {scan_info['document_name']} (Risk: {scan_info['risk_level']})\n"
                
            zipf.writestr("summary.txt", summary)
            
        return filepath
