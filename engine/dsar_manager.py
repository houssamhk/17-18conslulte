import os
import hashlib
from typing import List, Dict
from storage.secure_db import SecureDatabase

class DSARManager:
    """
    Manages Data Subject Access Requests (DSAR).
    Searches the entity index for a given subject identity and compiles
    a report of all documents containing their data.
    """
    def __init__(self, db: SecureDatabase):
        self.db = db
        
    def find_subject_data(self, subject_identity: str) -> List[Dict]:
        """
        Searches the entity index for exact matches of the subject's identity
        (which could be a Name, NIN, Email, etc).
        Returns a list of occurrences with document names and context.
        """
        # Hash the identity as we do when indexing
        ent_hash = hashlib.sha256(subject_identity.lower().encode('utf-8')).hexdigest()
        
        c = self.db.conn.cursor()
        c.execute('''SELECT document_name, scan_id, department, indexed_at 
                     FROM entity_index 
                     WHERE entity_hash=?''', (ent_hash,))
                     
        results = []
        for row in c.fetchall():
            results.append({
                'document_name': row[0],
                'scan_id': row[1],
                'department': row[2],
                'indexed_at': row[3]
            })
            
        return results

    def generate_dsar_report(self, request_id: int, subject_identity: str, output_path: str):
        """
        Generates a formal PDF response for a DSAR containing all discovered data locations.
        """
        data_locations = self.find_subject_data(subject_identity)
        
        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
        except ImportError:
            raise ImportError("reportlab is required for PDF generation")
            
        # Update the DSAR request record with the findings
        c = self.db.conn.cursor()
        c.execute("UPDATE dsar_requests SET entities_found=?, documents_affected=?, response_pdf_path=? WHERE id=?",
                  (len(data_locations), len(set([d['document_name'] for d in data_locations])), output_path, request_id))
        self.db.conn.commit()
        
        c = canvas.Canvas(output_path, pagesize=A4)
        width, height = A4
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "Data Subject Access Request (DSAR) Response")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 70, f"Subject: {subject_identity}")
        c.drawString(50, height - 90, f"Total records found: {len(data_locations)}")
        
        y = height - 130
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Document")
        c.drawString(300, y, "Department")
        c.drawString(450, y, "Date Indexed")
        y -= 20
        
        c.setFont("Helvetica", 10)
        for loc in data_locations:
            if y < 50:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 10)
                
            c.drawString(50, y, str(loc['document_name'])[:40])
            c.drawString(300, y, str(loc['department'] or 'Global'))
            c.drawString(450, y, str(loc['indexed_at']).split('.')[0])
            y -= 15
            
        c.save()
        
        return output_path
