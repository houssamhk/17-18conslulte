import json
import xml.etree.ElementTree as ET
import csv
import io
from .regex_detector import ScanResult, ComplianceReport, DetectedEntity


def _get_law_ref(e: DetectedEntity) -> str:
    """Safely get law_reference from entity (if it has the attribute)."""
    return getattr(e, 'law_reference', '') or ''


class ReportExporter:
    @staticmethod
    def to_json(result: ScanResult, report: ComplianceReport) -> str:
        data = {
            "risk_level": report.risk_level,
            "sensitivity_label": report.sensitivity_label,
            "recommendations": report.recommendations,
            "clusters": report.clusters,
            "entities": [
                {
                    "type": e.entity_type,
                    "value": e.text,
                    "confidence": e.confidence,
                    "source": e.source,
                    "law_reference": _get_law_ref(e),
                    "position": {"start": e.start, "end": e.end}
                } for e in result.entities
            ]
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    @staticmethod
    def to_xml(result: ScanResult, report: ComplianceReport) -> str:
        root = ET.Element("ComplianceReport")
        
        ET.SubElement(root, "RiskLevel").text = report.risk_level
        ET.SubElement(root, "SensitivityLabel").text = report.sensitivity_label
        
        recs = ET.SubElement(root, "Recommendations")
        for rec in report.recommendations:
            ET.SubElement(recs, "Recommendation").text = rec
            
        ents = ET.SubElement(root, "Entities")
        for e in result.entities:
            ent = ET.SubElement(ents, "Entity")
            ET.SubElement(ent, "Type").text = e.entity_type
            ET.SubElement(ent, "Value").text = e.text
            ET.SubElement(ent, "Confidence").text = str(e.confidence)
            ET.SubElement(ent, "LawReference").text = _get_law_ref(e)
            
        xml_str = ET.tostring(root, encoding='utf-8')
        try:
            import xml.dom.minidom
            parsed = xml.dom.minidom.parseString(xml_str)
            return parsed.toprettyxml(indent="  ")
        except Exception:
            return xml_str.decode('utf-8')
            
    @staticmethod
    def to_csv(result: ScanResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Type", "Value", "Confidence", "Source", "Law Reference"])
        for e in result.entities:
            writer.writerow([e.entity_type, e.text, e.confidence, e.source, _get_law_ref(e)])
        return output.getvalue()
        
    @staticmethod
    def save_docx(result: ScanResult, report: ComplianceReport, file_path: str):
        try:
            from docx import Document
        except ImportError:
            raise ImportError("python-docx is not installed. Please 'pip install python-docx'.")
            
        doc = Document()
        doc.add_heading('تقرير امتثال Alg-PII Engine', 0)
        
        doc.add_heading('الملخص', level=1)
        doc.add_paragraph(f"مستوى الخطر: {report.risk_level}")
        doc.add_paragraph(f"التصنيف: {report.sensitivity_label}")
        
        doc.add_heading('التوصيات', level=1)
        for r in report.recommendations:
            doc.add_paragraph(r, style='List Bullet')
            
        doc.add_heading('الكيانات المكتشفة', level=1)
        table = doc.add_table(rows=1, cols=4)
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = 'النوع'
        hdr_cells[1].text = 'القيمة'
        hdr_cells[2].text = 'الثقة'
        hdr_cells[3].text = 'المرجع القانوني'
        
        for e in result.entities:
            row_cells = table.add_row().cells
            row_cells[0].text = e.entity_type
            row_cells[1].text = e.text
            row_cells[2].text = str(e.confidence)
            row_cells[3].text = _get_law_ref(e)
            
        doc.save(file_path)
        
    @staticmethod
    def save_xlsx(result: ScanResult, file_path: str):
        try:
            from openpyxl import Workbook
        except ImportError:
            raise ImportError("openpyxl is not installed. Please 'pip install openpyxl'.")
            
        wb = Workbook()
        ws = wb.active
        ws.title = "Detected Entities"
        
        ws.append(["Type", "Value", "Confidence", "Source", "Law Reference"])
        
        for e in result.entities:
            ws.append([e.entity_type, e.text, e.confidence, e.source, _get_law_ref(e)])
            
        wb.save(file_path)
