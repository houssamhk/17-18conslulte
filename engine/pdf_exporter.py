import os
import logging
import sys
from datetime import datetime
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# Arabic support
import arabic_reshaper
from bidi.algorithm import get_display

from .regex_detector import AnonymizedResult, ComplianceReport

class PDFExporter:
    """Exports Scan Results to a Professional PDF Compliance Report with Arabic support."""
    
    FONT_NAME = "Amiri"
    FONT_PATH = os.path.join("assets", "Amiri-Regular.ttf")
    
    @classmethod
    def _ensure_arabic_font(cls):
        """Find a local Arabic-capable font; report generation never downloads files."""
        try:
            app_root = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            candidates = [
                os.path.join(app_root, cls.FONT_PATH),
                os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "arial.ttf"),
                os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "tahoma.ttf"),
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            ]
            for font_path in candidates:
                if os.path.isfile(font_path):
                    pdfmetrics.registerFont(TTFont(cls.FONT_NAME, font_path))
                    return True
            logging.warning("No local Arabic font found; PDF will use the built-in fallback font.")
            return False
        except Exception as e:
            logging.error(f"Font setup failed: {e}")
            return False

    @staticmethod
    def _format_arabic(text: str) -> str:
        """Reshapes and applies BiDi algorithm to Arabic text for PDF rendering."""
        try:
            reshaped_text = arabic_reshaper.reshape(text)
            bidi_text = get_display(reshaped_text)
            return bidi_text
        except Exception:
            return text

    @classmethod
    def _safe_paragraph(cls, text: str, style):
        """Escape user-controlled text before passing it to ReportLab's XML parser."""
        formatted = cls._format_arabic(str(text or ""))
        return Paragraph(escape(formatted), style)

    @classmethod
    def _labeled_paragraph(cls, label: str, value, style):
        """Keep the trusted label formatting while escaping the supplied value."""
        safe_label = escape(cls._format_arabic(label))
        safe_value = escape(cls._format_arabic(str(value or "")))
        return Paragraph(f"<b>{safe_label}</b> {safe_value}", style)

    @classmethod
    def export_report(cls, result: AnonymizedResult, report: ComplianceReport, file_path: str):
        try:
            # Ensure font is available
            has_arabic_font = cls._ensure_arabic_font()
            font_family = cls.FONT_NAME if has_arabic_font else 'Helvetica'
            
            doc = SimpleDocTemplate(file_path, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
            styles = getSampleStyleSheet()
            
            # Custom Styles
            title_style = ParagraphStyle(
                'TitleStyle',
                parent=styles['Heading1'],
                fontName=font_family,
                fontSize=18,
                spaceAfter=14,
                textColor=colors.HexColor('#0f3460')
            )
            
            subtitle_style = ParagraphStyle(
                'SubTitleStyle',
                parent=styles['Normal'],
                fontName=font_family,
                fontSize=12,
                spaceAfter=14,
                textColor=colors.HexColor('#a0a0a0')
            )
            
            content_style = ParagraphStyle(
                'ContentStyle',
                parent=styles['Normal'],
                fontName=font_family,
                fontSize=12,
                spaceAfter=12,
                leading=18,
                alignment=2 if has_arabic_font else 0  # Align right (2) for Arabic
            )

            story = []
            
            # Header
            story.append(Paragraph(cls._format_arabic("محرك الامتثال الجزائري | تقرير الامتثال"), title_style))
            story.append(Paragraph(cls._format_arabic("Alg-PII Engine — Compliance Report"), subtitle_style))
            story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
            story.append(Spacer(1, 12))
            
            # Summary Metrics
            story.append(Paragraph(cls._format_arabic("ملخص الفحص (Scan Summary)"), title_style))
            
            counts = {}
            for ent in result.entities:
                counts[ent.entity_type] = counts.get(ent.entity_type, 0) + 1
                
            total_entities = sum(counts.values())
            story.append(Paragraph(cls._format_arabic(f"إجمالي الكيانات الحساسة: {total_entities}"), content_style))
            story.append(cls._safe_paragraph(f"استراتيجية التمويه: {result.strategy}", content_style))
            
            # Details Table
            if counts:
                story.append(Spacer(1, 12))
                data = [[cls._format_arabic("النوع (Type)"), cls._format_arabic("العدد (Count)")]]
                for k, v in counts.items():
                    data.append([cls._format_arabic(k), str(v)])
                    
                t = Table(data, colWidths=[200, 100])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e94560')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, -1), font_family),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f0f0')),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#0f3460'))
                ]))
                story.append(t)
                
            story.append(Spacer(1, 24))
            
            # Legal References
            if report.applicable_articles:
                story.append(Paragraph(cls._format_arabic("المراجع القانونية (Legal References)"), title_style))
                for article in report.applicable_articles:
                    law_text = f"{article['law_name']} ({article['law_number']}) - {article['article_number']}: {article['article_title_ar']}"
                    story.append(cls._safe_paragraph(law_text, content_style))
                    summary_text = f"الملخص: {article['article_summary_ar']}"
                    story.append(cls._safe_paragraph(summary_text, subtitle_style))
                    penalty_text = f"العقوبة: {article['penalty_description_ar']}"
                    story.append(cls._safe_paragraph(penalty_text, subtitle_style))
                    story.append(Spacer(1, 6))
                story.append(Spacer(1, 18))
            
            # Anonymized Text Content
            story.append(Paragraph(cls._format_arabic("محتوى المستند المعالج (Anonymized Content)"), title_style))
            
            # Process lines
            text_lines = result.anonymized_text.split('\n')
            for line in text_lines:
                if line.strip():
                    story.append(cls._safe_paragraph(line, content_style))
                    
            doc.build(story)
            logging.info(f"Successfully generated Arabic PDF report at {file_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to generate PDF report: {e}")
            raise RuntimeError(f"PDF Generation failed: {str(e)}")

    @classmethod
    def export_pia(cls, pia_data: dict, file_path: str) -> bool:
        """Exports a PIA Assessment to PDF."""
        has_arabic = cls._ensure_arabic_font()
        
        try:
            doc = SimpleDocTemplate(file_path, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            story = []
            
            styles = getSampleStyleSheet()
            
            # Create custom styles
            title_style = ParagraphStyle(
                'CustomTitle', parent=styles['Heading1'], fontName=cls.FONT_NAME if has_arabic else 'Helvetica-Bold',
                fontSize=18, spaceAfter=20, alignment=1 # Center
            )
            heading_style = ParagraphStyle(
                'CustomHeading', parent=styles['Heading2'], fontName=cls.FONT_NAME if has_arabic else 'Helvetica-Bold',
                fontSize=14, spaceAfter=10, spaceBefore=15
            )
            content_style = ParagraphStyle(
                'CustomContent', parent=styles['Normal'], fontName=cls.FONT_NAME if has_arabic else 'Helvetica',
                fontSize=11, spaceAfter=6, leading=16
            )
            
            story.append(Paragraph(cls._format_arabic("تقرير تقييم أثر الخصوصية (Privacy Impact Assessment)"), title_style))
            story.append(Spacer(1, 12))
            
            # Project details
            story.append(Paragraph(cls._format_arabic("1. تفاصيل المشروع"), heading_style))
            story.append(cls._labeled_paragraph("المشروع:", pia_data.get('project_name'), content_style))
            story.append(cls._labeled_paragraph("القسم:", pia_data.get('department'), content_style))
            story.append(cls._labeled_paragraph("المقيِّم:", pia_data.get('assessor_name'), content_style))
            story.append(cls._labeled_paragraph("تاريخ التقييم:", pia_data.get('created_at'), content_style))
            
            story.append(Spacer(1, 12))
            
            story.append(Paragraph(cls._format_arabic("2. الغرض من المعالجة"), heading_style))
            story.append(cls._safe_paragraph(pia_data.get('processing_purpose', ''), content_style))
            
            story.append(Spacer(1, 12))
            
            story.append(Paragraph(cls._format_arabic("3. فئات البيانات الشخصية"), heading_style))
            data_types = pia_data.get('data_types', [])
            if isinstance(data_types, str):
                import json
                try:
                    data_types = json.loads(data_types)
                except:
                    data_types = [data_types]
            for dt in data_types:
                story.append(cls._safe_paragraph(f"• {dt}", content_style))
                
            story.append(Spacer(1, 12))
            
            story.append(Paragraph(cls._format_arabic("4. تقييم المخاطر والتخفيف"), heading_style))
            story.append(cls._labeled_paragraph("مستوى الخطر:", pia_data.get('risk_level'), content_style))
            story.append(Paragraph(cls._format_arabic("<b>التدابير الأمنية المتخذة:</b>"), content_style))
            story.append(cls._safe_paragraph(pia_data.get('mitigation_steps', ''), content_style))
            
            doc.build(story)
            logging.info(f"Successfully generated PIA PDF report at {file_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to generate PIA PDF report: {e}")
            raise RuntimeError(f"PIA PDF Generation failed: {str(e)}")

    @classmethod
    def export_with_template(cls, result: AnonymizedResult, report: ComplianceReport, file_path: str, template_json: str):
        """Exports a PDF using a custom template layout."""
        import json
        try:
            sections = json.loads(template_json)
        except Exception:
            sections = ["Header", "Entity Table"]
            
        has_arabic_font = cls._ensure_arabic_font()
        font_family = cls.FONT_NAME if has_arabic_font else 'Helvetica'
        
        doc = SimpleDocTemplate(file_path, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'TitleStyle', parent=styles['Heading1'], fontName=font_family, fontSize=18, spaceAfter=14, textColor=colors.HexColor('#0f3460')
        )
        content_style = ParagraphStyle(
            'ContentStyle', parent=styles['Normal'], fontName=font_family, fontSize=12, spaceAfter=12, leading=18, alignment=2 if has_arabic_font else 0
        )
        
        story = []
        for sec in sections:
            if sec == "Header":
                story.append(Paragraph(cls._format_arabic("محرك الامتثال الجزائري | تقرير مخصص"), title_style))
                story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", content_style))
                story.append(Spacer(1, 12))
            elif sec == "Entity Table":
                counts = {}
                for ent in result.entities:
                    counts[ent.entity_type] = counts.get(ent.entity_type, 0) + 1
                if counts:
                    data = [[cls._format_arabic("النوع (Type)"), cls._format_arabic("العدد (Count)")]]
                    for k, v in counts.items():
                        data.append([cls._format_arabic(k), str(v)])
                    t = Table(data, colWidths=[200, 100])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e94560')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, -1), font_family),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#0f3460'))
                    ]))
                    story.append(t)
                story.append(Spacer(1, 12))
            elif sec == "Risk Summary":
                story.append(Paragraph(cls._format_arabic("ملخص المخاطر"), title_style))
                story.append(Paragraph(cls._format_arabic(f"مستوى الخطر: {report.risk_level}"), content_style))
                story.append(Spacer(1, 12))
            elif sec == "Legal References":
                story.append(Paragraph(cls._format_arabic("المراجع القانونية"), title_style))
                for ref in report.law_references:
                    story.append(cls._safe_paragraph(ref, content_style))
                story.append(Spacer(1, 12))
            elif sec == "Signature Block":
                story.append(Spacer(1, 50))
                story.append(Paragraph(cls._format_arabic("التوقيع (Signature): ____________________"), content_style))
                
        doc.build(story)
        return True
