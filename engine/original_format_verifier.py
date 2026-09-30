"""Rescan saved Office outputs, including content not handled by redactors."""

import csv
import zipfile
import xml.etree.ElementTree as ET

from .redaction_verifier import RedactionVerifier


def _docx_visible_text(path):
    texts = []
    with zipfile.ZipFile(path) as package:
        for name in package.namelist():
            if name.startswith(("word/", "docProps/")) and name.endswith(".xml"):
                try:
                    root = ET.fromstring(package.read(name))
                except ET.ParseError:
                    continue
                paragraphs = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1] in {"p", "paragraph"}]
                for paragraph in paragraphs:
                    paragraph_text = "".join(
                        node.text or "" for node in paragraph.iter()
                        if node.tag.rsplit("}", 1)[-1] in {"t", "delText", "instrText"}
                    )
                    if paragraph_text:
                        texts.append(paragraph_text)
                if not paragraphs:
                    for node in root.iter():
                        if node.text and node.text.strip():
                            texts.append(node.text)
    return "\n".join(texts)


def _xlsx_visible_text(path):
    import openpyxl

    workbook = openpyxl.load_workbook(path, data_only=False, read_only=False)
    texts = []
    for worksheet in workbook.worksheets:
        for row in worksheet.iter_rows():
            for cell in row:
                if cell.value is not None:
                    texts.append(str(cell.value))
                if cell.comment:
                    texts.extend((cell.comment.text or "", cell.comment.author or ""))
                if cell.hyperlink:
                    texts.extend((cell.hyperlink.target or "", cell.hyperlink.location or ""))
    properties = workbook.properties
    for name in ("title", "subject", "creator", "keywords", "description", "category", "identifier", "language", "lastModifiedBy"):
        value = getattr(properties, name, None)
        if value:
            texts.append(str(value))
    for external_link in getattr(workbook, "_external_links", []):
        texts.append(str(external_link))
    workbook.close()
    return "\n".join(texts)


def _csv_visible_text(path):
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as source:
        return "\n".join("\n".join(row) for row in csv.reader(source))


def _pdf_visible_text(path):
    import fitz

    texts = []
    with fitz.open(path) as document:
        texts.extend(page.get_text() for page in document)
        if document.metadata:
            texts.extend(str(value) for value in document.metadata.values() if value)
        for page in document:
            for link in page.get_links():
                texts.extend(str(value) for value in link.values() if value)
            annotation = page.first_annot
            while annotation:
                texts.extend(str(value) for value in annotation.info.values() if value)
                annotation = annotation.next
            widgets = page.widgets()
            if widgets:
                texts.extend(str(widget.field_value) for widget in widgets if widget.field_value)
    return "\n".join(texts)


def _image_visible_text(path):
    from PIL import Image, ImageOps, ImageSequence
    from .document_parser import DocumentParser
    from .image_redactor import _ocr_frame

    texts = []
    _, language, _ = DocumentParser.get_ocr_config()
    with Image.open(path) as source:
        for frame in ImageSequence.Iterator(source):
            oriented = ImageOps.exif_transpose(frame.copy()).convert("RGB")
            text, _ = _ocr_frame(oriented, language)
            texts.append(text)
    return "\n".join(texts)


def verify_original_format(path, extension, original_scan, engine):
    """Return a value-only verification summary; never return raw leaked values."""
    extension = extension.lower()
    if extension == ".docx":
        output_text = _docx_visible_text(path)
    elif extension == ".xlsx":
        output_text = _xlsx_visible_text(path)
    elif extension == ".csv":
        output_text = _csv_visible_text(path)
    elif extension == ".pdf":
        output_text = _pdf_visible_text(path)
    elif extension in {".png", ".jpg", ".jpeg", ".tiff", ".bmp"}:
        output_text = _image_visible_text(path)
    else:
        raise ValueError(f"Unsupported original-format verification: {extension}")

    residual = engine.scan(output_text).entities
    result = RedactionVerifier.verify(original_scan, output_text, residual)
    return {
        "passed": result.is_successful,
        "masking_percentage": round(result.masking_percentage, 2),
        "remaining_original_count": len(result.leaked_entities),
        "additional_candidate_count": len(result.residual_entities),
        "details": result.details,
    }
