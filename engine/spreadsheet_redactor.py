"""Redact detected PII in Excel cells while keeping workbook structure."""

import os
from dataclasses import replace

from .regex_detector import AnonymizedResult


def redact_xlsx(input_path, output_path, engine, strategy="legal"):
    """Create a redacted XLSX copy and return the aggregate scan result.

    Cell values are scanned as separate text segments. Sheets, cell positions,
    and existing cell styles are retained by openpyxl. Formula cells are left
    untouched to avoid changing workbook calculations.
    """
    import openpyxl

    workbook = openpyxl.load_workbook(input_path, data_only=False)
    segments = []
    cells = []
    cursor = 0
    for worksheet in workbook.worksheets:
        for row in worksheet.iter_rows():
            for cell in row:
                value = cell.value
                if isinstance(value, str):
                    cell_text = value
                elif isinstance(value, (int, float)) and not isinstance(value, bool):
                    cell_text = str(value)
                else:
                    continue
                if not cell_text:
                    continue
                start = cursor
                segments.append(cell_text)
                cells.append((worksheet, cell, cell_text, start, start + len(cell_text)))
                cursor += len(cell_text) + 1

    original_text = "\n".join(segments)
    result = engine.anonymize(original_text, strategy)

    for worksheet, cell, cell_text, start, end in cells:
        local_entities = [
            replace(entity, start=entity.start - start, end=entity.end - start)
            for entity in result.entities
            if entity.start >= start and entity.end <= end
        ]
        if local_entities:
            redacted_value, _ = engine.anonymizer.anonymize(cell_text, local_entities, strategy)
            cell.value = redacted_value

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    workbook.save(output_path)
    workbook.close()
    result.original_format_output = output_path
    return result
