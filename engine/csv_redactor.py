"""Redact CSV fields while retaining row and column structure."""

import csv
import os
from dataclasses import replace


def redact_csv(input_path, output_path, engine, strategy="legal"):
    """Write an anonymized CSV copy and return its aggregate scan result."""
    with open(input_path, "r", encoding="utf-8-sig", errors="replace", newline="") as source:
        sample = source.read(8192)
        source.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except csv.Error:
            dialect = csv.excel
        rows = list(csv.reader(source, dialect))

    segments = []
    locations = []
    cursor = 0
    for row_index, row in enumerate(rows):
        for column_index, value in enumerate(row):
            if not value:
                continue
            start = cursor
            segments.append(value)
            locations.append((row_index, column_index, value, start, start + len(value)))
            cursor += len(value) + 1

    original_text = "\n".join(segments)
    result = engine.anonymize(original_text, strategy)
    for row_index, column_index, value, start, end in locations:
        entities = [
            replace(entity, start=entity.start - start, end=entity.end - start)
            for entity in result.entities
            if entity.start >= start and entity.end <= end
        ]
        if entities:
            rows[row_index][column_index], _ = engine.anonymizer.anonymize(value, entities, strategy)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8-sig", newline="") as destination:
        writer = csv.writer(destination, dialect)
        writer.writerows(rows)
    result.original_format_output = output_path
    return result
