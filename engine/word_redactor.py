"""Conservative DOCX redaction that retains paragraph and run formatting."""

import os
from dataclasses import replace


def _walk_paragraphs(container):
    for paragraph in container.paragraphs:
        yield paragraph
    for table in container.tables:
        for row in table.rows:
            for cell in row.cells:
                yield from _walk_paragraphs(cell)


def redact_docx(input_path, output_path, engine, strategy="legal"):
    """Redact detected text in paragraphs, tables, headers, and footers.

    A redaction spanning Word runs is distributed back across those runs so
    surrounding run styling remains intact. Paragraphs with non-text run XML
    are rejected when they contain a match to avoid deleting embedded objects.
    """
    import docx

    document = docx.Document(input_path)
    paragraphs = []
    seen = set()
    containers = [document]
    for section in document.sections:
        containers.extend((
            section.header, section.footer,
            section.first_page_header, section.first_page_footer,
            section.even_page_header, section.even_page_footer,
        ))
    for container in containers:
        for paragraph in _walk_paragraphs(container):
            identity = id(paragraph._p)
            if identity not in seen:
                seen.add(identity)
                paragraphs.append(paragraph)

    chunks = []
    paragraph_ranges = []
    cursor = 0
    for paragraph in paragraphs:
        run_texts = [run.text for run in paragraph.runs]
        text = "".join(run_texts)
        if paragraph.text != text:
            raise RuntimeError(
                "DOCX يحتوي نصًا في روابط أو عناصر غير مدعومة؛ لم تُنشأ نسخة قد تكون ناقصة."
            )
        start = cursor
        chunks.append(text)
        cursor += len(text) + 1
        paragraph_ranges.append((paragraph, run_texts, text, start, start + len(text)))

    original_text = "\n".join(chunks)
    result = engine.anonymize(original_text, strategy)

    for paragraph, run_texts, text, start, end in paragraph_ranges:
        entities = [
            replace(entity, start=entity.start - start, end=entity.end - start)
            for entity in result.entities
            if entity.start >= start and entity.end <= end
        ]
        if not entities:
            continue

        runs = paragraph.runs
        for run in runs:
            unsupported = [child for child in run._r if child.tag.rsplit("}", 1)[-1] not in {"rPr", "t"}]
            if unsupported:
                raise RuntimeError(
                    "تعذر تنقيح فقرة تحتوي صورة أو عنصرًا مضمّنًا؛ لم تُنشأ نسخة DOCX جزئية."
                )

        run_ends = []
        run_cursor = 0
        for run_text in run_texts:
            run_cursor += len(run_text)
            run_ends.append(run_cursor)
        output_by_run = [[] for _ in runs]

        def append_original(left, right):
            while left < right:
                run_index = next((i for i, run_end in enumerate(run_ends) if left < run_end), len(runs) - 1)
                run_start = 0 if run_index == 0 else run_ends[run_index - 1]
                segment_end = min(right, run_ends[run_index])
                output_by_run[run_index].append(text[left:segment_end])
                left = segment_end

        position = 0
        for entity in sorted(entities, key=lambda item: item.start):
            append_original(position, entity.start)
            run_index = next((i for i, run_end in enumerate(run_ends) if entity.start < run_end), len(runs) - 1)
            output_by_run[run_index].append(engine.anonymizer._get_replacement(entity, strategy))
            position = entity.end
        append_original(position, len(text))

        for run, parts in zip(runs, output_by_run):
            run.text = "".join(parts)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    document.save(output_path)
    result.original_format_output = output_path
    return result
