"""Apply permanent text redactions to searchable PDF pages."""

import os


def redact_pdf(input_path, output_path, engine, strategy="legal"):
    """Create a redacted PDF copy; fail closed when a detected span has no box."""
    import fitz

    document = fitz.open(input_path)
    if document.is_encrypted and not document.is_authenticated:
        document.close()
        raise RuntimeError("ملف PDF محمي بكلمة مرور ولا يمكن تنقيحه بأمان.")

    page_texts = []
    page_ranges = []
    cursor = 0
    for page_number, page in enumerate(document):
        page_text = page.get_text().strip()
        if not page_text and page.get_images(full=True):
            document.close()
            raise RuntimeError(
                f"الصفحة {page_number + 1} ممسوحة ضوئيًا ولا يمكن تحديد مواضع الحجب بدقة؛ لم تُنشأ نسخة PDF جزئية."
            )
        start = cursor
        page_texts.append(page_text)
        cursor += len(page_text) + 2
        page_ranges.append((page_number, page_text, start, start + len(page_text)))

    original_text = "\n\n".join(page_texts)
    result = engine.anonymize(original_text, strategy)
    redaction_count = 0
    for page_number, page_text, start, end in page_ranges:
        entities = [
            entity for entity in result.entities
            if entity.start >= start and entity.end <= end
        ]
        if not entities:
            continue
        page = document[page_number]
        for entity in entities:
            boxes = page.search_for(entity.text, quads=True)
            if not boxes:
                document.close()
                raise RuntimeError(
                    f"تعذر تحديد موضع كيان مكتشف في الصفحة {page_number + 1}؛ لم تُنشأ نسخة PDF جزئية."
                )
            for box in boxes:
                page.add_redact_annot(box, fill=(0, 0, 0), cross_out=False)
                redaction_count += 1

    if redaction_count:
        for page in document:
            if page.first_annot:
                page.apply_redactions(images=2, graphics=2, text=0)

    for name in document.embfile_names():
        document.embfile_del(name)
    document.set_metadata({})
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    document.save(output_path, garbage=4, deflate=True, preserve_metadata=0)
    document.close()
    result.original_format_output = output_path
    return result
