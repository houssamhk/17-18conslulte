"""OCR-guided raster redaction with fail-closed coordinate mapping."""

import os
import shutil


def _ocr_frame(frame, language=None):
    import cv2
    import numpy as np
    import pytesseract
    from PIL import Image
    from pytesseract import Output

    from .document_parser import DocumentParser
    enabled, configured_language, tesseract_path = DocumentParser.get_ocr_config()
    if not enabled:
        raise RuntimeError("تم تعطيل OCR من الإعدادات؛ لم تُنشأ نسخة صورة غير مكتملة.")
    language = language or configured_language
    if tesseract_path:
        if not os.path.isfile(tesseract_path):
            raise RuntimeError("مسار Tesseract المحدد غير موجود: " + tesseract_path)
        pytesseract.pytesseract.tesseract_cmd = tesseract_path
    else:
        path_from_env = shutil.which("tesseract")
        if not path_from_env:
            raise RuntimeError("Tesseract OCR غير موجود في PATH. حدّد مسار tesseract.exe من الإعدادات.")
        pytesseract.pytesseract.tesseract_cmd = path_from_env

    rgb = np.asarray(frame.convert("RGB"))
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    denoised = cv2.fastNlMeansDenoising(gray, h=30)
    _, thresholded = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    ocr_image = Image.fromarray(thresholded)
    try:
        data = pytesseract.image_to_data(ocr_image, lang=language, output_type=Output.DICT)
    except pytesseract.TesseractNotFoundError as exc:
        raise RuntimeError(
            "تنقيح الصور يحتاج تثبيت Tesseract OCR وإضافة مساره إلى PATH. لم تُنشأ نسخة غير مكتملة."
        ) from exc

    tokens = []
    parts = []
    cursor = 0
    for index, value in enumerate(data.get("text", [])):
        token = str(value).strip()
        if not token:
            continue
        if parts:
            cursor += 1
        start = cursor
        parts.append(token)
        cursor += len(token)
        box = (
            int(data["left"][index]),
            int(data["top"][index]),
            int(data["left"][index]) + int(data["width"][index]),
            int(data["top"][index]) + int(data["height"][index]),
        )
        tokens.append((start, cursor, box))
    return " ".join(parts), tokens


def redact_image(input_path, output_path, engine, strategy="legal", language=None):
    """Create a raster copy with OCR-located entity boxes permanently obscured."""
    from PIL import Image, ImageDraw, ImageOps, ImageSequence

    source = Image.open(input_path)
    frames = [ImageOps.exif_transpose(frame.copy()).convert("RGB") for frame in ImageSequence.Iterator(source)]
    if not frames:
        source.close()
        raise RuntimeError("تعذر قراءة إطارات الصورة.")

    frame_data = []
    text_parts = []
    cursor = 0
    for frame in frames:
        text, tokens = _ocr_frame(frame, language)
        frame_data.append((text, tokens, cursor, cursor + len(text)))
        text_parts.append(text)
        cursor += len(text) + 1
    original_text = "\n".join(text_parts)
    result = engine.anonymize(original_text, strategy)

    masks_by_frame = [[] for _ in frames]
    for frame_index, (text, tokens, start, end) in enumerate(frame_data):
        entities = [entity for entity in result.entities if entity.start >= start and entity.end <= end]
        for entity in entities:
            local_start, local_end = entity.start - start, entity.end - start
            boxes = [box for token_start, token_end, box in tokens if token_start < local_end and local_start < token_end]
            if not boxes:
                source.close()
                raise RuntimeError(
                    f"اكتُشفت بيانات حساسة في الصورة لكن تعذر تحديد موضعها؛ لم تُنشأ نسخة جزئية."
                )
            masks_by_frame[frame_index].extend(boxes)

    redacted_frames = []
    for frame, boxes in zip(frames, masks_by_frame):
        redacted = frame.copy()
        draw = ImageDraw.Draw(redacted)
        for left, top, right, bottom in boxes:
            margin = max(2, round(min(frame.size) * 0.002))
            draw.rectangle(
                (max(0, left - margin), max(0, top - margin), min(frame.width, right + margin), min(frame.height, bottom + margin)),
                fill="black",
            )
        redacted_frames.append(redacted)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    image_format = source.format or os.path.splitext(output_path)[1].lstrip(".").upper()
    save_options = {}
    if image_format.upper() in {"JPEG", "JPG"}:
        image_format = "JPEG"
        save_options["quality"] = 95
    if len(redacted_frames) > 1:
        redacted_frames[0].save(
            output_path,
            format=image_format,
            save_all=True,
            append_images=redacted_frames[1:],
            **save_options,
        )
    else:
        redacted_frames[0].save(output_path, format=image_format, **save_options)
    source.close()
    result.original_format_output = output_path
    return result
