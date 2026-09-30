"""Read-only application readiness checks for administrators."""

import importlib.metadata
import os
import shutil
import sys

from storage.key_manager import KeyManager
from .document_parser import DocumentParser


def collect_system_diagnostics(db, engine=None):
    results = []

    def add(name, status, details):
        results.append({"name": name, "status": status, "details": str(details)})

    try:
        db.conn.execute("SELECT 1").fetchone()
        encrypted = bool(getattr(db, "_use_sqlcipher", False))
        add(
            "قاعدة البيانات",
            "جاهز" if encrypted else "فشل",
            "اتصال SQLCipher نشط والتخزين مشفر." if encrypted else "الاتصال لا يستخدم SQLCipher.",
        )
    except Exception as exc:
        add("قاعدة البيانات", "فشل", f"تعذر الاستعلام عن قاعدة البيانات: {exc}")

    try:
        key_available = KeyManager.key_exists()
        add(
            "مفتاح النظام",
            "جاهز" if key_available else "فشل",
            "المفتاح موجود في مخزن بيانات اعتماد النظام." if key_available else "مفتاح التشفير غير متاح في مخزن النظام.",
        )
    except Exception as exc:
        add("مفتاح النظام", "فشل", f"تعذر فحص مخزن المفاتيح: {exc}")

    ocr_enabled, language, tesseract_path = DocumentParser.get_ocr_config()
    if not ocr_enabled:
        add("OCR", "غير مفعّل", "تعرف الصور وPDF الممسوح معطل من الإعدادات.")
    else:
        ready, message = DocumentParser.validate_ocr_configuration(language, tesseract_path)
        add("OCR", "جاهز" if ready else "يحتاج إعدادًا", message)

    nlp_enabled = bool(db.get_setting("nlp_enabled", False))
    if not nlp_enabled:
        add("نموذج NLP", "غير مفعّل", "يعمل التطبيق بالكشف المحلي القائم على القواعد.")
    elif engine and engine.is_nlp_available():
        add("نموذج NLP", "جاهز", "النموذج المحلي محمّل.")
    else:
        model_path = db.get_setting("model_path", "")
        add("نموذج NLP", "يحتاج إعدادًا", f"النموذج غير محمّل. المسار المحدد: {model_path or 'افتراضي'}")

    database_path = getattr(db, "db_path", "")
    data_dir = os.path.dirname(os.path.abspath(database_path)) if database_path else os.getcwd()
    try:
        usage = shutil.disk_usage(data_dir)
        writable = os.path.isdir(data_dir) and os.access(data_dir, os.W_OK)
        free_mb = usage.free // (1024 * 1024)
        status = "جاهز" if writable and free_mb >= 256 else "تحذير"
        details = f"المجلد متاح للكتابة: {'نعم' if writable else 'لا'}؛ المساحة الحرة: {free_mb} MB."
        if free_mb < 256:
            details += " المساحة الحرة منخفضة."
        add("التخزين المحلي", status, details)
    except Exception as exc:
        add("التخزين المحلي", "فشل", f"تعذر فحص مساحة التخزين: {exc}")

    add("Python", "معلومات", sys.version.split()[0])
    for package, label in (("PyQt6", "PyQt6"), ("PyMuPDF", "PyMuPDF"), ("openpyxl", "openpyxl"), ("python-docx", "python-docx")):
        try:
            add(label, "معلومات", importlib.metadata.version(package))
        except importlib.metadata.PackageNotFoundError:
            add(label, "غير مثبت", "الحزمة غير موجودة في بيئة التشغيل الحالية.")

    return results
