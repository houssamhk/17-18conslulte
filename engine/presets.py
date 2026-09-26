# Predefined compliance presets for different industries
INDUSTRY_PRESETS = {
    "Banking": {
        "description_ar": "قطاع البنوك والمالية",
        "description_en": "Banking & Finance Sector",
        "anonymization_strategy": "full_mask",
        "custom_keywords": ["رقم الحساب", "رصيد", "بطاقة ائتمان", "قرض", "RIB", "CCP", "IBAN", "SWIFT"],
        "min_risk_level": "HIGH",
        "nlp_enabled": True
    },
    "Healthcare": {
        "description_ar": "قطاع الصحة والمستشفيات",
        "description_en": "Healthcare & Hospitals",
        "anonymization_strategy": "pseudonymize",
        "custom_keywords": ["مريض", "تشخيص", "وصفة", "طبيب", "عيادة", "فصيلة الدم", "مرض", "علاج"],
        "min_risk_level": "CRITICAL",
        "nlp_enabled": True
    },
    "Government": {
        "description_ar": "القطاع الحكومي والإدارة العامة",
        "description_en": "Government & Public Administration",
        "anonymization_strategy": "legal_mask",
        "custom_keywords": ["سري", "قرار", "مرسوم", "وثيقة رسمية", "وزارة", "ولاية", "بلدية", "دائرة"],
        "min_risk_level": "MEDIUM",
        "nlp_enabled": True
    },
    "Education": {
        "description_ar": "قطاع التعليم والجامعات",
        "description_en": "Education & Universities",
        "anonymization_strategy": "partial_mask",
        "custom_keywords": ["طالب", "تلميذ", "علامة", "معدل", "امتحان", "مدرسة", "جامعة", "أستاذ"],
        "min_risk_level": "LOW",
        "nlp_enabled": False
    },
    "General": {
        "description_ar": "عام (بدون تخصيص)",
        "description_en": "General (Unspecialized)",
        "anonymization_strategy": "legal_mask",
        "custom_keywords": [],
        "min_risk_level": "LOW",
        "nlp_enabled": True
    }
}
