"""Shared password length policy and local strength guidance."""

MIN_PASSWORD_LENGTH = 14
MAX_PASSWORD_BYTES = 72  # bcrypt's input limit


def password_is_valid(password: str) -> bool:
    password = password or ""
    if len(password) < MIN_PASSWORD_LENGTH or len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False
    if len(set(password)) < 8:
        return False
    for pattern_length in (1, 2, 3):
        pattern = password[:pattern_length]
        if pattern and password == (pattern * (len(password) // pattern_length + 1))[:len(password)]:
            return False
    return True


def password_strength_hint(password: str) -> tuple[str, str]:
    """Return (Arabic guidance, color key) without sending the password anywhere."""
    password = password or ""
    if not password:
        return "استخدم عبارة مرور طويلة يسهل تذكرها ويصعب تخمينها.", "TEXT_SECONDARY"
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"قصيرة؛ الحد الأدنى {MIN_PASSWORD_LENGTH} محرفًا.", "WARNING"
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return "تجاوزت حد bcrypt البالغ 72 بايتًا؛ قلّل طولها.", "ERROR"

    # Unicode-aware diversity: Arabic letters, Latin letters, numbers, and symbols.
    categories = set()
    for char in password:
        if char.isalpha():
            categories.add("letters")
            if char.isupper():
                categories.add("uppercase")
        elif char.isdecimal():
            categories.add("numbers")
        else:
            categories.add("symbols")
    if not password_is_valid(password):
        return "ضعيفة؛ تجنب التكرار والأنماط المتوقعة.", "ERROR"
    if len(password) >= 24 and len(categories) >= 2:
        return "قوية جدًا — عبارة طويلة ومتنوعة.", "SUCCESS"
    if len(password) >= 18 and len(categories) >= 2:
        return "قوية — طول وتنوع جيدان.", "SUCCESS"
    return "مقبولة؛ زد الطول أو التنوع لرفع قوتها.", "WARNING"
