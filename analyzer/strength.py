import math
import re
from zxcvbn import zxcvbn


# ==========================================================
# CHARACTER SET SIZE
# ==========================================================

def get_character_pool(password: str) -> int:
    """
    Returns the possible character pool size.
    """

    pool = 0

    if any(c.islower() for c in password):
        pool += 26

    if any(c.isupper() for c in password):
        pool += 26

    if any(c.isdigit() for c in password):
        pool += 10

    if any(not c.isalnum() for c in password):
        pool += 32

    return pool


# ==========================================================
# ENTROPY
# ==========================================================

def calculate_entropy(password: str) -> float:
    """
    Calculate password entropy in bits.
    """

    if not password:
        return 0

    pool = get_character_pool(password)

    if pool == 0:
        return 0

    entropy = len(password) * math.log2(pool)

    return round(entropy, 2)


# ==========================================================
# REQUIREMENTS
# ==========================================================

def check_requirements(password: str) -> list:
    """
    Returns password requirement checklist.
    """

    requirements = [

        ("✓ Minimum 12 characters"
         if len(password) >= 12
         else "✗ Minimum 12 characters"),

        ("✓ Contains uppercase"
         if re.search(r"[A-Z]", password)
         else "✗ Contains uppercase"),

        ("✓ Contains lowercase"
         if re.search(r"[a-z]", password)
         else "✗ Contains lowercase"),

        ("✓ Contains number"
         if re.search(r"\d", password)
         else "✗ Contains number"),

        ("✓ Contains special character"
         if re.search(r"[^A-Za-z0-9]", password)
         else "✗ Contains special character")

    ]

    return requirements


# ==========================================================
# PATTERN DETECTION
# ==========================================================

def has_sequential(password: str) -> bool:
    """
    Detect sequential characters, ascending or descending
    (e.g. 'abc'/'cba', '123'/'321').
    """

    sequences = [

        "abcdefghijklmnopqrstuvwxyz",

        "0123456789"

    ]

    lowered = password.lower()

    for sequence in sequences:

        reversed_sequence = sequence[::-1]

        for i in range(len(sequence) - 2):

            chunk = sequence[i:i + 3]
            reversed_chunk = reversed_sequence[i:i + 3]

            if chunk in lowered or reversed_chunk in lowered:

                return True

    return False


def has_repeated(password: str) -> bool:
    """
    Detect repeated characters.
    """

    return bool(re.search(r"(.)\1{2,}", password))


def has_keyboard_pattern(password: str, min_run: int = 4) -> bool:
    """
    Detect keyboard-walk patterns by scanning full keyboard rows
    (forward and backward) instead of a fixed list of known strings,
    so variants like '1qaz' or 'poiuy' are caught too.
    """

    keyboard_rows = [

        "qwertyuiop",

        "asdfghjkl",

        "zxcvbnm",

        "1234567890",

    ]

    lowered = password.lower()

    for row in keyboard_rows:

        reversed_row = row[::-1]

        for i in range(len(row) - min_run + 1):

            chunk = row[i:i + min_run]
            reversed_chunk = reversed_row[i:i + min_run]

            if chunk in lowered or reversed_chunk in lowered:

                return True

    return False


# ==========================================================
# PASSWORD STRENGTH
# ==========================================================

def calculate_strength(password: str) -> dict:
    """
    Uses zxcvbn for password strength.
    """

    result = zxcvbn(password)

    score = result["score"]

    levels = {

        0: "Very Weak",

        1: "Weak",

        2: "Fair",

        3: "Strong",

        4: "Very Strong"

    }

    return {

        "score": score,

        "strength": levels[score],

        "crack_time":
            result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]

    }


# ==========================================================
# CHARACTER STATISTICS
# ==========================================================

def character_statistics(password: str) -> dict:
    """
    Returns character statistics.
    """

    return {

        "length": len(password),

        "uppercase": sum(c.isupper() for c in password),

        "lowercase": sum(c.islower() for c in password),

        "numbers": sum(c.isdigit() for c in password),

        "symbols": sum(not c.isalnum() for c in password)

    }


# ==========================================================
# WEAKNESSES
# ==========================================================

def generate_weaknesses(password: str) -> list:
    """
    List concrete structural weaknesses found in the password.

    Kept separate from generate_suggestions(): a weakness describes what
    is wrong, a suggestion describes what to do about it.
    """

    weaknesses = []

    if len(password) < 8:
        weaknesses.append("Password is shorter than the recommended minimum of 8 characters.")

    if not re.search(r"[A-Z]", password):
        weaknesses.append("No uppercase letters found.")

    if not re.search(r"[a-z]", password):
        weaknesses.append("No lowercase letters found.")

    if not re.search(r"\d", password):
        weaknesses.append("No numeric digits found.")

    if not re.search(r"[^A-Za-z0-9]", password):
        weaknesses.append("No special characters found.")

    if has_sequential(password):
        weaknesses.append("Contains a sequential character run (e.g. 'abc', '321').")

    if has_repeated(password):
        weaknesses.append("Contains a character repeated three or more times in a row.")

    if has_keyboard_pattern(password):
        weaknesses.append("Contains a keyboard-walk pattern (e.g. 'qwerty', '1qaz').")

    return weaknesses


# ==========================================================
# SUGGESTIONS
# ==========================================================

def generate_suggestions(password: str) -> list:
    """
    Generate password improvement suggestions.
    """

    suggestions = []

    if len(password) < 12:
        suggestions.append("Use at least 12 characters.")

    if not re.search(r"[A-Z]", password):
        suggestions.append("Add at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        suggestions.append("Add at least one lowercase letter.")

    if not re.search(r"\d", password):
        suggestions.append("Include at least one number.")

    if not re.search(r"[^A-Za-z0-9]", password):
        suggestions.append("Include at least one special character.")

    if has_sequential(password):
        suggestions.append("Avoid sequential characters (e.g. abc, 123, or their reverse).")

    if has_repeated(password):
        suggestions.append("Avoid repeated characters (e.g. aaa, 111).")

    if has_keyboard_pattern(password):
        suggestions.append("Avoid common keyboard patterns (e.g. qwerty, 1qaz).")

    if not suggestions:
        suggestions.append("This password looks strong. Consider a password manager to keep it unique per site.")

    return suggestions


# ==========================================================
# COMPOSITE SCORE
# ==========================================================

def calculate_score(entropy: float, zxcvbn_score: int, weakness_count: int) -> int:
    """
    Blend entropy, zxcvbn's pattern-matching score, and detected
    structural weaknesses into a single 0-100 score.

    Weighting:
        - up to 50 points from entropy (normalized against 80 bits, a
          reasonable "very strong" reference point)
        - up to 40 points from zxcvbn's 0-4 score
        - a flat +10 baseline
        - minus 5 points per weakness found, capped at -30

    This keeps entropy from dominating (a long password made of a
    repeated pattern has high entropy by the raw formula but should
    still score poorly once weaknesses are factored in).
    """

    entropy_component = min(entropy / 80.0, 1.0) * 50
    zxcvbn_component = (zxcvbn_score / 4.0) * 40
    penalty = min(weakness_count * 5, 30)

    score = entropy_component + zxcvbn_component - penalty + 10

    return max(0, min(100, round(score)))


# ==========================================================
# MAIN ANALYSIS FUNCTION
# ==========================================================

def analyze_password(password: str) -> dict:
    """
    Perform complete password analysis.
    """

    strength = calculate_strength(password)
    entropy = calculate_entropy(password)
    weaknesses = generate_weaknesses(password)

    score = calculate_score(
        entropy=entropy,
        zxcvbn_score=strength["score"],
        weakness_count=len(weaknesses),
    )

    return {

        "strength": strength["strength"],

        "zxcvbn_score": strength["score"],

        "score": score,

        "entropy": entropy,

        "crack_time": strength["crack_time"],

        "requirements": check_requirements(password),

        "weaknesses": weaknesses,

        "suggestions": generate_suggestions(password),

        "statistics": character_statistics(password),

        "patterns": {

            "sequential": has_sequential(password),

            "repeated": has_repeated(password),

            "keyboard": has_keyboard_pattern(password)

        }

    }


# ==========================================================
# TEST
# ==========================================================

if __name__ == "__main__":

    password = "Password123!"

    from pprint import pprint

    pprint(analyze_password(password))