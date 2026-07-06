"""
strength.py

Core password analysis module.
"""

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
    Detect sequential characters.
    """

    sequences = [

        "abcdefghijklmnopqrstuvwxyz",

        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",

        "0123456789"

    ]

    for sequence in sequences:

        for i in range(len(sequence) - 2):

            if sequence[i:i+3] in password:

                return True

    return False


def has_repeated(password: str) -> bool:
    """
    Detect repeated characters.
    """

    return bool(re.search(r"(.)\1{2,}", password))


def has_keyboard_pattern(password: str) -> bool:
    """
    Detect common keyboard patterns.
    """

    keyboard = [

        "qwerty",

        "asdf",

        "zxcv",

        "12345",

        "qwertyuiop"

    ]

    password = password.lower()

    return any(pattern in password for pattern in keyboard)


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
        suggestions.append("Avoid sequential characters (e.g. abc, 123).")

    if has_repeated(password):
        suggestions.append("Avoid repeated characters (e.g. aaa, 111).")

    if has_keyboard_pattern(password):
        suggestions.append("Avoid common keyboard patterns (e.g. qwerty).")

    return suggestions


# ==========================================================
# MAIN ANALYSIS FUNCTION
# ==========================================================

def analyze_password(password: str) -> dict:
    """
    Perform complete password analysis.
    """

    strength = calculate_strength(password)

    return {

        "strength": strength["strength"],

        "score": strength["score"],

        "entropy": calculate_entropy(password),

        "crack_time": strength["crack_time"],

        "requirements": check_requirements(password),

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