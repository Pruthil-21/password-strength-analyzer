"""
generator.py

Secure password generator.
"""

import secrets
import string


def generate_password(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
) -> str:
    """
    Generate a cryptographically secure password.
    """

    if length < 8 or length > 128:
        raise ValueError("Password length must be between 8 and 128.")

    character_pool = ""
    password = []

    if uppercase:
        character_pool += string.ascii_uppercase
        password.append(secrets.choice(string.ascii_uppercase))

    if lowercase:
        character_pool += string.ascii_lowercase
        password.append(secrets.choice(string.ascii_lowercase))

    if numbers:
        character_pool += string.digits
        password.append(secrets.choice(string.digits))

    if symbols:
        special = "!@#$%^&*()-_=+[]{}<>?"
        character_pool += special
        password.append(secrets.choice(special))

    if not character_pool:
        raise ValueError("At least one character type must be selected.")

    while len(password) < length:
        password.append(secrets.choice(character_pool))

    secrets.SystemRandom().shuffle(password)

    return "".join(password)


if __name__ == "__main__":
    print(generate_password())