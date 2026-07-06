"""
database.py

SQLite database operations.
"""

import sqlite3
import hashlib

from config import Config


def get_connection():
    """Create SQLite connection."""

    return sqlite3.connect(Config.DATABASE_PATH)


def initialize_database():
    """Create tables if they don't exist."""

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            password_hash TEXT UNIQUE,

            strength TEXT,

            entropy REAL,

            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)

    conn.commit()

    conn.close()


def hash_password(password: str) -> str:
    """Return SHA-256 hash."""

    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


def password_exists(password: str) -> bool:
    """Check whether password was previously analyzed."""

    password_hash = hash_password(password)

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(

        "SELECT id FROM password_history WHERE password_hash = ?",

        (password_hash,)

    )

    exists = cursor.fetchone() is not None

    conn.close()

    return exists


def save_password(password: str, strength: str, entropy: float):
    """Save password hash."""

    password_hash = hash_password(password)

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

        INSERT OR IGNORE INTO password_history

        (password_hash, strength, entropy)

        VALUES (?, ?, ?)

    """,

    (

        password_hash,

        strength,

        entropy

    ))

    conn.commit()

    conn.close()


def get_history():
    """Return password history."""

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

        SELECT

            strength,

            entropy,

            analyzed_at

        FROM password_history

        ORDER BY analyzed_at DESC

    """)

    rows = cursor.fetchall()

    conn.close()

    return rows