"""
database.py

SQLite database operations for password scan history.

Design notes:
    - Every analysis is logged as its own row. We intentionally do NOT
      deduplicate on password_hash — a user re-checking the same password
      later (e.g. after a breach was patched, or just to confirm) should
      show up as a new entry with its own timestamp, not vanish silently.
    - Only the SHA-256 hash of the password is ever stored. Plaintext is
      never written to disk.
    - All queries are parameterized to prevent SQL injection.
"""

import hashlib
import os
import sqlite3

from config import Config


def get_connection() -> sqlite3.Connection:
    """Create a SQLite connection, ensuring the parent directory exists."""
    db_path = Config.DATABASE_PATH

    if db_path != ":memory:":
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    return conn


def initialize_database() -> None:
    """
    Create the history table if it doesn't already exist, and add any
    columns that are missing from an older version of the table.

    This keeps existing local database files usable across schema
    changes instead of throwing sqlite3.OperationalError the first time
    a new column (like score or is_breached) is referenced.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL,
            strength TEXT NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            entropy REAL NOT NULL,
            is_breached INTEGER NOT NULL DEFAULT 0,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    # Migrate older database files that predate the score/is_breached
    # columns, so an existing local .db doesn't need to be deleted
    # every time the schema gains a new field.
    existing_columns = {
        row["name"] for row in cursor.execute("PRAGMA table_info(password_history)")
    }

    required_columns = {
        "score": "INTEGER NOT NULL DEFAULT 0",
        "is_breached": "INTEGER NOT NULL DEFAULT 0",
    }

    for column_name, column_definition in required_columns.items():
        if column_name not in existing_columns:
            cursor.execute(
                f"ALTER TABLE password_history ADD COLUMN {column_name} {column_definition}"
            )

    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    """Return a SHA-256 hash of the password for storage/display only."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def password_exists(password: str) -> bool:
    """Check whether this exact password has ever been analyzed before."""
    password_hash = hash_password(password)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM password_history WHERE password_hash = ? LIMIT 1",
        (password_hash,),
    )
    exists = cursor.fetchone() is not None

    conn.close()
    return exists


def save_password(
    password: str,
    strength: str,
    entropy: float,
    score: int = 0,
    is_breached: bool = False,
) -> int:
    """
    Save a scan result as a new row. Returns the new row's id.

    Every call inserts a new row — repeated checks of the same password
    are tracked individually rather than being silently ignored.
    """
    password_hash = hash_password(password)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO password_history
            (password_hash, strength, score, entropy, is_breached)
        VALUES (?, ?, ?, ?, ?)
        """,
        (password_hash, strength, score, entropy, int(is_breached)),
    )

    conn.commit()
    new_id = cursor.lastrowid
    conn.close()

    return new_id


def get_history(limit: int = 100, search: str = None) -> list:
    """
    Return scan history, most recent first.

    `search` filters by the start of the stored SHA-256 hash, so users
    can look up a specific past scan without ever handling plaintext.
    """
    conn = get_connection()
    cursor = conn.cursor()

    if search:
        cursor.execute(
            """
            SELECT id, password_hash, strength, score, entropy, is_breached, analyzed_at
            FROM password_history
            WHERE password_hash LIKE ?
            ORDER BY analyzed_at DESC
            LIMIT ?
            """,
            (f"{search}%", limit),
        )
    else:
        cursor.execute(
            """
            SELECT id, password_hash, strength, score, entropy, is_breached, analyzed_at
            FROM password_history
            ORDER BY analyzed_at DESC
            LIMIT ?
            """,
            (limit,),
        )

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row["id"],
            "password_hash": row["password_hash"],
            "strength": row["strength"],
            "score": row["score"],
            "entropy": row["entropy"],
            "is_breached": bool(row["is_breached"]),
            "date": row["analyzed_at"],
        }
        for row in rows
    ]


def delete_entry(entry_id: int) -> bool:
    """Delete a single history row by id. Returns True if a row was removed."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM password_history WHERE id = ?", (entry_id,))
    conn.commit()

    deleted = cursor.rowcount > 0
    conn.close()

    return deleted


def clear_history() -> int:
    """Delete all history rows. Returns the number of rows removed."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM password_history")
    conn.commit()

    count = cursor.rowcount
    conn.close()

    return count