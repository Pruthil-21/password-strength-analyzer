from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Project root directory
BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Application configuration."""

    # Flask
    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "change-this-secret-key-before-production"
    )

    # Database
    DATABASE_PATH = BASE_DIR / "data" / "history.db"

    # Report directory
    REPORTS_DIR = BASE_DIR / "reports"

    # API
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
    HIBP_REQUEST_TIMEOUT = 5  # seconds

    # App
    MAX_PASSWORD_LENGTH = 256