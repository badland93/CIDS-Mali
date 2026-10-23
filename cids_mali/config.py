"""Environment-backed configuration for the CIDS-Mali application."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


class Config:
    SECRET_KEY = os.environ.get("CIDS_SECRET_KEY")
    KEY_PASSWORD = os.environ.get("CIDS_KEY_PASSWORD")
    ISSUER_ID = os.environ.get("CIDS_ISSUER_ID", "ML-DEMO-001")
    DATABASE = Path(os.environ.get("CIDS_DATABASE", PROJECT_ROOT / "data" / "cids.db"))
    KEY_DIR = Path(os.environ.get("CIDS_KEY_DIR", PROJECT_ROOT / "keys"))
    UPLOAD_DIR = Path(os.environ.get("CIDS_UPLOAD_DIR", PROJECT_ROOT / "data" / "uploads"))
    CARD_DIR = Path(os.environ.get("CIDS_CARD_DIR", PROJECT_ROOT / "data" / "cards"))
    QR_DIR = Path(os.environ.get("CIDS_QR_DIR", PROJECT_ROOT / "data" / "qr"))
    REPLAY_WINDOW_SECONDS = int(os.environ.get("REPLAY_WINDOW_SECONDS", "3600"))
    CARD_VALIDITY_DAYS = int(os.environ.get("CIDS_CARD_VALIDITY_DAYS", "365"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("CIDS_COOKIE_SECURE", "1") == "1"
    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024


def validate_secret(secret_key: str | None) -> None:
    if not secret_key:
        raise RuntimeError("CIDS_SECRET_KEY is required; copy .env.example and set a strong value")