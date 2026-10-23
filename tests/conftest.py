from pathlib import Path

import pytest

from cids_mali.admin import initialize_keys
from cids_mali.crypto_utils import load_aes_key, load_public_key
from cids_mali.models import Database


@pytest.fixture
def school(tmp_path):
    key_dir = tmp_path / "keys"
    initialize_keys(key_dir, "test-key-password-123")
    aes_key = load_aes_key(key_dir / "aes_master.key")
    database = Database(tmp_path / "data" / "school.db", aes_key)
    return {
        "root": tmp_path,
        "key_dir": key_dir,
        "aes_key": aes_key,
        "public_key": load_public_key(key_dir / "issuer_public.pem"),
        "database": database,
    }


@pytest.fixture
def demo_photo():
    from io import BytesIO

    from PIL import Image

    image = Image.new("RGB", (120, 160), color=(35, 120, 90))
    stream = BytesIO()
    image.save(stream, format="JPEG")
    return stream.getvalue()


@pytest.fixture
def student_data():
    return {
        "first_name": "Aminata",
        "last_name": "Traoré",
        "date_of_birth": "2012-04-12",
        "class": "9e année",
        "school": "Ecole Demo de Bamako",
        "nina": "",
    }


@pytest.fixture
def app(school):
    from cids_mali.app import create_app

    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-session-secret",
            "KEY_PASSWORD": "test-key-password-123",
            "KEY_DIR": school["key_dir"],
            "DATABASE": school["root"] / "data" / "web.db",
            "UPLOAD_DIR": school["root"] / "uploads",
            "CARD_DIR": school["root"] / "cards",
            "QR_DIR": school["root"] / "qr",
            "ISSUER_ID": "ML-TEST-001",
            "SESSION_COOKIE_SECURE": False,
            "WTF_CSRF_ENABLED": False,
        }
    )
    return application