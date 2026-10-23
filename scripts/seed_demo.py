"""Create fictitious demo cards. Requires initialized school keys."""

from __future__ import annotations

import hashlib
import json
import os
from io import BytesIO

from dotenv import load_dotenv
from PIL import Image, ImageDraw

from cids_mali.admin import issue_card, load_issuer_private_key
from cids_mali.config import Config, PROJECT_ROOT
from cids_mali.crypto_utils import load_aes_key
from cids_mali.models import Database


DEMO_STUDENTS = [
    {"first_name": "Awa", "last_name": "Demo", "date_of_birth": "2012-02-14", "class": "9e année", "school": "Ecole Demo de Bamako", "nina": ""},
    {"first_name": "Boubacar", "last_name": "Exemple", "date_of_birth": "2011-07-03", "class": "10e année", "school": "Ecole Demo de Bamako", "nina": ""},
    {"first_name": "Fanta", "last_name": "Essai", "date_of_birth": "2013-11-22", "class": "8e année", "school": "Ecole Demo de Bamako", "nina": ""},
]


def demo_photo(index: int) -> bytes:
    image = Image.new("RGB", (240, 300), (30 + index * 30, 105, 85))
    draw = ImageDraw.Draw(image)
    draw.ellipse((75, 35, 165, 125), fill=(215, 185, 150))
    draw.rounded_rectangle((45, 145, 195, 290), radius=50, fill=(230, 225, 205))
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def main() -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    password = os.environ.get("CIDS_KEY_PASSWORD")
    if not password:
        raise SystemExit("Set CIDS_KEY_PASSWORD in .env before seeding demo records")
    aes_key = load_aes_key(Config.KEY_DIR / "aes_master.key")
    private_key = load_issuer_private_key(Config.KEY_DIR, password)
    database = Database(Config.DATABASE, aes_key)
    seed_operator = hashlib.sha256(b"cids-demo-seed-operator").hexdigest()
    with database.connection() as connection:
        seeded = connection.execute(
            "SELECT COUNT(*) AS total FROM issuance_log WHERE action = 'ISSUE' AND operator_hash = ?",
            (seed_operator,),
        ).fetchone()["total"]
    if seeded:
        print("Fictitious demo students are already present; no changes made.")
        return 0
    demo_payload_path = PROJECT_ROOT / "data" / "demo_payload.json"
    for index, student in enumerate(DEMO_STUDENTS):
        artifacts = issue_card(
            database,
            student,
            f"Guardian for {student['first_name']} Demo",
            True,
            "cids-demo-seed-operator",
            Config.ISSUER_ID,
            aes_key,
            private_key,
            demo_photo(index),
            Config.UPLOAD_DIR,
            Config.CARD_DIR,
            Config.QR_DIR,
            Config.CARD_VALIDITY_DAYS,
        )
        if index == 0:
            demo_payload_path.write_text(json.dumps(artifacts.payload, ensure_ascii=False), encoding="utf-8")
            demo_payload_path.chmod(0o600)
    print(f"Seeded {len(DEMO_STUDENTS)} fictitious students and cards.")
    print(f"Demo QR payload: {demo_payload_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())