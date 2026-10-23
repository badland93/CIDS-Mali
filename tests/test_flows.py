from datetime import UTC, datetime, timedelta

import pytest

from cids_mali.admin import issue_card
from cids_mali.crypto_utils import encrypt_json, generate_rsa_keypair, sign_payload
from cids_mali.verifier import verify_card


def _issue(school, demo_photo, student_data):
    from cids_mali.admin import load_issuer_private_key

    return issue_card(
        school["database"],
        student_data,
        "Guardian Demo",
        True,
        "secretary-demo",
        "ML-TEST-001",
        school["aes_key"],
        load_issuer_private_key(school["key_dir"], "test-key-password-123"),
        demo_photo,
        school["root"] / "uploads",
        school["root"] / "cards",
        school["root"] / "qr",
        365,
    )


def test_issue_then_verify_valid_card(school, demo_photo, student_data):
    artifacts = _issue(school, demo_photo, student_data)
    payload = artifacts.payload
    result = verify_card(payload, {"ML-TEST-001": school["public_key"]}, school["aes_key"])
    assert result.valid and result.reason == "Valid card"
    assert result.student_data["last_name"] == "Traoré"
    assert result.student_data["exam_category"] == "DEF"
    assert result.student_id == payload["student_id"]
    assert payload["issued_at"] == artifacts.payload["issued_at"]


def test_examination_category_survives_signed_qr_verification(school, demo_photo, student_data):
    artifacts = _issue(school, demo_photo, {**student_data, "exam_category": "BT2"})
    result = verify_card(artifacts.payload, {"ML-TEST-001": school["public_key"]}, school["aes_key"])
    assert result.valid
    assert result.student_data["exam_category"] == "BT2"


def test_tampered_and_wrong_key_cards_fail(school, demo_photo, student_data):
    payload = _issue(school, demo_photo, student_data).payload
    changed = {**payload, "issuer_id": "ML-OTHER-001"}
    result = verify_card(changed, {"ML-OTHER-001": school["public_key"]}, school["aes_key"])
    assert result.reason == "Invalid signature – tampering detected"
    _, wrong_public = generate_rsa_keypair()
    assert verify_card(payload, {"ML-TEST-001": wrong_public}, school["aes_key"]).reason.startswith("Invalid signature")


def test_expiry_and_exam_replay_rejected(school, demo_photo, student_data):
    from cids_mali.admin import load_issuer_private_key

    private_key = load_issuer_private_key(school["key_dir"], "test-key-password-123")
    issued = datetime.now(UTC) - timedelta(hours=2)
    encrypted = encrypt_json(
        {
            "last_name": "Demo",
            "first_name": "Student",
            "date_of_birth": "2012-01-01",
            "class": "9e année",
            "school": "Demo School",
            "photo_hash": "a" * 64,
        },
        school["aes_key"],
    )
    payload = {
        "v": 1,
        "student_id": "c24320e5-aad3-48b8-80aa-90cec7178980",
        "issuer_id": "ML-TEST-001",
        "encrypted_data": encrypted,
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
    }
    payload["signature"] = sign_payload(payload, private_key)
    key_map = {"ML-TEST-001": school["public_key"]}
    now = datetime.now(UTC)
    assert verify_card(payload, key_map, school["aes_key"], now=now).valid
    assert verify_card(payload, key_map, school["aes_key"], now=now, exam_mode=True).reason == "QR expired – possible replay"
    expired = {**payload, "expires_at": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")}
    expired["signature"] = sign_payload(expired, private_key)
    assert verify_card(expired, key_map, school["aes_key"], now=now).reason == "Card expired"


def test_revocation_and_unknown_issuer(school, demo_photo, student_data):
    artifacts = _issue(school, demo_photo, student_data)
    student_id = artifacts.payload["student_id"]
    assert school["database"].revoke(student_id, "test reason", "a" * 64)
    with school["database"].connection() as connection:
        stored_reason = connection.execute(
            "SELECT reason FROM revocations WHERE student_id = ?", (student_id,)
        ).fetchone()["reason"]
    assert "test reason" not in stored_reason
    assert verify_card(
        artifacts.payload,
        {"ML-TEST-001": school["public_key"]},
        school["aes_key"],
        {student_id},
    ).reason == "Card revoked"
    assert verify_card(artifacts.payload, {}, school["aes_key"]).reason == "Unknown issuer"


def test_boolean_qr_version_is_rejected(school, demo_photo, student_data):
    payload = _issue(school, demo_photo, student_data).payload
    payload["v"] = True
    assert verify_card(
        payload, {"ML-TEST-001": school["public_key"]}, school["aes_key"]
    ).reason == "Corrupted data"


def test_consent_required_before_issue(school, demo_photo, student_data):
    with pytest.raises(ValueError, match="consent"):
        issue_card(
            school["database"], student_data, "", False, "secretary", "ML-TEST-001",
            school["aes_key"], object(), demo_photo, school["root"] / "u",
            school["root"] / "c", school["root"] / "q", 365,
        )


def test_duplicate_nina_is_rejected(school, demo_photo, student_data):
    from cids_mali.admin import load_issuer_private_key

    data = {**student_data, "nina": "ML1234567"}
    arguments = (
        school["database"], data, "Guardian Demo", True, "secretary-demo", "ML-TEST-001",
        school["aes_key"], load_issuer_private_key(school["key_dir"], "test-key-password-123"),
        demo_photo, school["root"] / "uploads", school["root"] / "cards", school["root"] / "qr", 365,
    )
    issue_card(*arguments)
    with pytest.raises(ValueError, match="NINA is already registered"):
        issue_card(*arguments)