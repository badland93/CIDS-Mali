import json

from cids_mali.qr_generator import create_card_artifacts, normalize_photo, validate_student_data


def test_create_signed_card_and_qr(school, demo_photo, student_data):
    from cids_mali.admin import load_issuer_private_key

    private_key = load_issuer_private_key(school["key_dir"], "test-key-password-123")
    _, student_id, artifacts = create_card_artifacts(
        student_data,
        "ML-TEST-001",
        school["aes_key"],
        private_key,
        demo_photo,
        school["root"] / "uploads",
        school["root"] / "cards",
        school["root"] / "qr",
    )
    assert artifacts.payload["student_id"] == student_id
    assert artifacts.payload["issued_at"]
    assert artifacts.qr_path.is_file() and artifacts.png_path.is_file() and artifacts.pdf_path.is_file()
    assert "Traoré" not in json.dumps(artifacts.payload, ensure_ascii=False)
    assert len(json.dumps(artifacts.payload, separators=(",", ":"))) < 800


def test_photo_normalization_returns_deterministic_sha256(tmp_path, demo_photo):
    first, second = tmp_path / "one.png", tmp_path / "two.png"
    assert normalize_photo(demo_photo, first) == normalize_photo(demo_photo, second)


def test_student_validation_rejects_injection(student_data):
    validate_student_data(student_data)
    malicious = {**student_data, "first_name": "<script>alert(1)</script>"}
    try:
        validate_student_data(malicious)
    except ValueError:
        return
    raise AssertionError("markup must not be accepted as a student name")