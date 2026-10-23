from time import perf_counter

from cids_mali.admin import issue_card, load_issuer_private_key
from cids_mali.verifier import verify_card


def test_issue_and_verify_within_prototype_targets(school, demo_photo, student_data):
    private_key = load_issuer_private_key(school["key_dir"], "test-key-password-123")
    started = perf_counter()
    artifacts = issue_card(
        school["database"], student_data, "Guardian Demo", True, "secretary-demo",
        "ML-TEST-001", school["aes_key"], private_key, demo_photo,
        school["root"] / "uploads", school["root"] / "cards", school["root"] / "qr", 365,
    )
    issuance_seconds = perf_counter() - started
    started = perf_counter()
    result = verify_card(artifacts.payload, {"ML-TEST-001": school["public_key"]}, school["aes_key"])
    verification_seconds = perf_counter() - started
    assert result.valid
    assert issuance_seconds < 5
    assert verification_seconds < 2