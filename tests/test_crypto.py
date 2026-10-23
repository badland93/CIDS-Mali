import json

import pytest

from cids_mali.crypto_utils import (
    CryptoError,
    canonical_payload,
    decrypt_json,
    encrypt_json,
    generate_rsa_keypair,
    sha256_hex,
    sign_payload,
    verify_signature,
)


@pytest.fixture
def aes_key():
    return bytes(range(32))


@pytest.fixture
def payload():
    return {
        "v": 1,
        "student_id": "c24320e5-aad3-48b8-80aa-90cec7178980",
        "issuer_id": "ML-BKO-001",
        "encrypted_data": "YWJj",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z",
    }


@pytest.mark.parametrize("name", ["Konaré", "Traoré", "Diallo"])
def test_aes_round_trip_utf8(aes_key, name):
    data = {"last_name": name, "first_name": "Aminata", "class": "9e année"}
    assert decrypt_json(encrypt_json(data, aes_key), aes_key) == data


def test_aes_uses_a_fresh_iv(aes_key):
    data = {"last_name": "Diallo"}
    first, second = encrypt_json(data, aes_key), encrypt_json(data, aes_key)
    assert first != second


def test_aes_rejects_wrong_key(aes_key):
    encrypted = encrypt_json({"last_name": "Traoré"}, aes_key)
    with pytest.raises(CryptoError):
        decrypt_json(encrypted, b"x" * 32)


def test_rsa_signature_round_trip_and_detects_changes(payload):
    private, public = generate_rsa_keypair()
    signature = sign_payload(payload, private)
    assert verify_signature(payload, signature, public)
    changed = {**payload, "issuer_id": "ML-BKO-002"}
    assert not verify_signature(changed, signature, public)
    assert not verify_signature(payload, signature[:-4] + "AAAA", public)


def test_signature_does_not_cover_unsigned_fields(payload):
    private, public = generate_rsa_keypair()
    signature = sign_payload(payload, private)
    assert verify_signature({**payload, "display_hint": "ignored"}, signature, public)


def test_canonical_payload_matches_required_json_representation(payload):
    expected = {
        "version": 1,
        "student_id": payload["student_id"],
        "issuer_id": payload["issuer_id"],
        "encrypted_data": payload["encrypted_data"],
        "issued_at": payload["issued_at"],
        "expires_at": payload["expires_at"],
    }
    assert canonical_payload(payload) == json.dumps(
        expected, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")


def test_sha256_is_deterministic():
    assert sha256_hex("photo".encode()) == sha256_hex("photo".encode())
    assert len(sha256_hex(b"photo")) == 64


def test_encrypted_payload_is_not_plaintext(aes_key):
    encrypted = encrypt_json({"last_name": "Konaré"}, aes_key)
    assert "Konaré" not in encrypted
    json.loads(json.dumps(encrypted))