"""Offline CIDS-Mali QR verification and command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cids_mali.crypto_utils import CryptoError, decrypt_json, verify_signature
from cids_mali.exam_categories import EXAM_CATEGORIES


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str
    student_data: dict[str, Any] | None = None
    student_id: str | None = None


def verify_card(
    qr_data: str | bytes | Mapping[str, Any],
    trusted_issuers: Mapping[str, str | bytes | rsa.RSAPublicKey],
    aes_key: bytes,
    revoked_ids: set[str] | None = None,
    now: datetime | None = None,
    exam_mode: bool = False,
    replay_window_seconds: int = 3600,
) -> VerificationResult:
    try:
        payload = json.loads(qr_data) if isinstance(qr_data, (str, bytes)) else dict(qr_data)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
        return VerificationResult(False, "Corrupted data")
    required = {"v", "student_id", "issuer_id", "encrypted_data", "issued_at", "expires_at", "signature"}
    if not isinstance(payload, dict) or set(payload) != required or type(payload.get("v")) is not int or payload["v"] != 1:
        return VerificationResult(False, "Corrupted data")
    try:
        student_id = str(UUID(payload["student_id"], version=4))
        if student_id != payload["student_id"] or UUID(student_id).version != 4:
            raise ValueError("not UUID4")
        if not all(isinstance(payload[field], str) for field in required - {"v"}):
            raise ValueError("invalid field type")
        issued = _parse_time(payload["issued_at"])
        expires = _parse_time(payload["expires_at"])
        if expires <= issued:
            raise ValueError("expiry must follow issuance")
    except (ValueError, TypeError, KeyError):
        return VerificationResult(False, "Corrupted data")
    issuer_id = payload["issuer_id"]
    if issuer_id not in trusted_issuers:
        return VerificationResult(False, "Unknown issuer", student_id=student_id)
    try:
        key_value = trusted_issuers[issuer_id]
        public_key = (
            key_value if isinstance(key_value, rsa.RSAPublicKey)
            else serialization.load_pem_public_key(key_value.encode() if isinstance(key_value, str) else key_value)
        )
        if not isinstance(public_key, rsa.RSAPublicKey):
            return VerificationResult(False, "Unknown issuer", student_id=student_id)
    except (ValueError, TypeError):
        return VerificationResult(False, "Unknown issuer", student_id=student_id)
    if not verify_signature(payload, payload["signature"], public_key):
        return VerificationResult(False, "Invalid signature – tampering detected", student_id=student_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    if current > expires:
        return VerificationResult(False, "Card expired", student_id=student_id)
    age_seconds = (current - issued).total_seconds()
    if exam_mode and (age_seconds < 0 or age_seconds > replay_window_seconds):
        return VerificationResult(False, "QR expired – possible replay", student_id=student_id)
    if student_id in (revoked_ids or set()):
        return VerificationResult(False, "Card revoked", student_id=student_id)
    try:
        student_data = decrypt_json(payload["encrypted_data"], aes_key)
    except (CryptoError, ValueError):
        return VerificationResult(False, "Corrupted data", student_id=student_id)
    compact_fields = {
        "ln": "last_name",
        "fn": "first_name",
        "dob": "date_of_birth",
        "cl": "class",
        "sc": "school",
        "ph": "photo_hash",
        "ni": "nina",
        "ex": "exam_category",
    }
    if set(student_data) & compact_fields.keys():
        if set(student_data) - compact_fields.keys():
            return VerificationResult(False, "Corrupted data", student_id=student_id)
        student_data = {compact_fields[key]: value for key, value in student_data.items()}
    required_personal_fields = {"last_name", "first_name", "date_of_birth", "class", "school", "photo_hash"}
    allowed_personal_fields = required_personal_fields | {"nina", "exam_category"}
    if (
        not required_personal_fields.issubset(student_data)
        or not set(student_data).issubset(allowed_personal_fields)
        or any(not isinstance(student_data[field], str) for field in required_personal_fields)
        or ("exam_category" in student_data and student_data["exam_category"] not in EXAM_CATEGORIES)
        or ("nina" in student_data and student_data["nina"] is not None and not isinstance(student_data["nina"], str))
    ):
        return VerificationResult(False, "Corrupted data", student_id=student_id)
    student_data.setdefault("exam_category", "DEF")
    return VerificationResult(True, "Valid card", student_data, student_id)


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a CIDS-Mali QR payload offline")
    parser.add_argument("qr_json", type=Path, help="File containing the QR JSON")
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--aes-key", required=True, type=Path)
    parser.add_argument("--revocations", type=Path)
    parser.add_argument("--exam-mode", action="store_true")
    parser.add_argument("--replay-window-seconds", type=int, default=3600)
    args = parser.parse_args(argv)
    from cids_mali.crypto_utils import load_aes_key

    revocations = set(args.revocations.read_text(encoding="utf-8").splitlines()) if args.revocations else set()
    public_key = serialization.load_pem_public_key(args.public_key.read_bytes())
    payload_text = args.qr_json.read_text(encoding="utf-8")
    try:
        issuer_id = json.loads(payload_text)["issuer_id"]
    except (json.JSONDecodeError, KeyError, TypeError):
        print("INVALID: Corrupted data")
        return 1
    result = verify_card(
        payload_text,
        {issuer_id: public_key},
        load_aes_key(args.aes_key),
        revocations,
        exam_mode=args.exam_mode,
        replay_window_seconds=args.replay_window_seconds,
    )
    print(f"{'VALID' if result.valid else 'INVALID'}: {result.reason}")
    if result.student_data:
        for field in ("first_name", "last_name", "class", "school", "date_of_birth"):
            print(f"{field}: {result.student_data.get(field, '')}")
    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())