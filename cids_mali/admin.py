"""Administrative operations for keys, issuance, revocation, and erasure."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from cids_mali.crypto_utils import (
    CryptoError,
    generate_rsa_keypair,
    initialize_aes_key,
    load_aes_key,
    load_private_key,
    save_private_key,
    save_public_key,
)
from cids_mali.models import Database
from cids_mali.qr_generator import CardArtifacts, create_card_artifacts


def initialize_keys(key_dir: Path, password: str) -> None:
    key_dir = Path(key_dir)
    key_dir.mkdir(parents=True, exist_ok=True)
    key_dir.chmod(0o700)
    private_path, public_path, aes_path = (
        key_dir / "issuer_private.pem",
        key_dir / "issuer_public.pem",
        key_dir / "aes_master.key",
    )
    if private_path.exists() or public_path.exists():
        raise CryptoError("Issuer key files already exist; refusing to overwrite")
    if aes_path.exists():
        raise CryptoError("AES master key already exists; refusing to regenerate it")
    private, public = generate_rsa_keypair()
    save_private_key(private, private_path, password)
    save_public_key(public, public_path)
    initialize_aes_key(aes_path)


def rotate_issuer_key(key_dir: Path, password: str, old_issuer_id: str) -> Path:
    """Rotate signing keys while retaining the old public key for offline cards."""
    key_dir = Path(key_dir)
    old_public = key_dir / "issuer_public.pem"
    old_private = key_dir / "issuer_private.pem"
    trusted_dir = key_dir / "trusted"
    trusted_dir.mkdir(parents=True, exist_ok=True)
    trusted_dir.chmod(0o700)
    if old_public.exists():
        archive = trusted_dir / f"{old_issuer_id}.pem"
        archive.write_bytes(old_public.read_bytes())
        archive.chmod(0o644)
    private, public = generate_rsa_keypair()
    staged_private = key_dir / "issuer_private.pem.new"
    save_private_key(private, staged_private, password)
    os.replace(staged_private, old_private)
    save_public_key(public, old_public)
    return old_public


def issue_card(
    database: Database,
    student_data: dict[str, str],
    guardian_name: str,
    consent_given: bool,
    operator_id: str,
    issuer_id: str,
    aes_key: bytes,
    private_key: Any,
    photo_bytes: bytes,
    upload_dir: Path,
    card_dir: Path,
    qr_dir: Path,
    validity_days: int,
    consent_date: str | None = None,
    candidate_id: str | None = None,
    previous_card_id: str | None = None,
) -> CardArtifacts:
    if not consent_given or not guardian_name.strip():
        raise ValueError("Recorded parental consent is required before card issuance")
    if consent_date:
        try:
            parsed_consent_date = date.fromisoformat(consent_date)
        except ValueError as exc:
            raise ValueError("Invalid parental consent date") from exc
        if parsed_consent_date > datetime.now(UTC).date():
            raise ValueError("Parental consent date cannot be in the future")
    personal_data, student_id, artifacts = create_card_artifacts(
        student_data,
        issuer_id,
        aes_key,
        private_key,
        photo_bytes,
        upload_dir,
        card_dir,
        qr_dir,
        validity_days,
    )
    operator_hash = hashlib.sha256(operator_id.encode("utf-8")).hexdigest()
    try:
        candidate = {**personal_data, "student_id": student_id}
        final_consent_date = consent_date or artifacts.payload["issued_at"][:10]
        if candidate_id and previous_card_id and not database.replace_student_card(
            {**candidate, "candidate_id": candidate_id},
            previous_card_id,
            guardian_name.strip(),
            final_consent_date,
            operator_hash,
            artifacts.payload["issued_at"],
            artifacts.payload["expires_at"],
            operator_id,
        ):
            raise ValueError("This active card could not be replaced")
        if not candidate_id or not previous_card_id:
            database.issue_student(
                candidate,
                guardian_name.strip(),
                final_consent_date,
                operator_hash,
                artifacts.payload["issued_at"],
                artifacts.payload["expires_at"],
                operator_id,
            )
    except Exception:
        for path in (artifacts.photo_path, artifacts.qr_path, artifacts.png_path, artifacts.pdf_path):
            path.unlink(missing_ok=True)
        raise
    return artifacts


def erase_student_data(database: Database, student_id: str, operator_id: str, *directories: Path) -> bool:
    student = database.get_student(student_id)
    if not student:
        return False
    card_ids = database.list_candidate_card_ids(student["candidate_id"])
    erased = database.erase_student(
        student_id,
        hashlib.sha256(operator_id.encode("utf-8")).hexdigest(),
    )
    if erased:
        upload_dir, qr_dir, card_dir = (Path(directory) for directory in directories)
        for card_id in card_ids:
            (upload_dir / f"{card_id}.png").unlink(missing_ok=True)
            (qr_dir / f"{card_id}.png").unlink(missing_ok=True)
            (card_dir / f"{card_id}.png").unlink(missing_ok=True)
            (card_dir / f"{card_id}.pdf").unlink(missing_ok=True)
    return erased


def export_public_key(public_key_path: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(Path(public_key_path).read_bytes())
    output_path.chmod(0o644)


def load_issuer_private_key(key_dir: Path, password: str):
    return load_private_key(Path(key_dir) / "issuer_private.pem", password)


def load_school_aes_key(key_dir: Path) -> bytes:
    return load_aes_key(Path(key_dir) / "aes_master.key")


def public_key_pem(key_dir: Path) -> str:
    return (Path(key_dir) / "issuer_public.pem").read_text(encoding="ascii")


def load_public_key_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode("ascii"))