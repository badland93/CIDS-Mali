"""Create signed QR payloads and printable identity cards."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Any

import qrcode
from PIL import Image, ImageDraw, ImageFont, ImageOps
from qrcode.constants import ERROR_CORRECT_H
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

from cids_mali.crypto_utils import encrypt_json, sha256_hex, sign_payload
from cids_mali.exam_categories import EXAM_CATEGORIES


NAME_PATTERN = re.compile(r"^[\wÀ-ÖØ-öø-ÿ'’ -]{1,80}$", re.UNICODE)
NINA_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,32}$")


class IssuanceError(ValueError):
    """Raised when card issuance input is incomplete or invalid."""


@dataclass(frozen=True)
class CardArtifacts:
    payload: dict[str, Any]
    qr_path: Path
    png_path: Path
    pdf_path: Path
    photo_path: Path


def validate_student_data(data: dict[str, str]) -> None:
    for field in ("last_name", "first_name"):
        value = data.get(field, "").strip()
        if not NAME_PATTERN.fullmatch(value):
            raise IssuanceError(f"Invalid {field.replace('_', ' ')}")
    for field in ("date_of_birth", "class", "school"):
        if not data.get(field, "").strip() or len(data[field]) > 120:
            raise IssuanceError(f"Invalid {field.replace('_', ' ')}")
    try:
        date_of_birth = datetime.strptime(data["date_of_birth"], "%Y-%m-%d").date()
    except ValueError as exc:
        raise IssuanceError("Invalid date of birth") from exc
    if date_of_birth > datetime.now(UTC).date():
        raise IssuanceError("Date of birth cannot be in the future")
    nina = data.get("nina", "").strip()
    if nina and not NINA_PATTERN.fullmatch(nina):
        raise IssuanceError("Invalid NINA value")
    if data.get("exam_category", "DEF") not in EXAM_CATEGORIES:
        raise IssuanceError("Invalid examination category")


def normalize_photo(photo_bytes: bytes, output_path: Path) -> str:
    """Normalize an uploaded image and return its SHA-256 digest."""
    if not photo_bytes or len(photo_bytes) > 5 * 1024 * 1024:
        raise IssuanceError("Photo is empty or exceeds 5 MB")
    try:
        with Image.open(BytesIO(photo_bytes)) as source:
            if source.format not in {"JPEG", "PNG"}:
                raise IssuanceError("Photo must be a JPEG or PNG")
            source.verify()
        with Image.open(BytesIO(photo_bytes)) as source:
            image = ImageOps.exif_transpose(source).convert("RGB")
            image.thumbnail((400, 500), Image.Resampling.LANCZOS)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.parent.chmod(0o700)
            image.save(output_path, format="PNG", optimize=True)
            output_path.chmod(0o600)
    except (OSError, Image.DecompressionBombError) as exc:
        raise IssuanceError("Invalid photo image") from exc
    return sha256_hex(output_path.read_bytes())


def create_card_artifacts(
    student_data: dict[str, str],
    issuer_id: str,
    aes_key: bytes,
    private_key: Any,
    photo_bytes: bytes,
    upload_dir: Path,
    card_dir: Path,
    qr_dir: Path,
    validity_days: int = 365,
) -> tuple[dict[str, Any], str, CardArtifacts]:
    """Build one card, generating the signed timestamps exactly once."""
    validate_student_data(student_data)
    student_id = str(uuid.uuid4())
    photo_path = Path(upload_dir) / f"{student_id}.png"
    photo_hash = normalize_photo(photo_bytes, photo_path)
    issued = datetime.now(UTC).replace(microsecond=0)
    expires = issued + timedelta(days=validity_days)
    issued_at, expires_at = issued.isoformat().replace("+00:00", "Z"), expires.isoformat().replace("+00:00", "Z")
    personal_data: dict[str, Any] = {
        "student_id": student_id,
        "last_name": student_data["last_name"].strip(),
        "first_name": student_data["first_name"].strip(),
        "date_of_birth": student_data["date_of_birth"].strip(),
        "class": student_data["class"].strip(),
        "school": student_data["school"].strip(),
        "exam_category": student_data.get("exam_category", "DEF"),
        "photo_hash": photo_hash,
    }
    nina = student_data.get("nina", "").strip()
    if nina:
        personal_data["nina"] = nina
    qr_personal_data = {
        "ln": personal_data["last_name"],
        "fn": personal_data["first_name"],
        "dob": personal_data["date_of_birth"],
        "cl": personal_data["class"],
        "sc": personal_data["school"],
        "ph": personal_data["photo_hash"],
        "ex": personal_data["exam_category"],
    }
    if nina:
        qr_personal_data["ni"] = nina
    encrypted_data = encrypt_json(qr_personal_data, aes_key)
    payload: dict[str, Any] = {
        "v": 1,
        "student_id": student_id,
        "issuer_id": issuer_id,
        "encrypted_data": encrypted_data,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    from cids_mali.crypto_utils import sign_payload

    payload["signature"] = sign_payload(payload, private_key)
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    qr_dir, card_dir = Path(qr_dir), Path(card_dir)
    qr_dir.mkdir(parents=True, exist_ok=True)
    card_dir.mkdir(parents=True, exist_ok=True)
    Path(upload_dir).mkdir(parents=True, exist_ok=True)
    for directory in (Path(upload_dir), qr_dir, card_dir):
        directory.chmod(0o700)
    qr_path = qr_dir / f"{student_id}.png"
    qr = qrcode.QRCode(error_correction=ERROR_CORRECT_H, box_size=8, border=4)
    qr.add_data(payload_json)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    qr_image.save(qr_path, format="PNG", dpi=(300, 300))
    qr_path.chmod(0o600)

    png_path = card_dir / f"{student_id}.png"
    pdf_path = card_dir / f"{student_id}.pdf"
    _render_card_png(personal_data, photo_path, qr_image, png_path)
    _render_card_pdf(personal_data, photo_path, qr_image, pdf_path)
    png_path.chmod(0o600)
    pdf_path.chmod(0o600)
    return personal_data, student_id, CardArtifacts(payload, qr_path, png_path, pdf_path, photo_path)


def _font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _render_card_png(
    data: dict[str, Any], photo_path: Path, qr_image: Image.Image, output: Path
) -> None:
    width, height = 1011, 638
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, width, 110), fill="#17594f")
    draw.text((42, 28), data["school"], font=_font(32, True), fill="white")
    draw.text((42, 73), "STUDENT ID", font=_font(18, True), fill="#e4f3ec")
    with Image.open(photo_path) as photo:
        photo = ImageOps.fit(photo, (220, 280))
        image.paste(photo, (42, 155))
    qr_image.thumbnail((250, 250))
    image.paste(qr_image, (width - 290, 160))
    draw.text((300, 170), f"{data['first_name']} {data['last_name']}", font=_font(29, True), fill="#172421")
    draw.text((300, 230), f"Class: {data['class']}", font=_font(22), fill="#3d514c")
    draw.text((300, 275), f"Date of birth: {data['date_of_birth']}", font=_font(18), fill="#3d514c")
    draw.text((300, 320), f"Exam: {data['exam_category']}", font=_font(18, True), fill="#17594f")
    draw.text((300, 365), f"Card number: {data['student_id']}", font=_font(16), fill="#3d514c")
    image.save(output, format="PNG", dpi=(300, 300))


def _render_card_pdf(
    data: dict[str, Any], photo_path: Path, qr_image: Image.Image, output: Path
) -> None:
    page_width, page_height = 85.6 * mm, 54 * mm
    document = canvas.Canvas(str(output), pagesize=(page_width, page_height))
    document.setFillColorRGB(0.09, 0.35, 0.31)
    document.rect(0, page_height - 12 * mm, page_width, 12 * mm, fill=1, stroke=0)
    document.setFillColorRGB(1, 1, 1)
    document.setFont("Helvetica-Bold", 8)
    document.drawString(4 * mm, page_height - 7.5 * mm, data["school"][:45])
    document.drawImage(str(photo_path), 4 * mm, 8 * mm, width=20 * mm, height=27 * mm, preserveAspectRatio=True)
    document.drawImage(qr_image_path := _save_temp_qr(qr_image, output), 62 * mm, 9 * mm, width=19 * mm, height=19 * mm)
    document.setFillColorRGB(0.1, 0.14, 0.13)
    document.setFont("Helvetica-Bold", 7)
    document.drawString(27 * mm, 31 * mm, f"{data['first_name']} {data['last_name']}"[:34])
    document.setFont("Helvetica", 6)
    document.drawString(27 * mm, 25 * mm, f"Class: {data['class']}"[:42])
    document.drawString(27 * mm, 20 * mm, f"DOB: {data['date_of_birth']}"[:42])
    document.drawString(27 * mm, 15 * mm, f"Exam: {data['exam_category']}"[:42])
    document.setFont("Helvetica", 5)
    document.drawString(27 * mm, 10 * mm, f"Card no.: {data['student_id']}"[:42])
    document.save()
    Path(qr_image_path).unlink(missing_ok=True)


def _save_temp_qr(image: Image.Image, output: Path) -> str:
    temp_path = output.with_suffix(".qr.png")
    image.save(temp_path, format="PNG", dpi=(300, 300))
    temp_path.chmod(0o600)
    return str(temp_path)