"""Cryptographic primitives used by the CIDS-Mali prototype."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import zlib
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class CryptoError(ValueError):
    """Raised when cryptographic input is malformed or cannot be authenticated."""


def canonical_payload(payload: Mapping[str, Any]) -> bytes:
    """Serialize the exact signed fields in the canonical UTF-8 representation."""
    try:
        version = payload["version"] if "version" in payload else payload["v"]
        signed = {
            "version": version,
            "student_id": payload["student_id"],
            "issuer_id": payload["issuer_id"],
            "encrypted_data": payload["encrypted_data"],
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
        }
    except KeyError as exc:
        raise CryptoError("Missing signed payload field") from exc
    return json.dumps(signed, sort_keys=True, ensure_ascii=False).encode("utf-8")


def encrypt_json(data: Mapping[str, Any], key: bytes) -> str:
    """Encrypt JSON with AES-256-CBC and PKCS7; prefer compressed payloads for compact QR cards."""
    if len(key) != 32:
        raise CryptoError("AES-256 key must be exactly 32 bytes")
    plaintext = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(plaintext)
    payload = b"c1:" + compressed if len(compressed) < len(plaintext) else b"u1:" + plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(payload) + padder.finalize()
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode("ascii")


def decrypt_json(encoded: str, key: bytes) -> dict[str, Any]:
    """Decrypt and parse a payload produced by :func:`encrypt_json`."""
    if len(key) != 32:
        raise CryptoError("AES-256 key must be exactly 32 bytes")
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) < 32 or len(raw) % 16 != 0:
            raise CryptoError("Invalid AES payload length")
        decryptor = Cipher(algorithms.AES(key), modes.CBC(raw[:16])).decryptor()
        padded = decryptor.update(raw[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        if plaintext.startswith(b"c1:"):
            payload = zlib.decompress(plaintext[3:])
        elif plaintext.startswith(b"u1:"):
            payload = plaintext[3:]
        else:
            payload = plaintext
        value = json.loads(payload.decode("utf-8"))
        if not isinstance(value, dict):
            raise CryptoError("Encrypted data must be a JSON object")
        return value
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, zlib.error) as exc:
        if isinstance(exc, CryptoError):
            raise
        raise CryptoError("Unable to decrypt personal data") from exc


def sign_payload(payload: Mapping[str, Any], private_key: rsa.RSAPrivateKey) -> str:
    signature = private_key.sign(
        canonical_payload(payload),
        asymmetric_padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_signature(
    payload: Mapping[str, Any], signature: str, public_key: rsa.RSAPublicKey
) -> bool:
    try:
        public_key.verify(
            base64.b64decode(signature, validate=True),
            canonical_payload(payload),
            asymmetric_padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, CryptoError):
        return False


def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def save_private_key(private_key: rsa.RSAPrivateKey, path: Path, password: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    path.write_bytes(pem)
    path.chmod(0o600)


def load_private_key(path: Path, password: str) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password.encode("utf-8"))
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CryptoError("Issuer private key must be RSA")
    return key


def save_public_key(public_key: rsa.RSAPublicKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, rsa.RSAPublicKey):
        raise CryptoError("Issuer public key must be RSA")
    return key


def initialize_aes_key(path: Path) -> bytes:
    """Create the master key once; never silently replace an existing key."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise CryptoError("AES master key already exists; refusing to regenerate it") from exc
    key = os.urandom(32)
    with os.fdopen(descriptor, "wb") as key_file:
        key_file.write(key)
    path.chmod(0o600)
    return key


def load_aes_key(path: Path) -> bytes:
    key = path.read_bytes()
    if len(key) != 32:
        raise CryptoError("AES master key file must contain exactly 32 bytes")
    return key


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def anonymize_operator(operator_id: str) -> str:
    return sha256_hex(operator_id.encode("utf-8"))