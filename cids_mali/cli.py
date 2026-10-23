"""Administrative command-line interface."""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path

from dotenv import load_dotenv

from cids_mali.admin import export_public_key, initialize_keys, rotate_issuer_key
from cids_mali.config import PROJECT_ROOT
from cids_mali.crypto_utils import load_aes_key
from cids_mali.models import Database


def main(argv: list[str] | None = None) -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    parser = argparse.ArgumentParser(prog="cids-mali")
    parser.add_argument("--key-dir", type=Path, default=Path(os.getenv("CIDS_KEY_DIR", PROJECT_ROOT / "keys")))
    parser.add_argument("--database", type=Path, default=Path(os.getenv("CIDS_DATABASE", PROJECT_ROOT / "data" / "cids.db")))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init-keys", help="Generate the issuer and AES keys once")
    export = commands.add_parser("export-public-key", help="Export the issuer public key")
    export.add_argument("output", type=Path)
    rotate = commands.add_parser("rotate-keys", help="Rotate the issuer signing key")
    rotate.add_argument("--old-issuer-id", default=os.getenv("CIDS_ISSUER_ID", "ML-SCHOOL-001"))
    admin = commands.add_parser("create-admin", help="Create the first Director account")
    admin.add_argument("username")
    director = commands.add_parser("appoint-director", help="Appoint an existing administrator as Director")
    director.add_argument("username")
    revoke = commands.add_parser("revoke", help="Revoke a student card")
    revoke.add_argument("student_id")
    revoke.add_argument("reason")
    erase = commands.add_parser("erase", help="Erase a student's data and card files")
    erase.add_argument("student_id")
    trust = commands.add_parser("trust-issuer", help="Add an offline issuer public key to the local verifier")
    trust.add_argument("issuer_id")
    trust.add_argument("public_key", type=Path)
    export_revocations = commands.add_parser("export-revocations", help="Export the local revocation list")
    export_revocations.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    if args.command == "init-keys":
        password = os.environ.get("CIDS_KEY_PASSWORD") or getpass.getpass("Issuer key password: ")
        initialize_keys(args.key_dir, password)
        print("Issuer and AES keys initialized.")
        return 0
    if args.command == "export-public-key":
        export_public_key(args.key_dir / "issuer_public.pem", args.output)
        print(f"Public key exported to {args.output}")
        return 0
    if args.command == "rotate-keys":
        password = os.environ.get("CIDS_KEY_PASSWORD") or getpass.getpass("Issuer key password: ")
        rotate_issuer_key(args.key_dir, password, args.old_issuer_id)
        print("Issuer key rotated. Update CIDS_ISSUER_ID and distribute the new public key.")
        return 0
    if not (args.key_dir / "aes_master.key").exists():
        parser.error("Run init-keys before managing users or student records")
    database = Database(args.database, load_aes_key(args.key_dir / "aes_master.key"))
    if args.command == "create-admin":
        secret = getpass.getpass("New password (12+ characters): ")
        if len(secret) < 12:
            parser.error("Password must be at least 12 characters")
        if any(user["role"] == "director" for user in database.list_users()):
            parser.error("A Director already exists; create users in the Director web interface")
        database.create_user(args.username, secret, "director")
        print(f"User {args.username} created with role director.")
    elif args.command == "appoint-director":
        if not database.appoint_director(args.username):
            parser.error("A Director already exists, or the username is not an administrator")
        print(f"User {args.username} appointed as Director.")
    elif args.command == "revoke":
        import hashlib

        operator_id = os.environ.get("CIDS_OPERATOR_ID") or input("Operator identifier: ").strip()
        if not operator_id:
            parser.error("An operator identifier is required for the audit log")
        if not database.revoke(args.student_id, args.reason, hashlib.sha256(operator_id.encode()).hexdigest()):
            parser.error("Student not found")
        print(f"Student {args.student_id} revoked.")
    elif args.command == "erase":
        from cids_mali.admin import erase_student_data

        operator_id = os.environ.get("CIDS_OPERATOR_ID") or input("Operator identifier: ").strip()
        if not operator_id:
            parser.error("An operator identifier is required for the audit log")
        if not erase_student_data(
            database,
            args.student_id,
            operator_id,
            PROJECT_ROOT / "data" / "uploads",
            PROJECT_ROOT / "data" / "qr",
            PROJECT_ROOT / "data" / "cards",
        ):
            parser.error("Student not found")
        print(f"Student {args.student_id} erased.")
    elif args.command == "trust-issuer":
        database.add_trusted_issuer(args.issuer_id, args.public_key.read_text(encoding="ascii"))
        print(f"Trusted issuer {args.issuer_id} added.")
    elif args.command == "export-revocations":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with database.connection() as connection:
            rows = connection.execute("SELECT student_id FROM revocations ORDER BY student_id").fetchall()
        args.output.write_text("\n".join(row["student_id"] for row in rows), encoding="utf-8")
        args.output.chmod(0o600)
        print(f"Revocations exported to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())