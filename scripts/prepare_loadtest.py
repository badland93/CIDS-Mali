"""Create unique Argon2 load-test accounts for the Locust scenario."""

from __future__ import annotations

import os

from dotenv import load_dotenv

from cids_mali.config import Config, PROJECT_ROOT
from cids_mali.crypto_utils import load_aes_key
from cids_mali.models import Database


def main() -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    password = os.environ.get("CIDS_LOADTEST_PASSWORD", "")
    if len(password) < 12:
        raise SystemExit("Set CIDS_LOADTEST_PASSWORD to a value of at least 12 characters")
    count = int(os.environ.get("CIDS_LOADTEST_USERS", "50"))
    database = Database(Config.DATABASE, load_aes_key(Config.KEY_DIR / "aes_master.key"))
    for index in range(1, count + 1):
        username = f"load-{index:03d}"
        if not database.get_user(username):
            database.create_user(username, password, "secretary")
    print(f"Prepared {count} local load-test accounts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())