"""Locust workload: authenticated offline-card verification through Flask."""

from __future__ import annotations

import itertools
import os
import re
from pathlib import Path

from locust import HttpUser, task
from locust.exception import StopUser


USER_PREFIX = os.environ.get("CIDS_LOADTEST_USER_PREFIX", "load-")
USER_COUNT = int(os.environ.get("CIDS_LOADTEST_USERS", "50"))
USER_PASSWORD = os.environ.get("CIDS_LOADTEST_PASSWORD", "")
QR_FILE = Path(os.environ.get("CIDS_LOADTEST_QR", "data/demo_payload.json"))
USER_SEQUENCE = itertools.count(1)


class CardVerificationUser(HttpUser):
    wait_time = lambda self: 0.5

    def on_start(self):
        if not USER_PASSWORD or not QR_FILE.is_file():
            raise StopUser("Set CIDS_LOADTEST_PASSWORD and seed a demo QR payload first")
        user_index = (next(USER_SEQUENCE) - 1) % USER_COUNT + 1
        login_page = self.client.get("/login")
        token_match = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', login_page.content)
        if not token_match:
            raise StopUser("Could not find login CSRF token")
        login = self.client.post(
            "/login",
            data={
                "csrf_token": token_match.group(1).decode(),
                "username": f"{USER_PREFIX}{user_index:03d}",
                "password": USER_PASSWORD,
            },
            allow_redirects=False,
        )
        if login.status_code != 302:
            raise StopUser("Load-test login failed; check the prepared account list")
        verify_page = self.client.get("/verify")
        token_match = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', verify_page.content)
        if not token_match:
            raise StopUser("Could not find verification CSRF token")
        self.csrf_token = token_match.group(1).decode()
        self.payload = QR_FILE.read_text(encoding="utf-8")

    @task
    def verify_demo_card(self):
        with self.client.post(
            "/verify",
            data={"csrf_token": self.csrf_token, "qr_json": self.payload},
            name="POST /verify",
            catch_response=True,
        ) as response:
            if response.status_code != 200 or b"Valid card" not in response.content:
                response.failure("Card verification failed")
            else:
                response.success()