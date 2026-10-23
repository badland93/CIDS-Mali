import json
from datetime import UTC, datetime, timedelta
from html import unescape
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from cids_mali.crypto_utils import anonymize_operator
from cids_mali.models import Database
from cids_mali.verifier import verify_card


def test_student_sensitive_fields_are_encrypted_in_sqlite(school, demo_photo, student_data):
    from tests.test_flows import _issue

    artifacts = _issue(school, demo_photo, student_data)
    raw_database = (school["root"] / "data" / "school.db").read_bytes()
    assert b"Traor" not in raw_database
    assert b"Aminata" not in raw_database
    assert b"Guardian Demo" not in raw_database
    assert school["database"].get_student(artifacts.payload["student_id"])["last_name"] == "Traoré"


def test_sql_injection_is_data_not_sql(school):
    database: Database = school["database"]
    database.create_user("admin'); DROP TABLE users;--", "long-enough-demo-password", "admin")
    assert database.get_user("admin'); DROP TABLE users;--") is not None
    assert database.list_users()[0]["username"] == "admin'); DROP TABLE users;--"


def test_erasure_removes_student_and_anonymizes_audit(school, demo_photo, student_data):
    from tests.test_flows import _issue
    from cids_mali.admin import erase_student_data

    artifacts = _issue(school, demo_photo, student_data)
    student_id = artifacts.payload["student_id"]
    assert erase_student_data(
        school["database"], student_id, "admin-demo",
        school["root"] / "uploads", school["root"] / "qr", school["root"] / "cards",
    )
    assert school["database"].get_student(student_id) is None
    assert not artifacts.photo_path.exists()
    assert not artifacts.qr_path.exists()
    with school["database"].connection() as connection:
        rows = connection.execute("SELECT student_id FROM issuance_log").fetchall()
    assert all(row["student_id"] is None for row in rows)


def test_login_csrf_and_session_cookie(app):
    database = app.extensions["cids_database"]
    database.create_user("web-admin", "strong-demo-password-123", "admin")
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Staff sign in" in response.data
    login = client.post("/login", data={"username": "web-admin", "password": "strong-demo-password-123"})
    assert login.status_code == 302
    cookie = login.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_security_headers_include_permissions_policy(app):
    response = app.test_client().get("/login")
    assert response.status_code == 200
    assert "Permissions-Policy" in response.headers
    assert "camera=(self)" in response.headers["Permissions-Policy"]
    assert "geolocation=()" in response.headers["Permissions-Policy"]
    assert "microphone=()" in response.headers["Permissions-Policy"]


def test_csrf_rejects_post_without_token(app):
    app.config["WTF_CSRF_ENABLED"] = True
    response = app.test_client().post("/login", data={"username": "x", "password": "x"})
    assert response.status_code == 400


def test_login_failure_rate_limit(app):
    client = app.test_client()
    for _ in range(5):
        assert client.post("/login", data={"username": "unknown", "password": "incorrect"}).status_code == 200
    limited = client.post("/login", data={"username": "unknown", "password": "incorrect"})
    assert limited.status_code == 429


def test_application_requires_secret_key(school):
    import pytest

    from cids_mali.app import create_app

    with pytest.raises(RuntimeError, match="CIDS_SECRET_KEY"):
        create_app({"SECRET_KEY": None, "KEY_PASSWORD": "test-key-password-123"})


def test_operator_hash_is_deterministic_and_not_username():
    digest = anonymize_operator("secretary@example.test")
    assert digest == anonymize_operator("secretary@example.test")
    assert digest != "secretary@example.test"


def test_private_key_is_encrypted_and_protected(school):
    from cids_mali.crypto_utils import load_private_key

    private_path = school["key_dir"] / "issuer_private.pem"
    key_bytes = private_path.read_bytes()
    assert b"ENCRYPTED" in key_bytes
    assert private_path.stat().st_mode & 0o777 == 0o600
    assert load_private_key(private_path, "test-key-password-123").key_size == 2048


def test_master_key_initialization_refuses_regeneration(school):
    import pytest

    from cids_mali.crypto_utils import CryptoError, initialize_aes_key

    with pytest.raises(CryptoError, match="already exists"):
        initialize_aes_key(school["key_dir"] / "aes_master.key")


def test_issuer_rotation_keeps_previous_public_key_and_aes_key(school):
    from cids_mali.admin import rotate_issuer_key
    from cids_mali.crypto_utils import load_aes_key, load_public_key

    public_path = school["key_dir"] / "issuer_public.pem"
    old_public = public_path.read_bytes()
    aes_before = load_aes_key(school["key_dir"] / "aes_master.key")
    rotate_issuer_key(school["key_dir"], "test-key-password-123", "ML-TEST-001")
    assert public_path.read_bytes() != old_public
    assert (school["key_dir"] / "trusted" / "ML-TEST-001.pem").read_bytes() == old_public
    assert load_public_key(school["key_dir"] / "trusted" / "ML-TEST-001.pem").key_size == 2048
    assert load_aes_key(school["key_dir"] / "aes_master.key") == aes_before


def test_login_xss_value_is_not_reflected_as_markup(app):
    client = app.test_client()
    response = client.post("/login", data={"username": "<script>alert(1)</script>", "password": "bad"})
    assert b"<script>alert(1)</script>" not in response.data


def test_uploaded_filename_is_not_used_as_a_path(app, school, demo_photo):
    from io import BytesIO

    database = app.extensions["cids_database"]
    database.create_user("issuer", "strong-demo-password-123", "admin")
    client = app.test_client()
    client.post("/login", data={"username": "issuer", "password": "strong-demo-password-123"})
    response = client.post(
        "/issue",
        data={
            "first_name": "Aminata", "last_name": "Traoré", "date_of_birth": "2012-04-12",
            "student_class": "9e année", "school": "Ecole Demo", "nina": "",
            "guardian_name": "Guardian Demo", "consent_date": "2026-10-23", "consent_given": "y",
            "photo": (BytesIO(demo_photo), "../../outside.png"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert not (school["root"].parent / "outside.png").exists()


def test_offline_verifier_is_static_and_self_contained(app):
    database = app.extensions["cids_database"]
    database.create_user("offline-secretary", "strong-secretary-password", "secretary")
    client = app.test_client()
    response = client.get("/offline-verifier")
    assert response.status_code == 302
    assert client.get("/static/offline-verifier.html").status_code == 302
    client.post("/login", data={"username": "offline-secretary", "password": "strong-secretary-password"})
    response = client.get("/offline-verifier")
    assert response.status_code == 302
    page = app.test_client().get(response.headers["Location"])
    assert page.status_code == 302
    page = client.get(response.headers["Location"])
    assert page.status_code == 200
    assert b"offline-verifier.js" in page.data
    assert b"DecompressionStream" in client.get("/static/offline-verifier.js").data
    assert b"exam_category" in client.get("/static/offline-verifier.js").data
    assert b"unsafe-inline" not in page.headers.get("Content-Security-Policy", "").encode()


def test_secretary_cannot_access_admin_controls(app):
    database = app.extensions["cids_database"]
    database.create_user("secretary", "strong-demo-password-123", "secretary")
    client = app.test_client()
    client.post("/login", data={"username": "secretary", "password": "strong-demo-password-123"})
    denied = client.get("/admin")
    assert denied.status_code == 403
    assert "Zone réservée" in denied.get_data(as_text=True)
    assert client.get("/issue").status_code == 403
    assert client.get("/verify").status_code == 200
    assert client.get("/admin/students").status_code == 403
    assert client.get("/").headers["Location"].endswith("/verify")
    verification_page = client.get("/verify").get_data(as_text=True)
    assert "Vérifier" in verification_page
    assert 'href="/issue"' not in verification_page


def test_admin_lands_in_candidate_management_not_director_reports(app):
    database = app.extensions["cids_database"]
    database.create_user("admin-home", "strong-admin-password", "admin")
    client = app.test_client()
    client.post("/login", data={"username": "admin-home", "password": "strong-admin-password"})
    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/students")
    page = client.get(response.headers["Location"]).get_data(as_text=True)
    assert "Situation des élèves" in page
    assert 'href="/admin"' not in page


def test_student_list_detail_and_csv_links_work(app):
    database: Database = app.extensions["cids_database"]
    issued = datetime.now(UTC).replace(microsecond=0)
    student_id = str(uuid4())
    database.issue_student(
        {
            "student_id": student_id,
            "first_name": "Aminata",
            "last_name": "Traoré",
            "date_of_birth": "2012-04-12",
            "class": "9e",
            "school": "École de Bamako",
            "nina": "",
            "photo_hash": None,
        },
        "Guardian",
        issued.date().isoformat(),
        "operator-hash",
        issued.isoformat(),
        (issued + timedelta(days=365)).isoformat(),
    )
    database.create_user("director", "strong-director-password", "director")
    client = app.test_client()
    client.post("/login", data={"username": "director", "password": "strong-director-password"})

    dashboard = client.get("/admin")
    assert dashboard.status_code == 200
    assert f"/admin/students/{student_id}" in dashboard.get_data(as_text=True)
    report = client.get("/admin/api/stats")
    assert report.status_code == 200
    report_data = report.get_json()
    assert len(report_data["exam_categories"]) == 6
    assert next(item for item in report_data["exam_categories"] if item["code"] == "DEF")["candidates"] == 1
    assert client.get("/admin/reports/categories.csv").status_code == 200

    roster = client.get("/admin/students")
    assert roster.status_code == 200
    assert "Aminata Traoré" in roster.get_data(as_text=True)
    assert f"/admin/students/{student_id}" in roster.get_data(as_text=True)
    filtered = client.get("/admin/students?q=Aminata&category=DEF&status=valid")
    assert filtered.status_code == 200
    assert "Aminata Traoré" in filtered.get_data(as_text=True)

    card_number_result = client.get(f"/verify?card_number={student_id}")
    assert card_number_result.status_code == 200
    assert "Valide" in card_number_result.get_data(as_text=True)
    assert "Diplôme d'Études Fondamentales" in unescape(card_number_result.get_data(as_text=True))

    detail = client.get(f"/admin/students/{student_id}")
    assert detail.status_code == 200
    assert "École de Bamako" in detail.get_data(as_text=True)
    assert "Télécharger la carte PDF" not in detail.get_data(as_text=True)

    exported = client.get("/admin/students/export.csv")
    assert exported.status_code == 200
    assert exported.mimetype == "text/csv"
    assert "Aminata Traoré" in exported.get_data(as_text=True)


def test_admin_can_edit_candidate_and_replace_card(app, demo_photo):
    from cids_mali.admin import issue_card, load_issuer_private_key

    database: Database = app.extensions["cids_database"]
    database.create_user("edit-admin", "strong-admin-password", "admin")
    private_key = load_issuer_private_key(app.config["KEY_DIR"], "test-key-password-123")
    artifacts = issue_card(
        database,
        {
            "first_name": "Aminata", "last_name": "Traoré", "date_of_birth": "2012-04-12",
            "class": "9e", "school": "École de Bamako", "exam_category": "DEF", "nina": "",
        },
        "Guardian", True, "edit-admin", "ML-TEST-001", app.extensions["cids_aes_key"],
        private_key, demo_photo, app.config["UPLOAD_DIR"], app.config["CARD_DIR"],
        app.config["QR_DIR"], 365, "2026-10-20",
    )
    student_id = artifacts.payload["student_id"]
    client = app.test_client()
    client.post("/login", data={"username": "edit-admin", "password": "strong-admin-password"})
    edit_page = client.get(f"/admin/students/{student_id}/edit")
    assert edit_page.status_code == 200
    assert "Aminata" in edit_page.get_data(as_text=True)

    response = client.post(
        f"/admin/students/{student_id}/edit",
        data={
            "first_name": "Aminata Nouvelle", "last_name": "Traoré", "date_of_birth": "2012-04-12",
            "student_class": "Terminale", "school": "Lycée de Bamako", "exam_category": "BAC",
            "nina": "", "guardian_name": "Guardian", "consent_date": "2026-10-20",
            "consent_given": "y",
        },
    )
    assert response.status_code == 302
    new_student_id = urlsplit(response.headers["Location"]).path.rsplit("/", 1)[-1]
    assert new_student_id != student_id
    assert database.is_revoked(student_id)
    old_card_screen = unescape(client.get(f"/verify?card_number={student_id}").get_data(as_text=True))
    assert "Révoquée" in old_card_screen
    assert "Aminata Traoré" in old_card_screen
    assert "Diplôme d'Études Fondamentales" in old_card_screen
    old_qr_result = verify_card(
        artifacts.payload,
        {"ML-TEST-001": app.extensions["cids_database"].get_trusted_issuers()["ML-TEST-001"]},
        app.extensions["cids_aes_key"],
        {student_id},
    )
    assert old_qr_result.reason == "Card revoked"
    updated = database.get_student(new_student_id)
    assert updated["first_name"] == "Aminata Nouvelle"
    assert updated["exam_category"] == "BAC"
    current_candidates = database.list_students()
    assert len(current_candidates) == 1
    assert current_candidates[0]["student_id"] == new_student_id
    report = database.dashboard_report()
    assert next(item for item in report["exam_categories"] if item["code"] == "BAC")["cards_issued"] == 1
    assert next(item for item in report["issued_by_admin"] if item["username"] == "edit-admin")["cards_issued"] == 2
    with database.connection() as connection:
        event = connection.execute(
            "SELECT action FROM issuance_log WHERE student_id = ? ORDER BY log_id DESC LIMIT 1",
            (new_student_id,),
        ).fetchone()
    assert event["action"] == "REISSUE"

    second_edit = client.post(
        f"/admin/students/{new_student_id}/edit",
        data={
            "first_name": "Aminata Encore", "last_name": "Traoré", "date_of_birth": "2012-04-12",
            "student_class": "Terminale", "school": "Lycée de Bamako", "exam_category": "BAC",
            "nina": "", "guardian_name": "Guardian", "consent_date": "2026-10-20",
            "consent_given": "y",
        },
    )
    assert second_edit.status_code == 302
    previous_replacement_id = new_student_id
    new_student_id = urlsplit(second_edit.headers["Location"]).path.rsplit("/", 1)[-1]
    assert new_student_id != previous_replacement_id
    assert database.get_student(previous_replacement_id)["status"] == "revoked"
    assert database.get_student(new_student_id)["first_name"] == "Aminata Encore"
    assert len(database.list_students()) == 1
    assert client.get(f"/cards/{student_id}.pdf").status_code == 410
    assert client.get(f"/cards/{student_id}.png").status_code == 410

    revoked = client.post(f"/admin/students/{new_student_id}/revoke", data={"reason": "Test"})
    assert revoked.status_code == 302
    assert database.is_revoked(new_student_id)
    card_ids = database.list_candidate_card_ids(new_student_id)
    erased = client.post(f"/admin/students/{new_student_id}/erase")
    assert erased.status_code == 302
    assert database.get_student(new_student_id) is None
    assert database.get_student(student_id) is None
    for card_id in card_ids:
        assert not (Path(app.config["UPLOAD_DIR"]) / f"{card_id}.png").exists()
        assert not (Path(app.config["QR_DIR"]) / f"{card_id}.png").exists()
        assert not (Path(app.config["CARD_DIR"]) / f"{card_id}.png").exists()
        assert not (Path(app.config["CARD_DIR"]) / f"{card_id}.pdf").exists()


def test_only_director_can_manage_admin_accounts(app):
    database = app.extensions["cids_database"]
    database.create_user("director", "strong-director-password", "director")
    admin_id = database.create_user("school-admin", "strong-admin-password", "admin")

    admin_client = app.test_client()
    admin_client.post("/login", data={"username": "school-admin", "password": "strong-admin-password"})
    assert admin_client.get("/director/admins").status_code == 403
    assert admin_client.get("/director/settings").status_code == 403

    director_client = app.test_client()
    director_client.post("/login", data={"username": "director", "password": "strong-director-password"})
    assert director_client.get("/director/admins").status_code == 200
    assert director_client.get("/director/settings").status_code == 200
    updated_settings = director_client.post("/director/settings", data={"card_validity_days": "500"})
    assert updated_settings.status_code == 302
    assert database.get_setting("card_validity_days") == "500"
    invalid_settings = director_client.post("/director/settings", data={"card_validity_days": "10"})
    assert invalid_settings.status_code == 200
    assert database.get_setting("card_validity_days") == "500"
    created = director_client.post(
        "/director/admins",
        data={"action": "create_admin", "username": "new-admin", "password": "new-admin-password", "role": "admin"},
    )
    assert created.status_code == 302
    assert database.get_user("new-admin")["role"] == "admin"

    created_secretary = director_client.post(
        "/director/admins",
        data={"action": "create_admin", "username": "new-secretary", "password": "new-secretary-password", "role": "secretary"},
    )
    assert created_secretary.status_code == 302
    secretary = database.get_user("new-secretary")
    assert secretary["role"] == "secretary"

    disabled = director_client.post(
        "/director/admins", data={"action": "disable_admin", "user_id": admin_id}
    )
    assert disabled.status_code == 302
    assert database.authenticate("school-admin", "strong-admin-password") is None

    removed = director_client.post(
        "/director/admins", data={"action": "delete_admin", "user_id": admin_id}
    )
    assert removed.status_code == 302
    assert database.get_user("school-admin") is None
    director_client.post(
        "/director/admins", data={"action": "disable_admin", "user_id": secretary["id"]}
    )
    assert database.authenticate("new-secretary", "new-secretary-password") is None


def test_disabling_admin_invalidates_existing_session(app):
    database = app.extensions["cids_database"]
    admin_id = database.create_user("session-admin", "strong-admin-password", "admin")
    client = app.test_client()
    client.post("/login", data={"username": "session-admin", "password": "strong-admin-password"})
    assert client.get("/admin/students").status_code == 200

    assert database.set_admin_active(admin_id, False)
    response = client.get("/admin/students")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_existing_admin_can_be_appointed_as_single_director(school):
    database: Database = school["database"]
    database.create_user("owner", "strong-owner-password", "admin")
    assert database.appoint_director("owner")
    assert database.get_user("owner")["role"] == "director"
    assert not database.appoint_director("owner")


def test_verification_result_autoescapes_student_data(app, school):
    from datetime import UTC, datetime, timedelta

    from cids_mali.admin import load_issuer_private_key
    from cids_mali.crypto_utils import encrypt_json, sign_payload

    database = app.extensions["cids_database"]
    database.create_user("verifier", "strong-demo-password-123", "secretary")
    client = app.test_client()
    client.post("/login", data={"username": "verifier", "password": "strong-demo-password-123"})
    issued = datetime.now(UTC).replace(microsecond=0)
    payload = {
        "v": 1,
        "student_id": "c24320e5-aad3-48b8-80aa-90cec7178980",
        "issuer_id": "ML-TEST-001",
        "encrypted_data": encrypt_json(
            {
                "first_name": "<script>alert(1)</script>", "last_name": "Test",
                "date_of_birth": "2012-01-01", "class": "9e année",
                "school": "Demo", "photo_hash": "a" * 64,
            },
            school["aes_key"],
        ),
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued + timedelta(days=365)).isoformat().replace("+00:00", "Z"),
    }
    payload["signature"] = sign_payload(
        payload,
        load_issuer_private_key(school["key_dir"], "test-key-password-123"),
    )
    response = client.post("/verify", data={"qr_json": json.dumps(payload)})
    assert response.status_code == 200
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in response.data
    assert b"<script>alert(1)</script>" not in response.data