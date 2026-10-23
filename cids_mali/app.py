"""Flask application factory for the school-local CIDS-Mali service."""

from __future__ import annotations

import hashlib
import csv
import io
import json
import time
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable
from uuid import UUID

from flask import Flask, Response, abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from cids_mali.admin import issue_card, load_issuer_private_key, public_key_pem
from cids_mali.config import Config, PROJECT_ROOT, validate_secret
from cids_mali.crypto_utils import load_aes_key
from cids_mali.exam_categories import EXAM_CATEGORIES, EXAM_CATEGORY_CHOICES
from cids_mali.forms import (
    ActionForm,
    CreateAdminForm,
    DirectorSettingsForm,
    EditIssueForm,
    IssueForm,
    LoginForm,
)
from cids_mali.models import Database
from cids_mali.verifier import verify_card


csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


class WebUser(UserMixin):
    def __init__(self, user_id: int, username: str, role: str):
        self.id = str(user_id)
        self.username = username
        self.role = role


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_port=1, x_prefix=1)
    validate_secret(app.config.get("SECRET_KEY"))
    if not app.config.get("KEY_PASSWORD"):
        raise RuntimeError("CIDS_KEY_PASSWORD is required; set it before starting the school application")
    app.config.setdefault("WTF_CSRF_ENABLED", True)
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("SESSION_COOKIE_SECURE", True)
    key_path = Path(app.config["KEY_DIR"]) / "aes_master.key"
    if not key_path.is_file():
        raise RuntimeError("School AES key is missing; run `python -m cids_mali.cli init-keys` first")
    aes_key = load_aes_key(key_path)
    database = Database(Path(app.config["DATABASE"]), aes_key)
    public_path = Path(app.config["KEY_DIR"]) / "issuer_public.pem"
    if public_path.is_file():
        database.add_trusted_issuer(app.config["ISSUER_ID"], public_path.read_text(encoding="ascii"))
    app.extensions["cids_database"] = database
    app.extensions["cids_aes_key"] = aes_key
    csrf.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str) -> WebUser | None:
        try:
            record = database.get_user_by_id(int(user_id))
        except ValueError:
            return None
        return (
            WebUser(record["id"], record["username"], record["role"])
            if record and record["is_active"]
            else None
        )

    def roles_required(*roles: str) -> Callable:
        def decorate(view: Callable) -> Callable:
            @wraps(view)
            def wrapped(*args: Any, **kwargs: Any):
                if not current_user.is_authenticated:
                    return login_manager.unauthorized()
                if current_user.role not in roles:
                    abort(403)
                return view(*args, **kwargs)

            return wrapped

        return decorate

    def operator_hash() -> str:
        return hashlib.sha256(current_user.username.encode("utf-8")).hexdigest()

    def configured_card_validity_days() -> int:
        return int(database.get_setting("card_validity_days", str(app.config["CARD_VALIDITY_DAYS"])))

    def present_student(student: dict[str, Any]) -> dict[str, Any]:
        presented = dict(student)
        category_code = student.get("exam_category", "DEF")
        presented["exam_category"] = category_code
        presented["category_name"] = EXAM_CATEGORIES.get(category_code, EXAM_CATEGORIES["DEF"])
        try:
            expiration = datetime.fromisoformat(student["expires_at"])
            if expiration.tzinfo is None:
                expiration = expiration.replace(tzinfo=UTC)
            expired = expiration < datetime.now(UTC)
            presented["expires_display"] = expiration.strftime("%d/%m/%Y")
        except (KeyError, TypeError, ValueError):
            expired = False
            presented["expires_display"] = student.get("expires_at", "")
        if student.get("status") == "revoked":
            presented.update(status_label="Révoquée", status_class="danger")
        elif expired:
            presented.update(status_label="Expirée", status_class="warning")
        else:
            presented.update(status_label="Valide", status_class="success")
        return presented

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Permissions-Policy", "camera=(self), geolocation=(), microphone=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if request.is_secure or app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'",
        )
        return response

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(410)
    def card_gone(_error):
        return render_template("errors/410.html"), 410

    @app.before_request
    def protect_offline_verifier_assets():
        protected_assets = {
            "/static/offline-verifier.html",
            "/static/offline-verifier.js",
            "/static/css/offline-verifier.css",
        }
        if request.path not in protected_assets:
            return None
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if current_user.role not in {"director", "admin", "secretary"}:
            abort(403)
        return None

    @app.get("/")
    @login_required
    def index():
        if current_user.role == "secretary":
            return redirect(url_for("verify_online"))
        if current_user.role == "admin":
            return redirect(url_for("admin_students"))
        return render_template("index.html", kpis=database.dashboard_report()["kpis"])

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data.strip()
            now = time.time()
            if database.count_login_attempts(username, now - 900) >= 5:
                flash("Sign-in temporarily unavailable. Try again later.", "error")
                return render_template("login.html", form=form), 429
            user = database.authenticate(username, form.password.data)
            database.record_login_attempt(username, now)
            if user:
                login_user(WebUser(user["id"], user["username"], user["role"]))
                return redirect(url_for("index"))
            flash("Invalid username or password.", "error")
        return render_template("login.html", form=form)

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.route("/issue", methods=["GET", "POST"])
    @login_required
    @roles_required("director", "admin")
    def issue():
        form = IssueForm()
        if form.validate_on_submit():
            if not form.consent_given.data:
                flash("Parental consent is required.", "error")
                return render_template("issue.html", form=form), 400
            if not app.extensions["cids_aes_key"]:
                flash("School keys are not initialized. Ask an administrator to run init-keys.", "error")
                return render_template("issue.html", form=form), 503
            try:
                private_key = load_issuer_private_key(
                    Path(app.config["KEY_DIR"]), app.config.get("KEY_PASSWORD") or ""
                )
                artifacts = issue_card(
                    database,
                    {
                        "first_name": form.first_name.data,
                        "last_name": form.last_name.data,
                        "date_of_birth": form.date_of_birth.data,
                        "class": form.student_class.data,
                        "school": form.school.data,
                        "exam_category": form.exam_category.data,
                        "nina": form.nina.data or "",
                    },
                    form.guardian_name.data,
                    form.consent_given.data,
                    current_user.username,
                    app.config["ISSUER_ID"],
                    app.extensions["cids_aes_key"],
                    private_key,
                    form.photo.data.read(),
                    Path(app.config["UPLOAD_DIR"]),
                    Path(app.config["CARD_DIR"]),
                    Path(app.config["QR_DIR"]),
                    configured_card_validity_days(),
                        form.consent_date.data,
                )
            except (ValueError, OSError) as exc:
                flash(str(exc), "error")
                return render_template("issue.html", form=form), 400
            return render_template(
                "card_preview.html",
                payload=artifacts.payload,
                student_data={
                    "first_name": form.first_name.data,
                    "last_name": form.last_name.data,
                    "exam_category": form.exam_category.data,
                },
            )
        return render_template("issue.html", form=form)

    @app.get("/cards/<uuid:student_id>.pdf")
    @login_required
    @roles_required("director", "admin")
    def card_pdf(student_id):
        student = database.get_student(str(student_id))
        if not student:
            abort(404)
        if student["status"] == "revoked":
            abort(410)
        path = Path(app.config["CARD_DIR"]) / f"{student_id}.pdf"
        if not path.is_file():
            abort(404)
        return send_file(path, as_attachment=True, download_name=f"{student_id}.pdf")

    @app.get("/cards/<uuid:student_id>.png")
    @login_required
    @roles_required("director", "admin")
    def card_png(student_id):
        student = database.get_student(str(student_id))
        if not student:
            abort(404)
        if student["status"] == "revoked":
            abort(410)
        path = Path(app.config["CARD_DIR"]) / f"{student_id}.png"
        if not path.is_file():
            abort(404)
        return send_file(path, as_attachment=True, download_name=f"{student_id}.png")

    @app.route("/verify", methods=["GET", "POST"])
    @login_required
    @roles_required("director", "admin", "secretary")
    def verify_online():
        result = None
        raw_payload = ""
        card_number = request.values.get("card_number", "").strip()
        if card_number:
            try:
                normalized_id = str(UUID(card_number))
            except ValueError:
                normalized_id = ""
            student = database.get_student(normalized_id) if normalized_id else None
            if student:
                student = present_student(student)
                result = {
                    "valid": student["status_label"] == "Valide",
                    "status_label": student["status_label"],
                    "reason": student["status_label"],
                    "student_data": student,
                }
                database.record_verification(
                    student["student_id"], operator_hash(), result["valid"], student["status_label"]
                )
            else:
                result = {"valid": False, "status_label": "Introuvable", "reason": "Numéro de carte introuvable"}
                database.record_verification(None, operator_hash(), False, result["reason"])
        elif request.method == "POST":
            raw_payload = request.form.get("qr_json", "")
            if not app.extensions["cids_aes_key"]:
                result = {"valid": False, "status_label": "Indisponible", "reason": "Clés non initialisées"}
            else:
                issuers = database.get_trusted_issuers()
                if not issuers:
                    try:
                        issuers = {app.config["ISSUER_ID"]: public_key_pem(Path(app.config["KEY_DIR"]))}
                    except OSError:
                        issuers = {}
                outcome = verify_card(
                    raw_payload,
                    issuers,
                    app.extensions["cids_aes_key"],
                    _revoked_ids(database),
                    exam_mode=request.form.get("exam_mode") == "1",
                    replay_window_seconds=int(app.config["REPLAY_WINDOW_SECONDS"]),
                )
                reason_labels = {
                    "Valid card": "Valide",
                    "Card expired": "Expirée",
                    "Card revoked": "Révoquée",
                    "Unknown issuer": "Émetteur inconnu",
                    "Invalid signature – tampering detected": "Signature invalide",
                    "Corrupted data": "Données corrompues",
                    "QR expired – possible replay": "QR expiré ou déjà utilisé",
                }
                student_data = outcome.student_data
                if not student_data and outcome.reason in {"Card expired", "Card revoked"} and outcome.student_id:
                    stored = database.get_student(outcome.student_id)
                    if stored:
                        student_data = stored
                if student_data:
                    student_data.setdefault("exam_category", "DEF")
                    student_data["category_name"] = EXAM_CATEGORIES.get(
                        student_data["exam_category"], EXAM_CATEGORIES["DEF"]
                    )
                result = {
                    "valid": outcome.valid,
                    "status_label": reason_labels.get(outcome.reason, "Refusée"),
                    "reason": reason_labels.get(outcome.reason, "Refusée"),
                    "student_data": student_data,
                }
                database.record_verification(
                    outcome.student_id, operator_hash(), outcome.valid,
                    reason_labels.get(outcome.reason, "Refusée"),
                )
        return render_template("verify.html", result=result, qr_json=raw_payload, card_number=card_number)

    @app.get("/offline-verifier")
    @login_required
    @roles_required("director", "admin", "secretary")
    def offline_verifier():
        return redirect(url_for("static", filename="offline-verifier.html"))

    @app.route("/admin", methods=["GET", "POST"])
    @login_required
    @roles_required("director")
    def admin():
        revoke_form = ActionForm(prefix="revoke")
        erase_form = ActionForm(prefix="erase")
        action = request.form.get("action")
        if request.method == "POST" and action in {"revoke", "erase"}:
            form = revoke_form if action == "revoke" else erase_form
            if form.validate():
                if action == "revoke":
                    changed = database.revoke(form.student_id.data, form.reason.data or "Administrative revocation", operator_hash())
                else:
                    from cids_mali.admin import erase_student_data

                    changed = erase_student_data(
                        database,
                        form.student_id.data,
                        current_user.username,
                        Path(app.config["UPLOAD_DIR"]),
                        Path(app.config["QR_DIR"]),
                        Path(app.config["CARD_DIR"]),
                    )
                flash("Action completed." if changed else "Student not found.", "success" if changed else "error")
            return redirect(url_for("admin"))
        dashboard_payload = database.dashboard_report()
        return render_template(
            "admin/dashboard.html",
            revoke_form=revoke_form,
            erase_form=erase_form,
            audit=database.list_audit_events(),
            stats=dashboard_payload,
            category_stats=dashboard_payload["exam_categories"],
            admin_issue_counts=dashboard_payload["issued_by_admin"],
            students=[present_student(student) for student in database.list_students()[:5]],
        )

    @app.get("/admin/students")
    @login_required
    @roles_required("director", "admin")
    def admin_students():
        students = [present_student(student) for student in database.list_students()]
        search_query = request.args.get("q", "").strip()[:100]
        category_filter = request.args.get("category", "")
        if category_filter not in EXAM_CATEGORIES:
            category_filter = ""
        status_filter = request.args.get("status", "")
        if status_filter not in {"valid", "expired", "revoked"}:
            status_filter = ""
        search_term = search_query.casefold()
        filtered_students = []
        for student in students:
            if category_filter and student["exam_category"] != category_filter:
                continue
            if status_filter and student["status_label"].casefold() != {
                "valid": "valide", "expired": "expirée", "revoked": "révoquée"
            }[status_filter]:
                continue
            searchable = " ".join(str(student.get(field, "")) for field in (
                "first_name", "last_name", "school", "student_id", "exam_category", "class"
            )).casefold()
            if search_term and search_term not in searchable:
                continue
            filtered_students.append(student)
        return render_template(
            "admin/students.html",
            students=filtered_students,
            search_query=search_query,
            category_filter=category_filter,
            category_choices=EXAM_CATEGORY_CHOICES,
            status_filter=status_filter,
        )

    @app.get("/admin/students/export.csv")
    @login_required
    @roles_required("director", "admin")
    def admin_students_export():
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["Élève", "Classe", "Établissement", "Expiration", "Statut", "Identifiant"])
        for student in database.list_students():
            student = present_student(student)
            values = [
                f"{student['first_name']} {student['last_name']}",
                student["class"],
                student["school"],
                student["expires_display"],
                student["status_label"],
                student["student_id"],
            ]
            writer.writerow([
                "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value
                for value in values
            ])
        return Response(
            "\ufeff" + output.getvalue(),
            content_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=cids-eleves.csv"},
        )

    @app.get("/admin/students/<uuid:student_id>")
    @login_required
    @roles_required("director", "admin")
    def admin_student_detail(student_id):
        student = database.get_student(str(student_id))
        if not student:
            abort(404)
        student = present_student(student)
        student["pdf_available"] = (
            Path(app.config["CARD_DIR"]) / f"{student['student_id']}.pdf"
        ).is_file()
        return render_template("admin/student_detail.html", student=student)

    @app.post("/admin/students/<uuid:student_id>/revoke")
    @login_required
    @roles_required("director", "admin")
    def admin_student_revoke(student_id):
        reason = request.form.get("reason", "").strip()[:240] or "Révocation administrative"
        changed = database.revoke(str(student_id), reason, operator_hash())
        flash("Carte révoquée." if changed else "Candidat introuvable.", "success" if changed else "error")
        return redirect(url_for("admin_student_detail", student_id=student_id) if changed else url_for("admin_students"))

    @app.post("/admin/students/<uuid:student_id>/erase")
    @login_required
    @roles_required("director", "admin")
    def admin_student_erase(student_id):
        from cids_mali.admin import erase_student_data

        changed = erase_student_data(
            database,
            str(student_id),
            current_user.username,
            Path(app.config["UPLOAD_DIR"]),
            Path(app.config["QR_DIR"]),
            Path(app.config["CARD_DIR"]),
        )
        flash("Données du candidat supprimées." if changed else "Candidat introuvable.", "success" if changed else "error")
        return redirect(url_for("admin_students"))

    @app.route("/admin/students/<uuid:student_id>/edit", methods=["GET", "POST"])
    @login_required
    @roles_required("director", "admin")
    def admin_student_edit(student_id):
        student_id = str(student_id)
        student = database.get_student(student_id)
        if not student or student["status"] == "revoked":
            abort(404)
        form = EditIssueForm()
        if request.method == "GET":
            form.first_name.data = student["first_name"]
            form.last_name.data = student["last_name"]
            form.date_of_birth.data = student["date_of_birth"]
            form.student_class.data = student["class"]
            form.school.data = student["school"]
            form.exam_category.data = student.get("exam_category", "DEF")
            form.nina.data = student.get("nina") or ""
            form.guardian_name.data = student.get("guardian_name", "")
            form.consent_date.data = student.get("consent_date")
        elif form.validate_on_submit():
            if not form.consent_given.data:
                flash("La confirmation du consentement est requise.", "error")
                return render_template("admin/student_edit.html", form=form, student=student), 400
            photo_path = Path(app.config["UPLOAD_DIR"]) / f"{student_id}.png"
            try:
                photo_bytes = form.photo.data.read() if form.photo.data else photo_path.read_bytes()
                private_key = load_issuer_private_key(
                    Path(app.config["KEY_DIR"]), app.config.get("KEY_PASSWORD") or ""
                )
                replacement = issue_card(
                    database,
                    {
                        "first_name": form.first_name.data,
                        "last_name": form.last_name.data,
                        "date_of_birth": form.date_of_birth.data,
                        "class": form.student_class.data,
                        "school": form.school.data,
                        "exam_category": form.exam_category.data,
                        "nina": form.nina.data or "",
                    },
                    form.guardian_name.data,
                    form.consent_given.data,
                    current_user.username,
                    app.config["ISSUER_ID"],
                    app.extensions["cids_aes_key"],
                    private_key,
                    photo_bytes,
                    Path(app.config["UPLOAD_DIR"]),
                    Path(app.config["CARD_DIR"]),
                    Path(app.config["QR_DIR"]),
                    configured_card_validity_days(),
                    form.consent_date.data,
                    student["candidate_id"],
                    student_id,
                )
            except (ValueError, OSError) as exc:
                flash(str(exc), "error")
                return render_template("admin/student_edit.html", form=form, student=student), 400
            new_student_id = replacement.payload["student_id"]
            flash("Carte remplacée. L’ancien QR code est désormais révoqué.", "success")
            return redirect(url_for("admin_student_detail", student_id=new_student_id))
        return render_template("admin/student_edit.html", form=form, student=student)
    
    @app.get("/admin/api/stats")
    @login_required
    @roles_required("director")
    def admin_api_stats():
        payload = database.dashboard_report()
        return json.dumps(payload, ensure_ascii=False), 200, {"Content-Type": "application/json; charset=utf-8"}

    @app.get("/admin/reports/categories.csv")
    @login_required
    @roles_required("director")
    def admin_category_report_export():
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["Examen", "Catégorie", "Candidats", "Cartes émises", "Actives", "Expirées", "Révoquées"])
        for category in database.examination_category_stats():
            writer.writerow([
                category["code"], category["name"], category["candidates"], category["cards_issued"],
                category["active_cards"], category["expired_cards"], category["revoked_cards"],
            ])
        writer.writerow([])
        writer.writerow(["Administrateur", "Cartes émises"])
        for admin_count in database.issuance_counts_by_admin():
            username = admin_count["username"]
            if username.lstrip().startswith(("=", "+", "-", "@")):
                username = "'" + username
            writer.writerow([username, admin_count["cards_issued"]])
        return Response(
            "\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=cids-rapport-examens.csv"},
        )

    @app.route("/director/settings", methods=["GET", "POST"])
    @login_required
    @roles_required("director")
    def director_settings():
        current_validity = configured_card_validity_days()
        form = DirectorSettingsForm(card_validity_days=current_validity)
        if form.validate_on_submit():
            database.set_setting("card_validity_days", str(form.card_validity_days.data))
            flash("Paramètres enregistrés.", "success")
            return redirect(url_for("director_settings"))
        settings = {
            "issuer_id": app.config["ISSUER_ID"],
            "card_validity_days": current_validity,
            "secure_cookies": bool(app.config["SESSION_COOKIE_SECURE"]),
            "database_ready": Path(app.config["DATABASE"]).is_file(),
            "aes_key_ready": (Path(app.config["KEY_DIR"]) / "aes_master.key").is_file(),
            "issuer_key_ready": (Path(app.config["KEY_DIR"]) / "issuer_private.pem").is_file(),
        }
        return render_template("director/settings.html", form=form, settings=settings)

    @app.route("/director/admins", methods=["GET", "POST"])
    @login_required
    @roles_required("director")
    def director_admins():
        form = CreateAdminForm()
        if request.method == "POST":
            action = request.form.get("action")
            if action == "create_admin":
                if not form.validate():
                    managed_users = [user for user in database.list_users() if user["role"] in {"admin", "secretary"}]
                    return render_template(
                        "director/admins.html", form=form, managed_users=managed_users
                    ), 400
                try:
                    database.create_user(form.username.data.strip(), form.password.data, form.role.data)
                    flash("Compte créé.", "success")
                except Exception:
                    flash("Impossible de créer ce compte. Vérifiez le nom et le rôle.", "error")
                return redirect(url_for("director_admins"))

            if action in {"enable_admin", "disable_admin", "delete_admin"}:
                user_id = request.form.get("user_id", type=int)
                if user_id is None:
                    flash("Compte administrateur invalide.", "error")
                elif action == "delete_admin":
                    changed = database.delete_admin(user_id)
                    flash("Compte supprimé." if changed else "Compte introuvable.", "success" if changed else "error")
                else:
                    changed = database.set_admin_active(user_id, action == "enable_admin")
                    flash("Accès utilisateur mis à jour." if changed else "Compte introuvable.", "success" if changed else "error")
                return redirect(url_for("director_admins"))

            flash("Action invalide ou formulaire incomplet.", "error")
            return redirect(url_for("director_admins"))

        managed_users = [user for user in database.list_users() if user["role"] in {"admin", "secretary"}]
        return render_template("director/admins.html", form=form, managed_users=managed_users)

    return app


def _revoked_ids(database: Database) -> set[str]:
    with database.connection() as connection:
        rows = connection.execute("SELECT student_id FROM revocations").fetchall()
    return {row["student_id"] for row in rows}
