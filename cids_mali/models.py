"""SQLite persistence with parameterized statements and field-level encryption."""

from __future__ import annotations

import sqlite3
import hashlib
import os
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from cids_mali.crypto_utils import decrypt_json, encrypt_json
from cids_mali.exam_categories import EXAM_CATEGORIES


SENSITIVE_FIELDS = (
    "last_name",
    "first_name",
    "date_of_birth",
    "class",
    "school",
    "nina",
    "photo_hash",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS students (
    student_id TEXT PRIMARY KEY,
    candidate_id TEXT,
    last_name TEXT NOT NULL,
    first_name TEXT NOT NULL,
    date_of_birth TEXT NOT NULL,
    "class" TEXT NOT NULL,
    school TEXT NOT NULL,
    nina TEXT,
    photo_hash TEXT,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
    exam_category TEXT NOT NULL DEFAULT 'DEF' CHECK(exam_category IN ('DEF', 'BAC', 'CAP', 'BT1', 'BT2', 'IFM'))
);
CREATE TABLE IF NOT EXISTS consents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
    guardian_name_encrypted TEXT NOT NULL,
    consent_date TEXT NOT NULL,
    operator_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS issuance_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT,
    action TEXT NOT NULL CHECK(action IN ('ISSUE', 'REISSUE', 'REVOKE', 'ERASE', 'VERIFY')),
    timestamp TEXT NOT NULL,
    operator_hash TEXT NOT NULL,
    actor_username TEXT,
    result_status TEXT CHECK(result_status IN ('valid', 'invalid')),
    result_reason TEXT
);
CREATE TABLE IF NOT EXISTS revocations (
    student_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    revoked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('director', 'admin', 'secretary')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1))
);
CREATE TABLE IF NOT EXISTS trusted_issuers (
    issuer_id TEXT PRIMARY KEY,
    public_key_pem TEXT NOT NULL,
    added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
    username TEXT NOT NULL,
    attempted_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS login_attempts_user_time ON login_attempts(username, attempted_at);
CREATE INDEX IF NOT EXISTS issuance_log_student ON issuance_log(student_id);
"""

PASSWORD_HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)


class Database:
    def __init__(self, path: Path, aes_key: bytes):
        self.path = Path(path)
        self.aes_key = aes_key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        self.initialize()
        self.path.chmod(0o600)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connection() as connection:
            connection.executescript(SCHEMA)
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'"
            ).fetchone()["sql"]
            if "is_active" not in columns or "'director'" not in table_sql:
                connection.execute("ALTER TABLE users RENAME TO users_legacy")
                connection.execute(
                    """CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL CHECK(role IN ('director', 'admin', 'secretary')),
                        is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1))
                    )"""
                )
                connection.execute(
                    """INSERT INTO users (id, username, password_hash, role, is_active)
                       SELECT id, username, password_hash, role, 1 FROM users_legacy"""
                )
                connection.execute("DROP TABLE users_legacy")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS only_one_director ON users(role) WHERE role = 'director'"
            )
            student_columns = {row["name"] for row in connection.execute("PRAGMA table_info(students)")}
            if "candidate_id" not in student_columns:
                connection.execute("ALTER TABLE students ADD COLUMN candidate_id TEXT")
                connection.execute("UPDATE students SET candidate_id = student_id WHERE candidate_id IS NULL")
            connection.execute("CREATE INDEX IF NOT EXISTS students_candidate_id ON students(candidate_id)")
            if "exam_category" not in student_columns:
                connection.execute(
                    "ALTER TABLE students ADD COLUMN exam_category TEXT NOT NULL DEFAULT 'DEF' "
                    "CHECK(exam_category IN ('DEF', 'BAC', 'CAP', 'BT1', 'BT2', 'IFM'))"
                )
            log_columns = {row["name"] for row in connection.execute("PRAGMA table_info(issuance_log)")}
            if "actor_username" not in log_columns:
                connection.execute("ALTER TABLE issuance_log ADD COLUMN actor_username TEXT")
            if "result_status" not in log_columns:
                connection.execute("ALTER TABLE issuance_log ADD COLUMN result_status TEXT")
            if "result_reason" not in log_columns:
                connection.execute("ALTER TABLE issuance_log ADD COLUMN result_reason TEXT")

    def create_user(self, username: str, password: str, role: str) -> int:
        if role not in {"director", "admin", "secretary"}:
            raise ValueError("Invalid role")
        with self.connection() as connection:
            cursor = connection.execute(
                "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
                (username, PASSWORD_HASHER.hash(password), role),
            )
            return int(cursor.lastrowid)

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT setting_value FROM app_settings WHERE setting_key = ?", (key,)
            ).fetchone()
        return row["setting_value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO app_settings(setting_key, setting_value) VALUES (?, ?) "
                "ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value",
                (key, value),
            )

    def appoint_director(self, username: str) -> bool:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM users WHERE role = 'director'").fetchone():
                return False
            cursor = connection.execute(
                "UPDATE users SET role = 'director', is_active = 1 WHERE username = ? AND role = 'admin'",
                (username,),
            )
            return cursor.rowcount == 1

    def set_admin_active(self, user_id: int, is_active: bool) -> bool:
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE users SET is_active = ? WHERE id = ? AND role IN ('admin', 'secretary')",
                (int(is_active), user_id),
            )
            return cursor.rowcount == 1

    def delete_admin(self, user_id: int) -> bool:
        with self.connection() as connection:
            cursor = connection.execute(
                "DELETE FROM users WHERE id = ? AND role IN ('admin', 'secretary')", (user_id,)
            )
            return cursor.rowcount == 1

    def get_user(self, username: str) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT id, username, role, is_active FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT id, username, role, is_active FROM users ORDER BY username"
            ).fetchall()
        return [dict(row) for row in rows]

    def list_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT log_id, student_id, action, timestamp, operator_hash, actor_username FROM issuance_log ORDER BY log_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        user = self.get_user(username)
        if user and user["is_active"]:
            try:
                if PASSWORD_HASHER.verify(user["password_hash"], password):
                    return user
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                pass
        return None

    def record_login_attempt(self, username: str, attempted_at: float) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO login_attempts(username, attempted_at) VALUES (?, ?)",
                (username, attempted_at),
            )
            connection.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (attempted_at - 3600,))

    def count_login_attempts(self, username: str, since: float) -> int:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS attempts FROM login_attempts WHERE username = ? AND attempted_at >= ?",
                (username, since),
            ).fetchone()
        return int(row["attempts"])

    def _encrypt_field(self, value: str | None) -> str | None:
        if value is None:
            return None
        return encrypt_json({"value": value}, self.aes_key)

    def _decrypt_field(self, value: str | None) -> str | None:
        if value is None:
            return None
        return str(decrypt_json(value, self.aes_key)["value"])

    def issue_student(
        self,
        student: dict[str, str | None],
        guardian_name: str,
        consent_date: str,
        operator_hash: str,
        issued_at: str,
        expires_at: str,
        operator_username: str | None = None,
    ) -> None:
        student_id = student["student_id"]
        candidate_id = student.get("candidate_id", student_id)
        exam_category = student.get("exam_category", "DEF")
        if exam_category not in EXAM_CATEGORIES:
            raise ValueError("Invalid examination category")
        fields = {field: self._encrypt_field(student.get(field)) for field in SENSITIVE_FIELDS}
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            nina = student.get("nina")
            if nina:
                rows = connection.execute(
                    "SELECT nina FROM students WHERE nina IS NOT NULL"
                ).fetchall()
                if any(self._decrypt_field(row["nina"]) == nina for row in rows):
                    raise ValueError("A student with this NINA is already registered")
            connection.execute(
                     """INSERT INTO students(student_id, candidate_id, last_name, first_name, date_of_birth, "class",
                         school, nina, photo_hash, issued_at, expires_at, status, exam_category)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)""",
                (
                          student_id, candidate_id, fields["last_name"], fields["first_name"],
                    fields["date_of_birth"], fields["class"], fields["school"],
                    fields["nina"], fields["photo_hash"], issued_at, expires_at, exam_category,
                ),
            )
            connection.execute(
                "INSERT INTO consents(student_id, guardian_name_encrypted, consent_date, operator_hash) VALUES (?, ?, ?, ?)",
                (student_id, self._encrypt_field(guardian_name), consent_date, operator_hash),
            )
            self._add_log(
                connection, student_id, "ISSUE", operator_hash, issued_at, operator_username
            )

    def replace_student_card(
        self,
        student: dict[str, str | None],
        previous_card_id: str,
        guardian_name: str,
        consent_date: str,
        operator_hash: str,
        timestamp: str,
        expires_at: str,
        operator_username: str,
    ) -> bool:
        student_id = student["student_id"]
        candidate_id = student["candidate_id"]
        replaced_at = timestamp
        exam_category = student.get("exam_category", "DEF")
        if exam_category not in EXAM_CATEGORIES:
            raise ValueError("Invalid examination category")
        fields = {field: self._encrypt_field(student.get(field)) for field in SENSITIVE_FIELDS}
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            exists = connection.execute(
                "SELECT candidate_id FROM students WHERE student_id = ? AND status = 'active'",
                (previous_card_id,),
            ).fetchone()
            if not exists or exists["candidate_id"] != candidate_id:
                return False
            nina = student.get("nina")
            if nina:
                rows = connection.execute(
                    "SELECT candidate_id, nina FROM students WHERE nina IS NOT NULL AND candidate_id != ?",
                    (candidate_id,),
                ).fetchall()
                if any(self._decrypt_field(row["nina"]) == nina for row in rows):
                    raise ValueError("A student with this NINA is already registered")
            connection.execute(
                "UPDATE students SET status = 'revoked' WHERE student_id = ?", (previous_card_id,)
            )
            connection.execute(
                "INSERT OR REPLACE INTO revocations(student_id, reason, revoked_at) VALUES (?, ?, ?)",
                (previous_card_id, self._encrypt_field("Card replaced"), replaced_at),
            )
            connection.execute(
                """INSERT INTO students(student_id, candidate_id, last_name, first_name, date_of_birth,
                   "class", school, nina, photo_hash, issued_at, expires_at, status, exam_category)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)""",
                (
                    student_id, candidate_id, fields["last_name"], fields["first_name"],
                    fields["date_of_birth"], fields["class"], fields["school"], fields["nina"],
                    fields["photo_hash"], timestamp, expires_at, exam_category,
                ),
            )
            consent = connection.execute(
                "SELECT id FROM consents WHERE student_id = ? ORDER BY id DESC LIMIT 1", (candidate_id,)
            ).fetchone()
            connection.execute(
                "INSERT INTO consents(student_id, guardian_name_encrypted, consent_date, operator_hash) VALUES (?, ?, ?, ?)",
                (student_id, self._encrypt_field(guardian_name), consent_date, operator_hash),
            )
            self._add_log(connection, previous_card_id, "REVOKE", operator_hash, timestamp, operator_username)
            self._add_log(connection, student_id, "REISSUE", operator_hash, timestamp, operator_username)
        return True

    def get_student(self, student_id: str) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                """SELECT s.*, c.guardian_name_encrypted, c.consent_date
                   FROM students s LEFT JOIN consents c ON c.id = (
                       SELECT id FROM consents WHERE student_id = s.student_id ORDER BY id DESC LIMIT 1
                   ) WHERE s.student_id = ?""",
                (student_id,),
            ).fetchone()
        if not row:
            return None
        student = dict(row)
        guardian_encrypted = student.pop("guardian_name_encrypted", None)
        student["guardian_name"] = self._decrypt_field(guardian_encrypted) if guardian_encrypted else ""
        for field in SENSITIVE_FIELDS:
            student[field] = self._decrypt_field(student[field])
        return student

    def list_students(self) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                  '''SELECT s.student_id, s.candidate_id, s.last_name, s.first_name, s."class",
                         s.school, s.expires_at, s.status, s.exam_category
                   FROM students s
                   WHERE s.rowid = (
                       SELECT latest.rowid FROM students latest
                       WHERE latest.candidate_id = s.candidate_id
                       ORDER BY latest.issued_at DESC, latest.rowid DESC LIMIT 1
                   )
                   ORDER BY s.issued_at DESC'''
            ).fetchall()
        students = []
        for row in rows:
            student = dict(row)
            for field in ("last_name", "first_name", "class", "school"):
                student[field] = self._decrypt_field(student[field])
            students.append(student)
        students.sort(key=lambda student: (student["last_name"].casefold(), student["first_name"].casefold()))
        return students

    def list_candidate_card_ids(self, candidate_id: str) -> list[str]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT student_id FROM students WHERE candidate_id = ?", (candidate_id,)
            ).fetchall()
        return [row["student_id"] for row in rows]

    def examination_category_stats(self) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        stats = {
            code: {"code": code, "name": name, "candidates": 0, "cards_issued": 0,
                   "active_cards": 0, "expired_cards": 0, "revoked_cards": 0,
                   "verification_count": 0}
            for code, name in EXAM_CATEGORIES.items()
        }
        with self.connection() as connection:
            history = connection.execute(
                "SELECT exam_category, status FROM students"
            ).fetchall()
            current = connection.execute(
                '''SELECT s.exam_category, s.expires_at, s.status FROM students s
                   WHERE s.rowid = (
                       SELECT latest.rowid FROM students latest
                       WHERE latest.candidate_id = s.candidate_id
                       ORDER BY latest.issued_at DESC, latest.rowid DESC LIMIT 1
                   )'''
            ).fetchall()
            verification_counts = connection.execute(
                """SELECT s.exam_category, COUNT(*) AS count FROM issuance_log l
                   JOIN students s ON s.student_id = l.student_id
                   WHERE l.action = 'VERIFY' GROUP BY s.exam_category"""
            ).fetchall()
        for row in history:
            category = row["exam_category"] if row["exam_category"] in stats else "DEF"
            stats[category]["cards_issued"] += 1
            if row["status"] == "revoked":
                stats[category]["revoked_cards"] += 1
        for row in current:
            category = row["exam_category"] if row["exam_category"] in stats else "DEF"
            summary = stats[category]
            summary["candidates"] += 1
            if row["status"] == "revoked":
                continue
            try:
                expiry = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=UTC)
            except (AttributeError, ValueError):
                expiry = datetime.min.replace(tzinfo=UTC)
            if expiry >= now:
                summary["active_cards"] += 1
            else:
                summary["expired_cards"] += 1
        for row in verification_counts:
            category = row["exam_category"] if row["exam_category"] in stats else "DEF"
            stats[category]["verification_count"] += int(row["count"])
        return list(stats.values())

    def count_verifications_since(self, timestamp: str) -> int:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM issuance_log WHERE action = 'VERIFY' AND timestamp >= ?",
                (timestamp,),
            ).fetchone()
        return int(row["count"])

    def count_all_verifications(self) -> int:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM issuance_log WHERE action = 'VERIFY'"
            ).fetchone()
        return int(row["count"])

    def dashboard_report(self) -> dict[str, Any]:
        now = datetime.now(UTC)
        category_stats = self.examination_category_stats()
        students = self.list_students()
        issued_by_month = {}
        for offset in range(11, -1, -1):
            month_index = now.year * 12 + now.month - 1 - offset
            year, month_zero = divmod(month_index, 12)
            month = month_zero + 1
            issued_by_month[f"{year:04d}-{month:02d}"] = 0
        with self.connection() as connection:
            for row in connection.execute(
                """SELECT substr(timestamp, 1, 7) AS month, COUNT(*) AS count FROM issuance_log
                   WHERE action IN ('ISSUE', 'REISSUE') GROUP BY substr(timestamp, 1, 7)"""
            ):
                if row["month"] in issued_by_month:
                    issued_by_month[row["month"]] = int(row["count"])
            verification_rows = connection.execute(
                """SELECT substr(timestamp, 1, 10) AS day, result_status, COUNT(*) AS count
                   FROM issuance_log WHERE action = 'VERIFY' AND timestamp >= ?
                   GROUP BY substr(timestamp, 1, 10), result_status""",
                ((now - timedelta(days=6)).isoformat(),),
            ).fetchall()
            rejection_rows = connection.execute(
                """SELECT result_reason, COUNT(*) AS count FROM issuance_log
                   WHERE action = 'VERIFY' AND result_status = 'invalid' AND result_reason IS NOT NULL
                   GROUP BY result_reason ORDER BY count DESC"""
            ).fetchall()
            pending_consent = connection.execute(
                """SELECT COUNT(*) AS count FROM students s LEFT JOIN consents c
                   ON c.student_id = s.student_id WHERE c.id IS NULL"""
            ).fetchone()["count"]
        day_counts = {}
        for offset in range(6, -1, -1):
            day = (now.date() - timedelta(days=offset)).isoformat()
            day_counts[day] = {"valid": 0, "invalid": 0}
        for row in verification_rows:
            if row["day"] in day_counts and row["result_status"] in {"valid", "invalid"}:
                day_counts[row["day"]][row["result_status"]] = int(row["count"])
        class_counts: dict[str, int] = {}
        for student in students:
            class_counts[student["class"]] = class_counts.get(student["class"], 0) + 1
        total_issued = sum(item["cards_issued"] for item in category_stats)
        active_cards = sum(item["active_cards"] for item in category_stats)
        expired_cards = sum(item["expired_cards"] for item in category_stats)
        revoked_cards = sum(item["revoked_cards"] for item in category_stats)
        verification_today = self.count_verifications_since(now.date().isoformat())
        activity_labels = {
            "ISSUE": "Carte émise",
            "REISSUE": "Carte réémise",
            "REVOKE": "Carte révoquée",
            "ERASE": "Données candidat effacées",
            "VERIFY": "Carte vérifiée",
        }
        recent_activity = [
            {
                "type": "verify" if event["action"] == "VERIFY" else "revoke" if event["action"] == "REVOKE" else "issue",
                "title": activity_labels.get(event["action"], "Activité"),
                "time": event["timestamp"],
                "operator": event["actor_username"] or event["operator_hash"][:8],
            }
            for event in self.list_audit_events(6)
        ]
        expiring_soon = self.count_expiring_cards(now, 30)
        alerts = []
        if expiring_soon:
            alerts.append({"level": "warning", "message": f"{expiring_soon} cartes expirent dans 30 jours."})
        if pending_consent:
            alerts.append({"level": "info", "message": f"{pending_consent} consentements sont en attente."})
        if not alerts:
            alerts.append({"level": "info", "message": "Aucune alerte active."})
        month_names = ["Jan", "Fév", "Mar", "Avr", "Mai", "Juin", "Juil", "Aoû", "Sep", "Oct", "Nov", "Déc"]
        month_labels = [month_names[int(key[5:7]) - 1] for key in issued_by_month]
        return {
            "kpis": {
                "total_candidates": len(students),
                "total_issued": total_issued,
                "active_cards": active_cards,
                "expiring_soon": expiring_soon,
                "expired": expired_cards,
                "revoked": revoked_cards,
                "pending_consent": int(pending_consent),
                "verifications_today": verification_today,
                "total_verifications": self.count_all_verifications(),
                "registered_institutions": len({student["school"] for student in students if student["school"]}),
            },
            "coverage_rate": round(active_cards * 100 / total_issued) if total_issued else 0,
            "exam_categories": category_stats,
            "issued_by_admin": self.issuance_counts_by_admin(),
            "issued_per_month": {
                "labels": month_labels,
                "datasets": [{"label": "Cartes émises", "data": list(issued_by_month.values()),
                              "borderColor": "#2F8F5B", "backgroundColor": "rgba(47, 143, 91, 0.16)",
                              "fill": True, "tension": 0.35}],
            },
            "status_breakdown": {
                "labels": ["Valide", "Expire bientôt", "Expirée", "Révoquée"],
                "datasets": [{"data": [max(0, active_cards - expiring_soon), expiring_soon, expired_cards, revoked_cards],
                              "backgroundColor": ["#2F8F5B", "#D4AF37", "#94A3B8", "#C84B31"]}],
            },
            "by_class": {
                "labels": list(class_counts),
                "datasets": [{"label": "Cartes", "data": list(class_counts.values()), "backgroundColor": "#4CAF7A"}],
            },
            "verifications_per_day": {
                "labels": [key[5:] for key in day_counts],
                "datasets": [
                    {"label": "Validées", "data": [value["valid"] for value in day_counts.values()], "backgroundColor": "#2F8F5B"},
                    {"label": "Rejetées", "data": [value["invalid"] for value in day_counts.values()], "backgroundColor": "#C84B31"},
                ],
            },
            "rejection_reasons": {
                "labels": [row["result_reason"] for row in rejection_rows],
                "datasets": [{"label": "Nombre", "data": [int(row["count"]) for row in rejection_rows],
                              "backgroundColor": ["#C8553D", "#F4A261", "#6C757D", "#5B8DB8", "#4C8C6A"]}],
            },
            "recent_activity": recent_activity,
            "alerts": alerts,
        }

    def count_expiring_cards(self, now: datetime, within_days: int) -> int:
        limit = (now + __import__("datetime").timedelta(days=within_days)).isoformat()
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT expires_at FROM students WHERE status = 'active'"
            ).fetchall()
        return sum(
            1 for row in rows
            if now.isoformat() <= row["expires_at"].replace("Z", "+00:00") <= limit
        )

    def issuance_counts_by_admin(self) -> list[dict[str, Any]]:
        admins = [user for user in self.list_users() if user["role"] == "admin"]
        by_username = {user["username"]: 0 for user in admins}
        known_hashes = {
            hashlib.sha256(username.encode("utf-8")).hexdigest(): username
            for username in by_username
        }
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT actor_username, operator_hash, COUNT(*) AS cards_issued
                   FROM issuance_log WHERE action IN ('ISSUE', 'REISSUE')
                   GROUP BY actor_username, operator_hash"""
            ).fetchall()
        for row in rows:
            username = row["actor_username"] or known_hashes.get(row["operator_hash"])
            if username:
                by_username[username] = by_username.get(username, 0) + int(row["cards_issued"])
        return [{"username": username, "cards_issued": count} for username, count in sorted(by_username.items())]

    def add_trusted_issuer(self, issuer_id: str, public_key_pem: str) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO trusted_issuers(issuer_id, public_key_pem, added_at) VALUES (?, ?, ?)",
                (issuer_id, public_key_pem, datetime.now(UTC).isoformat()),
            )

    def get_trusted_issuers(self) -> dict[str, str]:
        with self.connection() as connection:
            rows = connection.execute("SELECT issuer_id, public_key_pem FROM trusted_issuers").fetchall()
        return {row["issuer_id"]: row["public_key_pem"] for row in rows}

    def revoke(self, student_id: str, reason: str, operator_hash: str) -> bool:
        timestamp = datetime.now(UTC).isoformat()
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE students SET status = 'revoked' WHERE student_id = ?", (student_id,)
            )
            if cursor.rowcount == 0:
                return False
            connection.execute(
                "INSERT OR REPLACE INTO revocations(student_id, reason, revoked_at) VALUES (?, ?, ?)",
                (student_id, self._encrypt_field(reason), timestamp),
            )
            self._add_log(connection, student_id, "REVOKE", operator_hash, timestamp)
        return True

    def is_revoked(self, student_id: str) -> bool:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM revocations WHERE student_id = ?", (student_id,)
            ).fetchone()
        return row is not None

    def erase_student(self, student_id: str, operator_hash: str) -> bool:
        timestamp = datetime.now(UTC).isoformat()
        anonymized_hash = hashlib.sha256(os.urandom(32)).hexdigest()
        with self.connection() as connection:
            selected = connection.execute(
                "SELECT candidate_id FROM students WHERE student_id = ?", (student_id,)
            ).fetchone()
            if not selected:
                return False
            card_ids = [
                row["student_id"] for row in connection.execute(
                    "SELECT student_id FROM students WHERE candidate_id = ?",
                    (selected["candidate_id"],),
                ).fetchall()
            ]
            placeholders = ",".join("?" for _ in card_ids)
            connection.execute(f"DELETE FROM students WHERE student_id IN ({placeholders})", card_ids)
            connection.execute(f"DELETE FROM revocations WHERE student_id IN ({placeholders})", card_ids)
            connection.execute(
                f"UPDATE issuance_log SET student_id = NULL, operator_hash = ? WHERE student_id IN ({placeholders})",
                (anonymized_hash, *card_ids),
            )
            self._add_log(connection, None, "ERASE", operator_hash, timestamp)
        return True

    def record_verification(
        self, student_id: str | None, operator_hash: str, valid: bool | None = None,
        reason: str | None = None,
    ) -> None:
        with self.connection() as connection:
            self._add_log(
                connection,
                student_id,
                "VERIFY",
                operator_hash,
                datetime.now(UTC).isoformat(),
                result_status="valid" if valid else "invalid" if valid is False else None,
                result_reason=reason,
            )

    @staticmethod
    def _add_log(
        connection: sqlite3.Connection,
        student_id: str | None,
        action: str,
        operator_hash: str,
        timestamp: str,
        actor_username: str | None = None,
        result_status: str | None = None,
        result_reason: str | None = None,
    ) -> None:
        connection.execute(
            """INSERT INTO issuance_log
               (student_id, action, timestamp, operator_hash, actor_username, result_status, result_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (student_id, action, timestamp, operator_hash, actor_username, result_status, result_reason),
        )