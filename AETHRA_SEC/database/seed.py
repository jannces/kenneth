"""Seed default data into a fresh AETHRA-SEC database.

Idempotent: every insert checks for existing rows first, so running the seed
repeatedly is safe.  Seeds:

* A default administrator account (``admin`` / ``Admin@123``) - the credentials
  are logged with a prompt to change them on first login.
* A default standard user (``analyst`` / ``Analyst@123``) for demonstrations.
* The mitigation knowledge base.
* Baseline application settings.
"""

from __future__ import annotations

from typing import Any

from authentication.password import hash_password, is_available as bcrypt_available
from logs.logger import LOG
from mitigation.recommendation_data import get_default_recommendations
from utils.constants import Role, UserStatus

DEFAULT_ADMIN = {
    "username": "admin",
    "password": "Admin@123",
    "fullname": "System Administrator",
    "email": "admin@aethra.local",
    "role": Role.ADMIN.value,
}

DEFAULT_USER = {
    "username": "analyst",
    "password": "Analyst@123",
    "fullname": "Security Analyst",
    "email": "analyst@aethra.local",
    "role": Role.USER.value,
}

DEFAULT_SETTINGS = {
    "theme": "darkly",
    "refresh_interval_ms": "1000",
    "auto_start_monitoring": "true",
    "capture_interface": "",
    "connection_timeout": "120",
    "default_scan_type": "quick",
    "scan_timeout": "600",
    "session_timeout_minutes": "30",
    "max_login_attempts": "5",
    "report_default_format": "pdf",
    "organization_name": "Educational Cybersecurity Laboratory",
    "laboratory_name": "Cybersecurity Laboratory",
    "app_name": "AETHRA-SEC",
}


def _seed_user(db: Any, spec: dict) -> None:
    existing = db.query_one("SELECT id FROM users WHERE username = %s", (spec["username"],))
    if existing:
        return
    if not bcrypt_available():
        LOG.error("seed", "bcrypt_missing",
                  f"Cannot create default user '{spec['username']}' without bcrypt.")
        return
    password_hash = hash_password(spec["password"])
    db.execute(
        """INSERT INTO users (username, password_hash, fullname, email, role, status)
               VALUES (%s, %s, %s, %s, %s, %s)""",
        (spec["username"], password_hash, spec["fullname"], spec["email"],
         spec["role"], UserStatus.ACTIVE.value),
        commit=True,
    )
    LOG.info("seed", "user_created",
             f"Default {spec['role']} '{spec['username']}' created "
             f"(password '{spec['password']}' - change on first login).")


def _seed_settings(db: Any) -> None:
    for name, value in DEFAULT_SETTINGS.items():
        exists = db.query_one("SELECT id FROM settings WHERE setting_name = %s", (name,))
        if exists:
            continue
        db.execute(
            "INSERT INTO settings (setting_name, setting_value) VALUES (%s, %s)",
            (name, value),
            commit=True,
        )


def _seed_mitigations(db: Any) -> None:
    columns = [
        "alert_type", "severity", "recommendation_title", "explanation",
        "educational", "problem", "why_it_happened", "risk", "how_to_verify",
        "immediate_actions", "long_term_prevention", "recommendation",
        "reference", "difficulty",
    ]
    placeholder = ", ".join(["%s"] * len(columns))
    insert_sql = (
        f"INSERT INTO mitigation_recommendations ({', '.join(columns)}) "
        f"VALUES ({placeholder})"
    )
    for rec in get_default_recommendations():
        exists = db.query_one(
            "SELECT id FROM mitigation_recommendations WHERE alert_type = %s",
            (rec["alert_type"],),
        )
        if exists:
            continue
        values = [rec.get(col, "") for col in columns]
        db.execute(insert_sql, values, commit=True)


def seed_defaults(db: Any) -> None:
    """Populate baseline data.  Safe to call on every startup."""
    try:
        _seed_user(db, DEFAULT_ADMIN)
        _seed_user(db, DEFAULT_USER)
        _seed_settings(db)
        _seed_mitigations(db)
        LOG.info("seed", "complete", "Default data verified/seeded.")
    except Exception as exc:  # noqa: BLE001
        LOG.exception("seed", "seed_failed", exc)
