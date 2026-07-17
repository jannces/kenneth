"""Authentication & user-management service.

This is the business-logic layer between the login/user GUI and the database.
It owns:

* Credential verification with bcrypt.
* Account lockout after N failed attempts (configurable).
* Login-history recording (success + failure).
* Full user CRUD for administrators (create / update / deactivate / delete /
  reset password / assign role).

Every method returns a small result object or raises a domain error; the GUI
translates these into friendly messages.  All SQL is parameterised.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, List, Optional

from authentication.password import hash_password, verify_password
from authentication.permissions import require, PermissionError
from authentication.session import Session
from config import CONFIG
from logs.activity_logger import ACTIVITY
from logs.logger import LOG
from utils.constants import Role, UserStatus
from utils.helpers import now
from utils.validators import (
    validate_email,
    validate_password,
    validate_username,
)


@dataclass
class AuthResult:
    """Outcome of a login attempt."""

    ok: bool
    message: str = ""
    session: Optional[Session] = None
    locked: bool = False


class AuthService:
    """Handles authentication and user administration."""

    def __init__(self, database: Any) -> None:
        self._db = database

    # ------------------------------------------------------------------ login
    def authenticate(self, username: str, password: str) -> AuthResult:
        """Verify credentials and, on success, build a :class:`Session`."""
        username = (username or "").strip()
        if not username:
            return AuthResult(False, "Username is required.")
        if not password:
            return AuthResult(False, "Password is required.")

        user = self._db.query_one(
            "SELECT * FROM users WHERE username = %s", (username,)
        )
        if not user:
            # Do not reveal whether the username exists.
            self._record_login(None, username, "failed:no-user")
            LOG.warning("auth", "login_failed", f"Unknown username '{username}'")
            return AuthResult(False, "Invalid username or password.")

        # Locked account handling.
        if user["status"] == UserStatus.LOCKED.value:
            if self._still_locked(user):
                self._record_login(user["id"], username, "blocked:locked")
                return AuthResult(
                    False,
                    "Account is locked due to repeated failed logins. "
                    "Contact an administrator.",
                    locked=True,
                )
            # Lock window elapsed -> auto-unlock.
            self._set_status(user["id"], UserStatus.ACTIVE.value)
            self._reset_failed(user["id"])
            user["status"] = UserStatus.ACTIVE.value
            user["failed_attempts"] = 0

        if user["status"] == UserStatus.INACTIVE.value:
            self._record_login(user["id"], username, "blocked:inactive")
            return AuthResult(False, "Account is inactive. Contact an administrator.")

        # Verify password.
        if not verify_password(password, user["password_hash"]):
            attempts = int(user.get("failed_attempts", 0)) + 1
            max_attempts = CONFIG.security.max_login_attempts
            if attempts >= max_attempts:
                self._lock_account(user["id"])
                self._record_login(user["id"], username, "failed:locked-now")
                LOG.warning("auth", "account_locked",
                            f"'{username}' locked after {attempts} failed attempts.")
                return AuthResult(
                    False,
                    f"Account locked after {attempts} failed attempts. "
                    "Contact an administrator.",
                    locked=True,
                )
            self._db.execute(
                "UPDATE users SET failed_attempts = %s WHERE id = %s",
                (attempts, user["id"]), commit=True,
            )
            self._record_login(user["id"], username, "failed:bad-password")
            LOG.warning("auth", "login_failed",
                        f"'{username}' bad password ({attempts}/{max_attempts})")
            remaining = max_attempts - attempts
            return AuthResult(
                False,
                f"Invalid username or password. {remaining} attempt(s) remaining.",
            )

        # Success.
        self._reset_failed(user["id"])
        self._db.execute(
            "UPDATE users SET last_login = %s WHERE id = %s",
            (now(), user["id"]), commit=True,
        )
        history_id = self._record_login(user["id"], username, "success")
        session = Session(
            user_id=user["id"],
            username=user["username"],
            fullname=user["fullname"],
            role=user["role"],
            login_history_id=history_id,
        )
        ACTIVITY.attach_database(self._db)
        ACTIVITY.login(username, ip=self._local_ip(), host=self._computer_name())
        LOG.info("auth", "login_success", f"'{username}' ({user['role']})", user=username)
        return AuthResult(True, "Login successful.", session=session)

    def logout(self, session: Optional[Session]) -> None:
        if session is None:
            return
        if session.login_history_id:
            self._db.execute(
                "UPDATE login_history SET logout_time = %s WHERE id = %s",
                (now(), session.login_history_id), commit=True,
            )
        ACTIVITY.logout(session.username)
        LOG.info("auth", "logout", f"'{session.username}'", user=session.username)

    # --------------------------------------------------------- lockout helpers
    def _still_locked(self, user: Dict[str, Any]) -> bool:
        locked_until = user.get("locked_until")
        if locked_until is None:
            return True
        return now() < locked_until

    def _lock_account(self, user_id: int) -> None:
        locked_until = now() + timedelta(minutes=CONFIG.security.lockout_minutes)
        self._db.execute(
            "UPDATE users SET status = %s, locked_until = %s WHERE id = %s",
            (UserStatus.LOCKED.value, locked_until, user_id), commit=True,
        )

    def _reset_failed(self, user_id: int) -> None:
        self._db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s",
            (user_id,), commit=True,
        )

    def _set_status(self, user_id: int, status: str) -> None:
        self._db.execute(
            "UPDATE users SET status = %s WHERE id = %s", (status, user_id), commit=True
        )

    # ------------------------------------------------------------ login history
    def _record_login(self, user_id: Optional[int], username: str, status: str) -> Optional[int]:
        try:
            return self._db.execute(
                """INSERT INTO login_history
                       (user_id, username, login_time, ip_address, computer_name, status)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                (user_id, username, now(), self._local_ip(),
                 self._computer_name(), status),
                commit=True,
            )
        except Exception as exc:  # noqa: BLE001
            LOG.error("auth", "login_history_failed", str(exc))
            return None

    @staticmethod
    def _local_ip() -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:  # noqa: BLE001
            return "127.0.0.1"

    @staticmethod
    def _computer_name() -> str:
        return socket.gethostname() or os.environ.get("COMPUTERNAME", "unknown")

    # ============================================================ USER MANAGEMENT
    def list_users(self, search: str = "") -> List[Dict[str, Any]]:
        if search:
            like = f"%{search}%"
            return self._db.query(
                """SELECT id, username, fullname, email, role, status,
                          created_at, last_login
                       FROM users
                       WHERE username LIKE %s OR fullname LIKE %s OR email LIKE %s
                       ORDER BY username""",
                (like, like, like),
            )
        return self._db.query(
            """SELECT id, username, fullname, email, role, status,
                      created_at, last_login
                   FROM users ORDER BY username"""
        )

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        return self._db.query_one(
            """SELECT id, username, fullname, email, role, status,
                      created_at, updated_at, last_login
                   FROM users WHERE id = %s""",
            (user_id,),
        )

    def create_user(self, actor: Session, username: str, password: str,
                    fullname: str, email: str, role: str) -> AuthResult:
        require(actor.role, "manage_users")

        uname = validate_username(username)
        if not uname:
            return AuthResult(False, uname.message)
        pwd = validate_password(password)
        if not pwd:
            return AuthResult(False, pwd.message)
        mail = validate_email(email)
        if not mail:
            return AuthResult(False, mail.message)
        if role not in (Role.ADMIN.value, Role.USER.value):
            return AuthResult(False, "Invalid role.")

        exists = self._db.query_one(
            "SELECT id FROM users WHERE username = %s", (uname.value,)
        )
        if exists:
            return AuthResult(False, "That username already exists.")

        self._db.execute(
            """INSERT INTO users (username, password_hash, fullname, email, role, status)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
            (uname.value, hash_password(pwd.value), fullname.strip(),
             mail.value, role, UserStatus.ACTIVE.value),
            commit=True,
        )
        ACTIVITY.user_created(actor.username, uname.value, role)
        LOG.info("auth", "user_created", f"{uname.value} ({role})", user=actor.username)
        return AuthResult(True, f"User '{uname.value}' created.")

    def update_user(self, actor: Session, user_id: int, fullname: str,
                    email: str, role: str, status: str) -> AuthResult:
        require(actor.role, "manage_users")
        mail = validate_email(email)
        if not mail:
            return AuthResult(False, mail.message)
        if role not in (Role.ADMIN.value, Role.USER.value):
            return AuthResult(False, "Invalid role.")
        if status not in {s.value for s in UserStatus}:
            return AuthResult(False, "Invalid status.")

        target = self.get_user(user_id)
        if not target:
            return AuthResult(False, "User not found.")

        # Guard: do not allow removing the last active administrator.
        if target["role"] == Role.ADMIN.value and role != Role.ADMIN.value:
            if self._active_admin_count() <= 1:
                return AuthResult(False, "Cannot demote the last administrator.")

        self._db.execute(
            """UPDATE users SET fullname = %s, email = %s, role = %s, status = %s
                   WHERE id = %s""",
            (fullname.strip(), mail.value, role, status, user_id), commit=True,
        )
        ACTIVITY.record(actor.username, "User Updated",
                        f"{target['username']} -> role={role}, status={status}")
        LOG.info("auth", "user_updated", target["username"], user=actor.username)
        return AuthResult(True, "User updated.")

    def deactivate_user(self, actor: Session, user_id: int) -> AuthResult:
        require(actor.role, "manage_users")
        target = self.get_user(user_id)
        if not target:
            return AuthResult(False, "User not found.")
        if target["role"] == Role.ADMIN.value and self._active_admin_count() <= 1:
            return AuthResult(False, "Cannot deactivate the last administrator.")
        self._set_status(user_id, UserStatus.INACTIVE.value)
        ACTIVITY.record(actor.username, "User Deactivated", target["username"])
        return AuthResult(True, f"User '{target['username']}' deactivated.")

    def unlock_user(self, actor: Session, user_id: int) -> AuthResult:
        require(actor.role, "manage_users")
        target = self.get_user(user_id)
        if not target:
            return AuthResult(False, "User not found.")
        self._set_status(user_id, UserStatus.ACTIVE.value)
        self._reset_failed(user_id)
        ACTIVITY.record(actor.username, "User Unlocked", target["username"])
        LOG.info("auth", "user_unlocked", target["username"], user=actor.username)
        return AuthResult(True, f"User '{target['username']}' unlocked.")

    def delete_user(self, actor: Session, user_id: int) -> AuthResult:
        require(actor.role, "manage_users")
        target = self.get_user(user_id)
        if not target:
            return AuthResult(False, "User not found.")
        if user_id == actor.user_id:
            return AuthResult(False, "You cannot delete your own account.")
        if target["role"] == Role.ADMIN.value and self._active_admin_count() <= 1:
            return AuthResult(False, "Cannot delete the last administrator.")
        self._db.execute("DELETE FROM users WHERE id = %s", (user_id,), commit=True)
        ACTIVITY.record(actor.username, "User Deleted", target["username"])
        LOG.warning("auth", "user_deleted", target["username"], user=actor.username)
        return AuthResult(True, f"User '{target['username']}' deleted.")

    def reset_password(self, actor: Session, user_id: int, new_password: str) -> AuthResult:
        require(actor.role, "manage_users")
        pwd = validate_password(new_password)
        if not pwd:
            return AuthResult(False, pwd.message)
        target = self.get_user(user_id)
        if not target:
            return AuthResult(False, "User not found.")
        self._db.execute(
            """UPDATE users SET password_hash = %s, failed_attempts = 0,
                   locked_until = NULL, status = %s WHERE id = %s""",
            (hash_password(pwd.value), UserStatus.ACTIVE.value, user_id), commit=True,
        )
        ACTIVITY.password_changed(actor.username, target["username"])
        LOG.info("auth", "password_reset", target["username"], user=actor.username)
        return AuthResult(True, f"Password reset for '{target['username']}'.")

    def change_own_password(self, session: Session, current: str, new_password: str) -> AuthResult:
        """Allow any authenticated user to change their own password."""
        user = self._db.query_one("SELECT * FROM users WHERE id = %s", (session.user_id,))
        if not user or not verify_password(current, user["password_hash"]):
            return AuthResult(False, "Current password is incorrect.")
        pwd = validate_password(new_password)
        if not pwd:
            return AuthResult(False, pwd.message)
        self._db.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (hash_password(pwd.value), session.user_id), commit=True,
        )
        ACTIVITY.password_changed(session.username, session.username)
        return AuthResult(True, "Password updated.")

    def user_login_history(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        return self._db.query(
            """SELECT login_time, logout_time, ip_address, computer_name, status
                   FROM login_history WHERE user_id = %s
                   ORDER BY login_time DESC LIMIT %s""",
            (user_id, limit),
        )

    def user_activity(self, username: str, limit: int = 50) -> List[Dict[str, Any]]:
        return self._db.query(
            """SELECT timestamp, activity, details FROM activity_logs
                   WHERE user = %s ORDER BY timestamp DESC LIMIT %s""",
            (username, limit),
        )

    def _active_admin_count(self) -> int:
        row = self._db.query_one(
            "SELECT COUNT(*) AS c FROM users WHERE role = %s AND status = %s",
            (Role.ADMIN.value, UserStatus.ACTIVE.value),
        )
        return int(row["c"]) if row else 0
