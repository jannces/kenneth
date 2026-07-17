"""In-memory session management.

A :class:`Session` captures the authenticated user, role, login time, and
permissions.  Sessions live only in memory and are destroyed on logout,
satisfying the confidentiality requirement (no persistent client-side token).
An idle-timeout check supports the security policy's automatic-logout feature.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from authentication.permissions import has_permission, permitted_pages
from config import CONFIG
from utils.helpers import now


@dataclass
class Session:
    """Represents one authenticated user session."""

    user_id: int
    username: str
    fullname: str
    role: str
    login_time: datetime = field(default_factory=now)
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    login_history_id: Optional[int] = None
    last_activity: datetime = field(default_factory=now)

    # -- permission helpers --------------------------------------------------
    def can(self, permission: str) -> bool:
        return has_permission(self.role, permission)

    def pages(self) -> dict:
        return permitted_pages(self.role)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    # -- idle timeout --------------------------------------------------------
    def touch(self) -> None:
        """Record user activity to reset the idle timer."""
        self.last_activity = now()

    def is_expired(self) -> bool:
        """Return True if the session has been idle past the configured timeout."""
        if not CONFIG.security.auto_logout:
            return False
        timeout = timedelta(minutes=CONFIG.security.session_timeout_minutes)
        return now() - self.last_activity > timeout

    def duration_seconds(self) -> float:
        return (now() - self.login_time).total_seconds()


class SessionManager:
    """Holds the single active session for the desktop application."""

    def __init__(self) -> None:
        self._current: Optional[Session] = None

    @property
    def current(self) -> Optional[Session]:
        return self._current

    def start(self, session: Session) -> None:
        self._current = session

    def end(self) -> None:
        self._current = None

    @property
    def is_authenticated(self) -> bool:
        return self._current is not None


# Global session manager singleton.
SESSION = SessionManager()
