"""User activity auditing.

Records *who did what* into the ``activity_logs`` table (append-only from the
GUI's perspective - the interface never exposes edit/delete of these rows,
satisfying the Integrity requirement of the CIA triad).
"""

from __future__ import annotations

from typing import Any, Optional

from logs.logger import LOG
from utils.helpers import now


class ActivityLogger:
    """Persist user actions for auditing and evaluation."""

    def __init__(self, database: Optional[Any] = None) -> None:
        self._db = database

    def attach_database(self, database: Any) -> None:
        self._db = database

    def record(self, user: str, activity: str, details: str = "") -> None:
        """Insert an activity row.  Failures are logged, never raised."""
        if self._db is None:
            LOG.info("activity", activity, details, user=user)
            return
        try:
            self._db.execute(
                """INSERT INTO activity_logs (timestamp, user, activity, details)
                       VALUES (%s, %s, %s, %s)""",
                (now(), user, activity, details),
                commit=True,
            )
        except Exception as exc:  # noqa: BLE001
            LOG.error("activity", "persist_failed", str(exc))

    # Common, well-known activities get named helpers for consistency.
    def login(self, user: str, ip: str = "", host: str = "") -> None:
        self.record(user, "Login", f"Signed in from {host or 'local'} ({ip or 'n/a'})")

    def logout(self, user: str) -> None:
        self.record(user, "Logout", "Session ended")

    def scan_started(self, user: str, target: str, scan_type: str) -> None:
        self.record(user, "Scan Started", f"{scan_type} scan of {target}")

    def scan_finished(self, user: str, target: str, hosts: int, ports: int) -> None:
        self.record(user, "Scan Finished", f"{target}: {hosts} host(s), {ports} open port(s)")

    def monitoring_started(self, user: str, interface: str) -> None:
        self.record(user, "Monitoring Started", f"Interface: {interface}")

    def monitoring_stopped(self, user: str) -> None:
        self.record(user, "Monitoring Stopped", "")

    def report_generated(self, user: str, report_type: str, filename: str) -> None:
        self.record(user, "Report Generated", f"{report_type} -> {filename}")

    def settings_changed(self, user: str, name: str, value: str) -> None:
        self.record(user, "Settings Changed", f"{name} = {value}")

    def user_created(self, actor: str, target_user: str, role: str) -> None:
        self.record(actor, "User Created", f"{target_user} ({role})")

    def password_changed(self, actor: str, target_user: str) -> None:
        self.record(actor, "Password Changed", f"For {target_user}")

    def mitigation_viewed(self, user: str, threat: str) -> None:
        self.record(user, "Mitigation Viewed", threat)


# Global singleton.
ACTIVITY = ActivityLogger()
