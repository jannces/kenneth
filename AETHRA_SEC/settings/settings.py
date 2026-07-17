"""Runtime settings service backed by the ``settings`` table.

Non-sensitive, user-tunable settings live in MySQL so they persist across
sessions and can be edited from the Settings page (admin only).  Sensitive
credentials (DB password, etc.) remain in the protected ``.env`` file and are
never written here.  On load these values are merged into the in-memory
:data:`config.CONFIG` object via :meth:`AppConfig.apply_overrides`.
"""

from __future__ import annotations

from typing import Any, Dict

from config import CONFIG
from logs.activity_logger import ACTIVITY
from logs.logger import LOG


class SettingsService:
    """Read/write application settings persisted in MySQL."""

    def __init__(self, database: Any) -> None:
        self._db = database

    def load_all(self) -> Dict[str, str]:
        rows = self._db.query("SELECT setting_name, setting_value FROM settings")
        return {r["setting_name"]: r["setting_value"] for r in rows}

    def get(self, name: str, default: str = "") -> str:
        row = self._db.query_one(
            "SELECT setting_value FROM settings WHERE setting_name = %s", (name,)
        )
        return row["setting_value"] if row and row["setting_value"] is not None else default

    def set(self, name: str, value: Any, actor: str = "system") -> None:
        value_str = str(value)
        existing = self._db.query_one(
            "SELECT id FROM settings WHERE setting_name = %s", (name,)
        )
        if existing:
            self._db.execute(
                "UPDATE settings SET setting_value = %s WHERE setting_name = %s",
                (value_str, name), commit=True,
            )
        else:
            self._db.execute(
                "INSERT INTO settings (setting_name, setting_value) VALUES (%s, %s)",
                (name, value_str), commit=True,
            )
        ACTIVITY.settings_changed(actor, name, value_str)
        LOG.info("settings", "changed", f"{name}={value_str}", user=actor)

    def set_many(self, values: Dict[str, Any], actor: str = "system") -> None:
        for name, value in values.items():
            self.set(name, value, actor)

    def apply_to_config(self) -> None:
        """Merge persisted settings into the live CONFIG singleton."""
        try:
            CONFIG.apply_overrides(self.load_all())
        except Exception as exc:  # noqa: BLE001
            LOG.error("settings", "apply_failed", str(exc))
