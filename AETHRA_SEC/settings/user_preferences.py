"""Per-user preferences (theme, auto-scroll, etc.).

Preferences are namespaced by username in the ``settings`` table using the
``pref:<user>:<key>`` convention so they never collide with global settings.
"""

from __future__ import annotations

from typing import Any

from settings.settings import SettingsService


class UserPreferences:
    """Lightweight per-user preference store."""

    def __init__(self, settings: SettingsService, username: str) -> None:
        self._settings = settings
        self._username = username

    def _key(self, key: str) -> str:
        return f"pref:{self._username}:{key}"

    def get(self, key: str, default: str = "") -> str:
        return self._settings.get(self._key(key), default)

    def set(self, key: str, value: Any) -> None:
        self._settings.set(self._key(key), value, actor=self._username)
