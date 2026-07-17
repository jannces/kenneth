"""Database access for the mitigation knowledge base.

Wraps CRUD against ``mitigation_recommendations``.  Editing is administrator-only
(enforced by the calling layer through RBAC); standard users get read access so
they can browse the educational content in the Mitigation Center.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from logs.logger import LOG
from utils.helpers import now


# Columns an administrator may edit through the GUI.
EDITABLE_COLUMNS = [
    "severity", "recommendation_title", "explanation", "educational", "problem",
    "why_it_happened", "risk", "how_to_verify", "immediate_actions",
    "long_term_prevention", "recommendation", "reference", "difficulty",
    "admin_notes",
]


class RecommendationDB:
    """CRUD facade over the mitigation knowledge base."""

    def __init__(self, database: Any) -> None:
        self._db = database

    def list_all(self) -> List[Dict[str, Any]]:
        return self._db.query(
            "SELECT * FROM mitigation_recommendations ORDER BY alert_type"
        )

    def get_by_type(self, alert_type: str) -> Optional[Dict[str, Any]]:
        return self._db.query_one(
            "SELECT * FROM mitigation_recommendations WHERE alert_type = %s",
            (alert_type,),
        )

    def get_by_id(self, rec_id: int) -> Optional[Dict[str, Any]]:
        return self._db.query_one(
            "SELECT * FROM mitigation_recommendations WHERE id = %s", (rec_id,)
        )

    def update(self, rec_id: int, fields: Dict[str, Any], actor: str = "") -> bool:
        """Update editable columns of a recommendation (admin only)."""
        updates = {k: v for k, v in fields.items() if k in EDITABLE_COLUMNS}
        if not updates:
            return False
        set_clause = ", ".join(f"{col} = %s" for col in updates)
        params = list(updates.values()) + [rec_id]
        try:
            self._db.execute(
                f"UPDATE mitigation_recommendations SET {set_clause} WHERE id = %s",
                params, commit=True,
            )
            LOG.info("mitigation", "recommendation_updated",
                     f"id={rec_id} fields={list(updates)}", user=actor or "system")
            return True
        except Exception as exc:  # noqa: BLE001
            LOG.exception("mitigation", "update_failed", exc)
            return False

    def create(self, alert_type: str, fields: Dict[str, Any], actor: str = "") -> bool:
        existing = self.get_by_type(alert_type)
        if existing:
            return self.update(existing["id"], fields, actor)
        columns = ["alert_type"] + [c for c in EDITABLE_COLUMNS if c in fields]
        values = [alert_type] + [fields[c] for c in columns[1:]]
        placeholders = ", ".join(["%s"] * len(columns))
        try:
            self._db.execute(
                f"INSERT INTO mitigation_recommendations ({', '.join(columns)}) "
                f"VALUES ({placeholders})",
                values, commit=True,
            )
            LOG.info("mitigation", "recommendation_created", alert_type, user=actor)
            return True
        except Exception as exc:  # noqa: BLE001
            LOG.exception("mitigation", "create_failed", exc)
            return False
