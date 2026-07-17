"""Mitigation recommendation engine.

Given a threat category (or a stored alert), returns the matching structured
recommendation from the knowledge base, enriched with correlated context
(related vulnerabilities and affected devices).  The engine is advisory only -
it never blocks traffic or changes firewall rules, matching the manuscript's
educational scope.

Viewing a recommendation is audited (LOG + activity log) so the evaluation can
measure how often mitigation guidance is consulted.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from logs.activity_logger import ACTIVITY
from mitigation.recommendation_db import RecommendationDB
from utils.constants import ThreatCategory


class MitigationEngine:
    """Resolves threats to actionable, educational recommendations."""

    def __init__(self, database: Any) -> None:
        self._db = database
        self.repo = RecommendationDB(database)

    # ----------------------------------------------------------- lookup
    def recommend_for_category(self, category: str,
                               viewer: str = "") -> Optional[Dict[str, Any]]:
        rec = self.repo.get_by_type(category)
        if rec is None:
            rec = self.repo.get_by_type(ThreatCategory.UNKNOWN_THREAT.value)
        if rec and viewer:
            ACTIVITY.mitigation_viewed(viewer, category)
        return rec

    def recommend_for_alert(self, alert: Dict[str, Any],
                            viewer: str = "") -> Dict[str, Any]:
        """Return a full recommendation package for a stored alert."""
        category = alert.get("category", ThreatCategory.UNKNOWN_THREAT.value)
        rec = self.recommend_for_category(category, viewer) or {}
        related = self.related_vulnerabilities(alert.get("destination_ip", ""), category)
        devices = self.affected_devices(alert)
        return {
            "recommendation": rec,
            "related_vulnerabilities": related,
            "affected_devices": devices,
            "educational": rec.get("educational", ""),
        }

    # ----------------------------------------------------------- correlation
    def related_vulnerabilities(self, target_ip: str, category: str) -> List[Dict[str, Any]]:
        if not target_ip:
            return []
        try:
            rows = self._db.query(
                """SELECT service, port, version, risk_level FROM scan_results
                       WHERE host = %s AND state = 'open' ORDER BY port""",
                (target_ip,),
            )
        except Exception:  # noqa: BLE001
            return []
        hint = self._service_hint(category)
        result = []
        for row in rows:
            svc = (row.get("service") or "").lower()
            if not hint or hint in svc:
                result.append(row)
        return result or rows  # show all open services if none specifically match

    def affected_devices(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        ips = [ip for ip in (alert.get("source_ip"), alert.get("destination_ip")) if ip]
        if not ips:
            return []
        placeholders = ",".join(["%s"] * len(ips))
        try:
            return self._db.query(
                f"""SELECT ip_address, hostname, mac_address, operating_system,
                        risk_level, open_ports, status FROM devices
                        WHERE ip_address IN ({placeholders})""",
                ips,
            )
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _service_hint(category: str) -> str:
        return {
            ThreatCategory.SSH_ATTACK.value: "ssh",
            ThreatCategory.FTP_ATTACK.value: "ftp",
            ThreatCategory.HTTP_ATTACK.value: "http",
            ThreatCategory.WEB_ATTACK.value: "http",
            ThreatCategory.DNS_ATTACK.value: "dns",
        }.get(category, "")

    # ----------------------------------------------------------- browse
    def list_recommendations(self) -> List[Dict[str, Any]]:
        return self.repo.list_all()

    def get(self, alert_type: str, viewer: str = "") -> Optional[Dict[str, Any]]:
        return self.recommend_for_category(alert_type, viewer)
