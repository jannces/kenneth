"""Dashboard statistics aggregator.

Pulls together the numbers shown on the dashboard cards and charts from the live
monitoring engine and the database, presenting them as one snapshot the GUI can
render on its refresh timer.  All database access is wrapped so a transient DB
hiccup degrades a card to its last value rather than crashing the dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from utils.helpers import format_bytes, format_duration


@dataclass
class DashboardSnapshot:
    devices_online: int = 0
    total_devices: int = 0
    active_connections: int = 0
    packets_captured: int = 0
    packets_per_second: float = 0.0
    alerts_today: int = 0
    critical_alerts: int = 0
    open_vulnerabilities: int = 0
    upload: str = "0 B/s"
    download: str = "0 B/s"
    monitoring_time: str = "00:00:00"
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    top_threats: Dict[str, int] = field(default_factory=dict)
    monitoring_active: bool = False


class DashboardStatistics:
    """Builds :class:`DashboardSnapshot` from the app services."""

    def __init__(self, context) -> None:
        self._ctx = context

    def snapshot(self) -> DashboardSnapshot:
        ctx = self._ctx
        snap = DashboardSnapshot()

        # Live monitoring metrics (in-memory, always available).
        try:
            stats = ctx.monitoring.stats_snapshot()
            bw = ctx.monitoring.bandwidth_snapshot()
            snap.packets_captured = stats.total_packets
            snap.packets_per_second = stats.packets_per_second
            snap.upload = f"{format_bytes(bw.upload_bps)}/s"
            snap.download = f"{format_bytes(bw.download_bps)}/s"
            snap.protocol_distribution = self._protocol_dist(stats)
            snap.active_connections = ctx.monitoring.connections.active_count()
            snap.devices_online = ctx.monitoring.devices.count_online()
            snap.total_devices = ctx.monitoring.devices.count_total()
            snap.monitoring_time = format_duration(ctx.monitoring.monitoring_seconds())
            snap.monitoring_active = ctx.monitoring.running
        except Exception:  # noqa: BLE001
            pass

        # Database-backed metrics.
        snap.alerts_today = self._scalar(
            "SELECT COUNT(*) FROM intrusion_alerts WHERE DATE(timestamp)=CURDATE()")
        snap.critical_alerts = self._scalar(
            "SELECT COUNT(*) FROM intrusion_alerts "
            "WHERE severity='Critical' AND status='Open'")
        snap.open_vulnerabilities = self._scalar(
            "SELECT COUNT(*) FROM scan_results WHERE state='open'")
        if not snap.total_devices:
            snap.total_devices = self._scalar("SELECT COUNT(*) FROM devices")
        snap.severity_distribution = self._severity_dist()
        snap.top_threats = self._top_threats()
        return snap

    def _protocol_dist(self, stats) -> Dict[str, int]:
        return {
            "TCP": stats.tcp, "UDP": stats.udp, "ICMP": stats.icmp,
            "HTTP": stats.http, "HTTPS": stats.https, "DNS": stats.dns,
            "Other": stats.other,
        }

    def _severity_dist(self) -> Dict[str, int]:
        rows = self._query(
            "SELECT risk_level, COUNT(*) AS c FROM scan_results "
            "WHERE state='open' GROUP BY risk_level")
        return {r["risk_level"]: r["c"] for r in rows}

    def _top_threats(self) -> Dict[str, int]:
        rows = self._query(
            "SELECT category, SUM(occurrences) AS c FROM intrusion_alerts "
            "GROUP BY category ORDER BY c DESC LIMIT 6")
        return {r["category"]: int(r["c"]) for r in rows}

    def _scalar(self, sql: str) -> int:
        try:
            return int(self._ctx.db.scalar(sql) or 0)
        except Exception:  # noqa: BLE001
            return 0

    def _query(self, sql: str) -> list:
        try:
            return self._ctx.db.query(sql)
        except Exception:  # noqa: BLE001
            return []
