"""Report data aggregation and orchestration.

Gathers the data required for each report type from the database, then dispatches
to the requested exporter (PDF / CSV / Excel).  Report metadata is recorded in
the ``reports`` table and the activity log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from authentication.session import Session
from config import CONFIG
from logs.activity_logger import ACTIVITY
from logs.logger import LOG
from utils.helpers import now, days_ago


REPORT_TYPES = [
    "Daily Summary", "Weekly Summary", "Monthly Summary", "Custom Date Range",
    "Vulnerability Report", "Alert Report", "Traffic Report", "Device Report",
    "Incident Report", "System Activity Report",
]


@dataclass
class ReportData:
    """Structured content gathered for a report."""

    title: str
    report_type: str
    generated_by: str
    generated_at: datetime = field(default_factory=now)
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    summary: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    devices: List[Dict[str, Any]] = field(default_factory=list)
    threat_distribution: Dict[str, int] = field(default_factory=dict)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    top_devices: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    activity: List[Dict[str, Any]] = field(default_factory=list)
    conclusion: str = ""


class ReportGenerator:
    """Builds :class:`ReportData` and exports it to a file."""

    def __init__(self, database: Any) -> None:
        self._db = database

    # -------------------------------------------------------------- gather
    def build(self, report_type: str, session: Session,
              start: Optional[datetime] = None,
              end: Optional[datetime] = None) -> ReportData:
        end = end or now()
        if report_type == "Daily Summary":
            start = start or (now() - timedelta(days=1))
        elif report_type == "Weekly Summary":
            start = start or days_ago(7)
        elif report_type == "Monthly Summary":
            start = start or days_ago(30)
        elif start is None:
            start = days_ago(30)

        data = ReportData(
            title=f"AETHRA-SEC {report_type}",
            report_type=report_type,
            generated_by=session.fullname or session.username,
            period_start=start,
            period_end=end,
        )
        data.summary = self._summary(start, end)
        data.vulnerabilities = self._vulnerabilities(start, end)
        data.alerts = self._alerts(start, end)
        data.devices = self._devices()
        data.threat_distribution = self._threat_distribution(start, end)
        data.severity_distribution = self._severity_distribution(start, end)
        data.top_devices = self._top_devices()
        data.recommendations = self._recommendations()
        data.activity = self._activity(start, end)
        data.conclusion = self._conclusion(data)
        return data

    def _summary(self, start: datetime, end: datetime) -> Dict[str, Any]:
        def count(sql: str, params=()) -> int:
            return self._db.scalar(sql, params) or 0

        return {
            "total_scans": count(
                "SELECT COUNT(*) FROM vulnerability_scans WHERE started_at BETWEEN %s AND %s",
                (start, end)),
            "open_vulnerabilities": count(
                "SELECT COUNT(*) FROM scan_results WHERE state='open'"),
            "total_alerts": count(
                "SELECT COUNT(*) FROM intrusion_alerts WHERE timestamp BETWEEN %s AND %s",
                (start, end)),
            "critical_alerts": count(
                "SELECT COUNT(*) FROM intrusion_alerts WHERE severity='Critical' "
                "AND timestamp BETWEEN %s AND %s", (start, end)),
            "devices_seen": count("SELECT COUNT(*) FROM devices"),
            "false_positives": count(
                "SELECT COUNT(*) FROM intrusion_alerts WHERE status='False Positive'"),
            "packets_captured": count(
                "SELECT COUNT(*) FROM live_packets WHERE timestamp BETWEEN %s AND %s",
                (start, end)),
        }

    def _vulnerabilities(self, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        return self._db.query(
            """SELECT sr.host, sr.hostname, sr.port, sr.protocol, sr.service,
                      sr.version, sr.state, sr.risk_level
                   FROM scan_results sr
                   JOIN vulnerability_scans vs ON vs.id = sr.scan_id
                   WHERE vs.started_at BETWEEN %s AND %s AND sr.state='open'
                   ORDER BY FIELD(sr.risk_level,'Critical','High','Medium','Low','Informational')
                   LIMIT 200""",
            (start, end),
        )

    def _alerts(self, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        return self._db.query(
            """SELECT timestamp, category, severity, source_ip, destination_ip,
                      protocol, occurrences, status
                   FROM intrusion_alerts WHERE timestamp BETWEEN %s AND %s
                   ORDER BY timestamp DESC LIMIT 200""",
            (start, end),
        )

    def _devices(self) -> List[Dict[str, Any]]:
        return self._db.query(
            """SELECT ip_address, hostname, mac_address, operating_system,
                      risk_level, status, packets_sent, packets_received
                   FROM devices ORDER BY last_seen DESC LIMIT 100"""
        )

    def _threat_distribution(self, start: datetime, end: datetime) -> Dict[str, int]:
        rows = self._db.query(
            """SELECT category, COUNT(*) AS c FROM intrusion_alerts
                   WHERE timestamp BETWEEN %s AND %s GROUP BY category ORDER BY c DESC""",
            (start, end),
        )
        return {r["category"]: r["c"] for r in rows}

    def _severity_distribution(self, start: datetime, end: datetime) -> Dict[str, int]:
        rows = self._db.query(
            """SELECT severity, COUNT(*) AS c FROM intrusion_alerts
                   WHERE timestamp BETWEEN %s AND %s GROUP BY severity""",
            (start, end),
        )
        return {r["severity"]: r["c"] for r in rows}

    def _top_devices(self) -> List[Dict[str, Any]]:
        return self._db.query(
            """SELECT ip_address, hostname, risk_level,
                      (packets_sent + packets_received) AS total_packets
                   FROM devices ORDER BY total_packets DESC LIMIT 10"""
        )

    def _recommendations(self) -> List[Dict[str, Any]]:
        return self._db.query(
            """SELECT DISTINCT m.alert_type, m.severity, m.recommendation_title,
                      m.recommendation
                   FROM mitigation_recommendations m
                   JOIN intrusion_alerts a ON a.category = m.alert_type
                   ORDER BY FIELD(m.severity,'Critical','High','Medium','Low','Informational')"""
        )

    def _activity(self, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        return self._db.query(
            """SELECT timestamp, user, activity, details FROM activity_logs
                   WHERE timestamp BETWEEN %s AND %s ORDER BY timestamp DESC LIMIT 100""",
            (start, end),
        )

    def _conclusion(self, data: ReportData) -> str:
        s = data.summary
        return (
            f"During the reporting period, AETHRA-SEC recorded "
            f"{s.get('total_scans', 0)} vulnerability scan(s), "
            f"{s.get('total_alerts', 0)} intrusion alert(s) "
            f"({s.get('critical_alerts', 0)} critical), and observed "
            f"{s.get('devices_seen', 0)} device(s). "
            f"{s.get('open_vulnerabilities', 0)} open service(s) warrant review. "
            "Apply the mitigation recommendations above and continue monitoring "
            "to maintain the security posture of the laboratory network."
        )

    # -------------------------------------------------------------- export
    def generate(self, report_type: str, session: Session, fmt: str = "pdf",
                 start: Optional[datetime] = None,
                 end: Optional[datetime] = None) -> str:
        """Build and export a report.  Returns the output file path."""
        data = self.build(report_type, session, start, end)
        out_dir = CONFIG.report_path()
        stamp = now().strftime("%Y%m%d_%H%M%S")
        safe_type = report_type.replace(" ", "_")
        fmt = fmt.lower()

        if fmt == "csv":
            from reports.csv_export import export_csv
            path = out_dir / f"{safe_type}_{stamp}.csv"
            export_csv(data, path)
        elif fmt in ("xlsx", "excel"):
            from reports.excel_export import export_excel
            path = out_dir / f"{safe_type}_{stamp}.xlsx"
            export_excel(data, path)
        else:
            from reports.pdf_report import export_pdf
            path = out_dir / f"{safe_type}_{stamp}.pdf"
            export_pdf(data, path)

        self._record_report(session, report_type, fmt, str(path))
        ACTIVITY.report_generated(session.username, report_type, path.name)
        LOG.info("reports", "generated", f"{report_type} ({fmt}) -> {path.name}",
                 user=session.username)
        return str(path)

    def _record_report(self, session: Session, report_type: str,
                       fmt: str, filename: str) -> None:
        try:
            self._db.execute(
                """INSERT INTO reports (generated_by, generated_at, report_type,
                       file_format, filename) VALUES (%s,%s,%s,%s,%s)""",
                (session.user_id, now(), report_type, fmt, filename), commit=True,
            )
        except Exception as exc:  # noqa: BLE001
            LOG.error("reports", "record_failed", str(exc))

    def report_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._db.query(
            """SELECT r.generated_at, r.report_type, r.file_format, r.filename,
                      u.username AS generated_by_name
                   FROM reports r LEFT JOIN users u ON u.id = r.generated_by
                   ORDER BY r.generated_at DESC LIMIT %s""",
            (limit,),
        )
