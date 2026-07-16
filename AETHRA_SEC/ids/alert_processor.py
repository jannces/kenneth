"""Alert processing pipeline: classify -> deduplicate -> correlate -> persist.

This is where a raw Snort alert becomes actionable intelligence:

* **Classification** into a threat category and severity.
* **Deduplication** so 1000 identical floods become one row with an occurrence
  counter and preserved first/last timestamps (not 1000 rows).
* **Correlation** against Nmap scan results / device inventory to surface
  related vulnerabilities (e.g. SSH exposed + SSH brute force = high-risk).
* **Persistence** to ``intrusion_alerts`` + ``alert_timeline`` and a detection
  metric row for evaluation.
* **Notification** to the GUI via a callback so the dashboard updates live.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List, Optional

from ids.alert_parser import ParsedAlert
from ids.threat_classifier import classify_category, classify_severity
from logs.logger import LOG
from utils.constants import AlertStatus, Severity, ThreatCategory
from utils.helpers import now


class AlertProcessor:
    """Turns parsed Snort alerts into stored, correlated, deduplicated events."""

    def __init__(self, database: Any,
                 notify_cb: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self._db = database
        self._notify_cb = notify_cb
        self._lock = threading.Lock()
        # Detection-time bookkeeping: category -> first-seen timestamp this run.
        self._attack_first_seen: Dict[str, float] = {}

    def set_notifier(self, notify_cb: Callable[[Dict[str, Any]], None]) -> None:
        self._notify_cb = notify_cb

    # --------------------------------------------------------------- process
    def process(self, alert: ParsedAlert) -> Optional[Dict[str, Any]]:
        """Process one parsed alert.  Returns the stored alert dict (or None)."""
        try:
            category = classify_category(alert.message, alert.classification)
            dedup_key = self._dedup_key(category, alert)

            with self._lock:
                existing = self._db.query_one(
                    "SELECT * FROM intrusion_alerts WHERE dedup_key = %s AND status = %s",
                    (dedup_key, AlertStatus.OPEN.value),
                )
                if existing:
                    stored = self._update_existing(existing, category, alert)
                else:
                    stored = self._insert_new(dedup_key, category, alert)

            self._record_detection_metric(category, stored)
            related = self.correlate(stored)
            stored["related_vulnerabilities"] = related

            if self._notify_cb:
                try:
                    self._notify_cb(stored)
                except Exception:  # noqa: BLE001
                    pass
            return stored
        except Exception as exc:  # noqa: BLE001
            LOG.exception("ids", "alert_process_failed", exc)
            return None

    def _dedup_key(self, category: ThreatCategory, alert: ParsedAlert) -> str:
        return f"{category.value}|{alert.source_ip}|{alert.destination_ip}|{alert.sid}"

    def _insert_new(self, dedup_key: str, category: ThreatCategory,
                    alert: ParsedAlert) -> Dict[str, Any]:
        severity = classify_severity(category, alert.priority, occurrences=1)
        alert_id = self._db.execute(
            """INSERT INTO intrusion_alerts
                   (timestamp, last_seen, snort_sid, classification, category,
                    priority, source_ip, destination_ip, source_port,
                    destination_port, protocol, interface, description, severity,
                    occurrences, status, dedup_key)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (alert.timestamp, alert.timestamp, alert.rule_id, alert.classification,
             category.value, alert.priority, alert.source_ip, alert.destination_ip,
             alert.source_port, alert.destination_port, alert.protocol,
             alert.interface, alert.message, severity.value, 1,
             AlertStatus.OPEN.value, dedup_key),
            commit=True,
        )
        self._add_timeline(alert_id, f"Detected: {alert.message}")
        LOG.info("ids", "alert_new", f"{category.value} {alert.source_ip}->{alert.destination_ip} "
                                     f"[{severity.value}]")
        stored = self._db.query_one("SELECT * FROM intrusion_alerts WHERE id = %s", (alert_id,))
        return stored or {}

    def _update_existing(self, existing: Dict[str, Any], category: ThreatCategory,
                         alert: ParsedAlert) -> Dict[str, Any]:
        occurrences = int(existing["occurrences"]) + 1
        severity = classify_severity(category, alert.priority, occurrences=occurrences)
        # Severity can only escalate for an active event, never silently drop.
        current = Severity(existing["severity"])
        if severity.rank < current.rank:
            severity = current
        self._db.execute(
            """UPDATE intrusion_alerts
                   SET occurrences = %s, last_seen = %s, severity = %s
                   WHERE id = %s""",
            (occurrences, alert.timestamp, severity.value, existing["id"]),
            commit=True,
        )
        # Timeline: record milestone occurrences to avoid flooding the timeline.
        if occurrences in (10, 50, 100, 500, 1000) or occurrences % 1000 == 0:
            self._add_timeline(existing["id"],
                               f"Occurrence #{occurrences} (severity {severity.value})")
        stored = self._db.query_one("SELECT * FROM intrusion_alerts WHERE id = %s",
                                    (existing["id"],))
        return stored or existing

    def _add_timeline(self, alert_id: int, event: str) -> None:
        try:
            self._db.execute(
                "INSERT INTO alert_timeline (alert_id, timestamp, event) VALUES (%s,%s,%s)",
                (alert_id, now(), event), commit=True,
            )
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------- correlation
    def correlate(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find Nmap-discovered services on the alert's target that relate.

        Example: a Snort SSH brute-force alert against a host that Nmap found
        with SSH open yields a "related vulnerability" linking the two.
        """
        target = alert.get("destination_ip") or ""
        if not target:
            return []
        try:
            rows = self._db.query(
                """SELECT DISTINCT service, port, risk_level FROM scan_results
                       WHERE host = %s AND state = 'open'""",
                (target,),
            )
        except Exception:  # noqa: BLE001
            return []

        category = alert.get("category", "")
        related: List[Dict[str, Any]] = []
        service_hint = self._category_service_hint(category)
        for row in rows:
            svc = (row.get("service") or "").lower()
            match = (service_hint and service_hint in svc) or (not service_hint)
            if match:
                related.append({
                    "service": row.get("service", ""),
                    "port": row.get("port", 0),
                    "risk_level": row.get("risk_level", ""),
                    "note": f"{row.get('service','service')} exposed on port "
                            f"{row.get('port')} correlates with {category}.",
                })
        return related

    @staticmethod
    def _category_service_hint(category: str) -> str:
        return {
            ThreatCategory.SSH_ATTACK.value: "ssh",
            ThreatCategory.FTP_ATTACK.value: "ftp",
            ThreatCategory.HTTP_ATTACK.value: "http",
            ThreatCategory.WEB_ATTACK.value: "http",
            ThreatCategory.DNS_ATTACK.value: "dns",
        }.get(category, "")

    # ------------------------------------------------------- detection metrics
    def _record_detection_metric(self, category: ThreatCategory,
                                 stored: Dict[str, Any]) -> None:
        """Record detection latency for the evaluation metrics table."""
        key = category.value
        current = now().timestamp()
        first = self._attack_first_seen.setdefault(key, current)
        detection_time = current - first
        try:
            self._db.execute(
                """INSERT INTO detection_metrics
                       (metric_type, attack_type, detection_time, detected)
                       VALUES ('detection_time', %s, %s, 1)""",
                (key, round(detection_time, 3)), commit=True,
            )
        except Exception:  # noqa: BLE001
            pass

    # --------------------------------------------------------- status changes
    def set_status(self, alert_id: int, status: str, user: str = "",
                   reason: str = "") -> bool:
        """Change an alert's lifecycle status (admin-gated by the caller)."""
        if status not in {s.value for s in AlertStatus}:
            return False
        if status == AlertStatus.FALSE_POSITIVE.value:
            self._db.execute(
                """UPDATE intrusion_alerts SET status = %s, fp_reason = %s,
                       fp_user = %s, fp_date = %s WHERE id = %s""",
                (status, reason, user, now(), alert_id), commit=True,
            )
        else:
            self._db.execute(
                "UPDATE intrusion_alerts SET status = %s WHERE id = %s",
                (status, alert_id), commit=True,
            )
        self._add_timeline(alert_id, f"Status changed to {status}" +
                           (f" by {user}" if user else ""))
        LOG.info("ids", "alert_status", f"id={alert_id} -> {status}", user=user or "system")
        return True

    def set_notes(self, alert_id: int, notes: str) -> None:
        self._db.execute("UPDATE intrusion_alerts SET admin_notes = %s WHERE id = %s",
                         (notes, alert_id), commit=True)
