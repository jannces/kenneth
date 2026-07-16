"""Scan orchestration: validate -> record -> run -> parse -> store.

Runs each scan on a background daemon thread so the GUI never freezes.  Progress
updates and completion are delivered through callbacks that the GUI marshals
onto the Tk main thread.  Scan history CRUD lives here too.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List, Optional

from authentication.session import Session
from logs.activity_logger import ACTIVITY
from logs.logger import LOG
from scanner.nmap_engine import NmapEngine, ScanOutcome
from scanner.scan_parser import assess_outcome, to_db_rows, AssessedScan
from utils.constants import SCAN_TYPE_LABELS, Severity
from utils.helpers import now
from utils.validators import validate_scan_target


class ScanController:
    """Coordinates vulnerability scans and persists their results."""

    def __init__(self, database: Any, engine: Optional[NmapEngine] = None) -> None:
        self._db = database
        self._engine = engine or NmapEngine()
        self._active_thread: Optional[threading.Thread] = None
        self._cancel_flag = threading.Event()

    @property
    def engine_available(self) -> bool:
        return self._engine.available

    @property
    def is_scanning(self) -> bool:
        return self._active_thread is not None and self._active_thread.is_alive()

    # ------------------------------------------------------------------- start
    def start_scan(self, session: Session, target: str, scan_type: str,
                   scan_name: str = "",
                   on_progress: Optional[Callable[[str], None]] = None,
                   on_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
                   on_error: Optional[Callable[[str], None]] = None) -> Optional[str]:
        """Validate and launch a scan on a background thread.

        Returns an error string if the request is rejected before starting,
        otherwise ``None`` (the outcome arrives via callbacks).
        """
        if self.is_scanning:
            return "A scan is already running. Please wait for it to finish."

        validation = validate_scan_target(target)
        if not validation:
            return validation.message

        target = validation.value
        scan_name = scan_name.strip() or f"{SCAN_TYPE_LABELS.get(scan_type, scan_type)} - {target}"
        self._cancel_flag.clear()

        self._active_thread = threading.Thread(
            target=self._run_scan, name="aethra-scan", daemon=True,
            args=(session, target, scan_type, scan_name, on_progress, on_complete, on_error),
        )
        self._active_thread.start()
        return None

    def cancel(self) -> None:
        self._cancel_flag.set()

    # -------------------------------------------------------------- background
    def _run_scan(self, session: Session, target: str, scan_type: str, scan_name: str,
                  on_progress, on_complete, on_error) -> None:
        started = now()
        scan_id = self._create_scan_record(session, scan_name, target, scan_type)
        ACTIVITY.scan_started(session.username, target, scan_type)

        def progress(msg: str) -> None:
            if on_progress and not self._cancel_flag.is_set():
                on_progress(msg)

        try:
            outcome: ScanOutcome = self._engine.scan(target, scan_type, progress_cb=progress)
            if outcome.error:
                self._finish_scan(scan_id, started, 0, 0, Severity.INFORMATIONAL.value, "failed")
                LOG.error("scan", "scan_failed", outcome.error, user=session.username)
                if on_error:
                    on_error(outcome.error)
                return

            assessed = assess_outcome(outcome)
            self._store_results(scan_id, assessed)
            self._sync_devices(assessed)

            self._finish_scan(
                scan_id, started, assessed.total_hosts, assessed.total_open_ports,
                assessed.highest_risk, "completed",
            )
            ACTIVITY.scan_finished(session.username, target,
                                   assessed.total_hosts, assessed.total_open_ports)

            if on_complete:
                on_complete({
                    "scan_id": scan_id,
                    "scan_name": scan_name,
                    "target": target,
                    "total_hosts": assessed.total_hosts,
                    "total_open_ports": assessed.total_open_ports,
                    "highest_risk": assessed.highest_risk,
                    "assessed": assessed,
                })
        except Exception as exc:  # noqa: BLE001
            LOG.exception("scan", "scan_exception", exc, user=session.username)
            self._finish_scan(scan_id, started, 0, 0, Severity.INFORMATIONAL.value, "failed")
            if on_error:
                on_error(str(exc))
        finally:
            self._active_thread = None

    # ---------------------------------------------------------- persistence
    def _create_scan_record(self, session: Session, scan_name: str,
                            target: str, scan_type: str) -> int:
        return self._db.execute(
            """INSERT INTO vulnerability_scans
                   (scan_name, target_ip, scan_type, started_at, status, created_by)
                   VALUES (%s, %s, %s, %s, 'running', %s)""",
            (scan_name, target, scan_type, now(), session.user_id), commit=True,
        )

    def _finish_scan(self, scan_id: int, started, hosts: int, open_ports: int,
                     highest_risk: str, status: str) -> None:
        finished = now()
        duration = (finished - started).total_seconds()
        self._db.execute(
            """UPDATE vulnerability_scans
                   SET finished_at = %s, duration = %s, total_hosts = %s,
                       total_open_ports = %s, highest_risk = %s, status = %s
                   WHERE id = %s""",
            (finished, duration, hosts, open_ports, highest_risk, status, scan_id),
            commit=True,
        )

    def _store_results(self, scan_id: int, assessed: AssessedScan) -> None:
        rows = to_db_rows(scan_id, assessed)
        if not rows:
            return
        columns = ["scan_id", "host", "hostname", "mac_address", "vendor",
                   "os_guess", "port", "protocol", "service", "product",
                   "version", "state", "risk_level", "cve_reference", "description"]
        placeholders = ", ".join(["%s"] * len(columns))
        sql = f"INSERT INTO scan_results ({', '.join(columns)}) VALUES ({placeholders})"
        params = [[row[c] for c in columns] for row in rows]
        self._db.executemany(sql, params, commit=True)

    def _sync_devices(self, assessed: AssessedScan) -> None:
        """Update the devices table with scan-derived info (open ports/OS/risk)."""
        for host in assessed.hosts:
            open_ports = ",".join(str(p.port) for p in host.ports if p.state == "open")
            existing = self._db.query_one(
                "SELECT id FROM devices WHERE ip_address = %s", (host.host,)
            )
            if existing:
                self._db.execute(
                    """UPDATE devices SET hostname = COALESCE(NULLIF(%s,''), hostname),
                           mac_address = COALESCE(NULLIF(%s,''), mac_address),
                           vendor = COALESCE(NULLIF(%s,''), vendor),
                           operating_system = COALESCE(NULLIF(%s,''), operating_system),
                           open_ports = %s, risk_level = %s, last_seen = %s
                           WHERE id = %s""",
                    (host.hostname, host.mac_address, host.vendor, host.os_guess,
                     open_ports, host.risk, now(), existing["id"]), commit=True,
                )
            else:
                self._db.execute(
                    """INSERT INTO devices (ip_address, hostname, mac_address, vendor,
                           operating_system, open_ports, risk_level, status)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, 'Online')""",
                    (host.host, host.hostname, host.mac_address, host.vendor,
                     host.os_guess, open_ports, host.risk), commit=True,
                )

    # -------------------------------------------------------------- history
    def scan_history(self, search: str = "", limit: int = 200) -> List[Dict[str, Any]]:
        if search:
            like = f"%{search}%"
            return self._db.query(
                """SELECT s.*, u.username AS created_by_name
                       FROM vulnerability_scans s
                       LEFT JOIN users u ON u.id = s.created_by
                       WHERE s.scan_name LIKE %s OR s.target_ip LIKE %s
                       ORDER BY s.started_at DESC LIMIT %s""",
                (like, like, limit),
            )
        return self._db.query(
            """SELECT s.*, u.username AS created_by_name
                   FROM vulnerability_scans s
                   LEFT JOIN users u ON u.id = s.created_by
                   ORDER BY s.started_at DESC LIMIT %s""",
            (limit,),
        )

    def scan_results(self, scan_id: int) -> List[Dict[str, Any]]:
        return self._db.query(
            "SELECT * FROM scan_results WHERE scan_id = %s ORDER BY host, port",
            (scan_id,),
        )

    def all_results(self, search: str = "", limit: int = 500) -> List[Dict[str, Any]]:
        if search:
            like = f"%{search}%"
            return self._db.query(
                """SELECT * FROM scan_results
                       WHERE host LIKE %s OR service LIKE %s OR risk_level LIKE %s
                       ORDER BY id DESC LIMIT %s""",
                (like, like, like, limit),
            )
        return self._db.query(
            "SELECT * FROM scan_results ORDER BY id DESC LIMIT %s", (limit,)
        )

    def delete_scan(self, session: Session, scan_id: int) -> bool:
        """Delete a scan (admin only - enforced by caller via permissions)."""
        self._db.execute("DELETE FROM vulnerability_scans WHERE id = %s",
                         (scan_id,), commit=True)
        ACTIVITY.record(session.username, "Scan Deleted", f"scan_id={scan_id}")
        return True

    def summary_counts(self) -> Dict[str, Any]:
        total_scans = self._db.scalar("SELECT COUNT(*) FROM vulnerability_scans") or 0
        total_vulns = self._db.scalar(
            "SELECT COUNT(*) FROM scan_results WHERE state = 'open'"
        ) or 0
        last = self._db.query_one(
            "SELECT finished_at FROM vulnerability_scans WHERE status='completed' "
            "ORDER BY finished_at DESC LIMIT 1"
        )
        severity_rows = self._db.query(
            """SELECT risk_level, COUNT(*) AS c FROM scan_results
                   WHERE state='open' GROUP BY risk_level"""
        )
        by_severity = {r["risk_level"]: r["c"] for r in severity_rows}
        return {
            "total_scans": total_scans,
            "open_vulnerabilities": total_vulns,
            "last_scan": last["finished_at"] if last else None,
            "by_severity": by_severity,
        }
