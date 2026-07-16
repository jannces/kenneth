"""Application service container (a small service locator).

The :class:`AppContext` wires together every backend service and shares them
with the GUI pages.  Constructing it once after login keeps the presentation
layer decoupled from how services are built, and gives pages a single, typed
handle to everything they need.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from authentication.auth_service import AuthService
from authentication.session import Session, SESSION
from database.database import Database
from ids.alert_processor import AlertProcessor
from ids.snort_listener import SnortListener
from logs.activity_logger import ACTIVITY
from logs.logger import LOG
from mitigation.recommender import MitigationEngine
from monitoring.pyshark_capture import MonitoringEngine
from reports.report_generator import ReportGenerator
from scanner.scan_controller import ScanController
from settings.network_settings import NetworkSettings
from settings.settings import SettingsService


class AppContext:
    """Holds the database and all business services for the GUI."""

    def __init__(self, database: Database) -> None:
        self.db = database
        # Core services.
        self.auth = AuthService(database)
        self.settings = SettingsService(database)
        self.network_settings = NetworkSettings(self.settings)
        self.scan_controller = ScanController(database)
        self.monitoring = MonitoringEngine(database)
        self.mitigation = MitigationEngine(database)
        self.reports = ReportGenerator(database)

        # IDS: processor + listener share a notify callback fanned out to
        # any GUI subscribers (dashboard, alerts page, toast notifications).
        self._alert_subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self.alert_processor = AlertProcessor(database, self._on_alert)
        self.snort = SnortListener(database, self.alert_processor, self._on_alert)

        self._notify_subscribers: List[Callable[[str, str, str], None]] = []

    # ------------------------------------------------------------- session
    @property
    def session(self) -> Optional[Session]:
        return SESSION.current

    # ------------------------------------------------------ background start
    def start_background_services(self) -> None:
        """Start monitoring + Snort listener after login (best-effort)."""
        self.settings.apply_to_config()
        # Correlate live packets with the IDS layer.
        try:
            self.monitoring.subscribe(self._on_packet)
        except Exception:  # noqa: BLE001
            pass

        if getattr(self.settings, "get", None):
            auto = self.settings.get("auto_start_monitoring", "true").lower() in (
                "1", "true", "yes", "on")
        else:
            auto = True

        if auto and self.monitoring.available:
            self.monitoring.start()
        # Always begin listening for Snort alerts; it self-recovers if idle.
        self.snort.start_listener()
        LOG.info("app", "services_started",
                 f"monitoring={self.monitoring.running}, "
                 f"snort_listener=on")

    def stop_background_services(self) -> None:
        try:
            self.monitoring.stop()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.snort.stop_listener()
        except Exception:  # noqa: BLE001
            pass

    # -------------------------------------------------------- event plumbing
    def subscribe_alerts(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        self._alert_subscribers.append(cb)

    def subscribe_notifications(self, cb: Callable[[str, str, str], None]) -> None:
        """Subscribe to (title, message, level) toast notifications."""
        self._notify_subscribers.append(cb)

    def notify(self, title: str, message: str, level: str = "info") -> None:
        for cb in list(self._notify_subscribers):
            try:
                cb(title, message, level)
            except Exception:  # noqa: BLE001
                continue

    def _on_alert(self, alert: Dict[str, Any]) -> None:
        for cb in list(self._alert_subscribers):
            try:
                cb(alert)
            except Exception:  # noqa: BLE001
                continue
        # Surface critical/high alerts as toast notifications.
        severity = alert.get("severity", "")
        if severity in ("Critical", "High"):
            self.notify(
                f"Threat Detected: {alert.get('category', 'Alert')}",
                f"{severity} severity from {alert.get('source_ip', 'unknown')}",
                "critical" if severity == "Critical" else "warning",
            )

    def _on_packet(self, meta) -> None:
        """Capture->correlation wire.

        Snort is the authoritative detector, so per-packet work here is kept
        deliberately minimal to avoid slowing the capture thread.  The hook
        exists so additional live-packet correlation engines can attach to the
        same stream without touching the capture code (the extension point the
        manuscript's PyShark -> ... -> Snort flow calls for).
        """
        return
