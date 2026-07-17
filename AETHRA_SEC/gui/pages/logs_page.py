"""Logs page - tabbed, searchable, read-only audit views.

Logs are never editable through the GUI (Integrity requirement).  Standard
users get a limited set of tabs (no system/authentication logs).
"""

from __future__ import annotations

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, X, YES

from gui.data_table import DataTable
from gui.pages.base_page import BasePage
from utils.helpers import format_timestamp


class LogsPage(BasePage):
    title = "Logs & Audit Trail"
    subtitle = "Historical records for auditing and troubleshooting (read-only)"

    def build(self) -> None:
        self._notebook = ttk.Notebook(self.body)
        self._notebook.pack(fill=BOTH, expand=YES)
        self._tabs = {}

        admin = self.can("view_all_logs")
        tab_specs = [
            ("System Logs", self._load_system, admin),
            ("Activity Logs", self._load_activity, True),
            ("Scan Logs", self._load_scans, True),
            ("Monitoring Logs", self._load_monitoring, True),
            ("Alert Logs", self._load_alerts, True),
            ("Authentication Logs", self._load_auth, admin),
        ]
        for label, loader, visible in tab_specs:
            if not visible:
                continue
            frame = ttk.Frame(self._notebook, padding=8)
            self._notebook.add(frame, text=label)
            table = self._make_table(frame, label)
            self._tabs[label] = (table, loader)
            ttk.Button(frame, text="Refresh", bootstyle="secondary-outline",
                       command=lambda l=label: self._refresh_tab(l)).pack(anchor="e",
                                                                          pady=(6, 0))

    def _make_table(self, frame, label: str) -> DataTable:
        cols = {
            "System Logs": (["timestamp", "module", "action", "description", "user", "severity"],
                            ["Time", "Module", "Action", "Description", "User", "Severity"]),
            "Activity Logs": (["timestamp", "user", "activity", "details"],
                              ["Time", "User", "Activity", "Details"]),
            "Scan Logs": (["started_at", "scan_name", "target_ip", "scan_type",
                           "status", "created_by_name"],
                          ["Started", "Name", "Target", "Type", "Status", "By"]),
            "Monitoring Logs": (["timestamp", "packets_per_second", "bytes_per_second",
                                 "active_connections", "tcp_count", "udp_count"],
                                ["Time", "Pkts/s", "Bytes/s", "Conns", "TCP", "UDP"]),
            "Alert Logs": (["timestamp", "category", "severity", "source_ip",
                            "destination_ip", "status"],
                           ["Time", "Threat", "Severity", "Source", "Dest", "Status"]),
            "Authentication Logs": (["login_time", "username", "ip_address",
                                     "computer_name", "status", "logout_time"],
                                    ["Login", "User", "IP", "Computer", "Status", "Logout"]),
        }[label]
        table = DataTable(frame, columns=cols[0], headings=cols[1], height=16)
        table.pack(fill=BOTH, expand=YES)
        return table

    def on_show(self) -> None:
        for label in self._tabs:
            self._refresh_tab(label)

    def _refresh_tab(self, label: str) -> None:
        table, loader = self._tabs[label]
        try:
            table.set_rows(loader())
        except Exception:  # noqa: BLE001
            table.set_rows([])

    # ------------------------------------------------------------- loaders
    def _load_system(self):
        rows = self.context.db.query(
            "SELECT * FROM system_logs ORDER BY timestamp DESC LIMIT 500")
        for r in rows:
            r["timestamp"] = format_timestamp(r.get("timestamp"))
        return rows

    def _load_activity(self):
        # Non-admins only see their own activity.
        if self.can("view_all_logs"):
            rows = self.context.db.query(
                "SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 500")
        else:
            rows = self.context.db.query(
                "SELECT * FROM activity_logs WHERE user = %s "
                "ORDER BY timestamp DESC LIMIT 500", (self.context.session.username,))
        for r in rows:
            r["timestamp"] = format_timestamp(r.get("timestamp"))
        return rows

    def _load_scans(self):
        rows = self.context.db.query(
            """SELECT s.started_at, s.scan_name, s.target_ip, s.scan_type,
                      s.status, u.username AS created_by_name
                   FROM vulnerability_scans s LEFT JOIN users u ON u.id = s.created_by
                   ORDER BY s.started_at DESC LIMIT 500""")
        for r in rows:
            r["started_at"] = format_timestamp(r.get("started_at"))
        return rows

    def _load_monitoring(self):
        rows = self.context.db.query(
            "SELECT * FROM traffic_statistics ORDER BY timestamp DESC LIMIT 500")
        for r in rows:
            r["timestamp"] = format_timestamp(r.get("timestamp"))
        return rows

    def _load_alerts(self):
        rows = self.context.db.query(
            "SELECT * FROM intrusion_alerts ORDER BY timestamp DESC LIMIT 500")
        for r in rows:
            r["timestamp"] = format_timestamp(r.get("timestamp"))
        return rows

    def _load_auth(self):
        rows = self.context.db.query(
            "SELECT * FROM login_history ORDER BY login_time DESC LIMIT 500")
        for r in rows:
            r["login_time"] = format_timestamp(r.get("login_time"))
            r["logout_time"] = format_timestamp(r.get("logout_time"))
        return rows
