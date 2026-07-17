"""Intrusion Alerts page - live Snort alerts with status control and details."""

from __future__ import annotations

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, X, YES
from tkinter import messagebox

from dashboard.widgets import StatCard
from gui.data_table import DataTable
from gui.pages.base_page import BasePage
from utils.constants import AlertStatus
from utils.helpers import format_timestamp


class AlertsPage(BasePage):
    live = True
    title = "Intrusion Alerts"
    subtitle = "Real-time Snort detections, classified and deduplicated"

    def build(self) -> None:
        # IDS status cards.
        cards = ttk.Frame(self.body)
        cards.pack(fill=X)
        self._cards = {}
        for idx, (key, label, style) in enumerate([
            ("status", "Snort Status", "primary"),
            ("today", "Alerts Today", "info"),
            ("critical", "Critical Alerts", "danger"),
            ("received", "Alerts Received", "secondary"),
            ("rules", "Rules Loaded", "secondary"),
        ]):
            card = StatCard(cards, label, "—", bootstyle=style)
            card.grid(row=0, column=idx, padx=5, sticky="nsew")
            self._cards[key] = card
        for col in range(5):
            cards.columnconfigure(col, weight=1)

        # Filter bar.
        filters = ttk.Frame(self.body)
        filters.pack(fill=X, pady=(10, 4))
        ttk.Label(filters, text="Severity").pack(side=LEFT)
        self._sev_filter = ttk.Combobox(filters, width=14, state="readonly",
                                        values=["All", "Critical", "High", "Medium",
                                                "Low", "Informational"])
        self._sev_filter.set("All")
        self._sev_filter.pack(side=LEFT, padx=(4, 12))
        self._sev_filter.bind("<<ComboboxSelected>>", lambda _e: self._load_alerts())
        ttk.Label(filters, text="Status").pack(side=LEFT)
        self._status_filter = ttk.Combobox(filters, width=16, state="readonly",
                                           values=["All"] + [s.value for s in AlertStatus])
        self._status_filter.set("All")
        self._status_filter.pack(side=LEFT, padx=(4, 12))
        self._status_filter.bind("<<ComboboxSelected>>", lambda _e: self._load_alerts())

        if self.can("manage_alert_status"):
            ttk.Button(filters, text="Acknowledge", bootstyle="info-outline",
                       command=lambda: self._set_status(AlertStatus.ACKNOWLEDGED.value)
                       ).pack(side=RIGHT, padx=2)
            ttk.Button(filters, text="Resolve", bootstyle="success-outline",
                       command=lambda: self._set_status(AlertStatus.RESOLVED.value)
                       ).pack(side=RIGHT, padx=2)
            ttk.Button(filters, text="False Positive", bootstyle="secondary-outline",
                       command=self._mark_false_positive).pack(side=RIGHT, padx=2)

        # Alerts table.
        self._table = DataTable(
            self.body,
            columns=["timestamp", "category", "source_ip", "destination_ip",
                     "severity", "priority", "protocol", "occurrences",
                     "recommendation", "status"],
            headings=["Time", "Threat", "Source", "Destination", "Severity",
                      "Priority", "Proto", "Occ.", "Rec.", "Status"],
            on_double_click=self._show_details,
            height=16,
        )
        self._table.pack(fill=BOTH, expand=YES, pady=(6, 0))

    def on_show(self) -> None:
        self._load_alerts()
        self._update_status_cards()

    def on_refresh(self) -> None:
        self._update_status_cards()
        # Reload the alert table periodically (not every tick) so new alerts
        # appear without constantly rebuilding the tree under the user's cursor.
        self._tick = getattr(self, "_tick", 0) + 1
        if self._tick % 4 == 0:
            self._load_alerts()

    def _update_status_cards(self) -> None:
        snap = self.context.snort.status_snapshot()
        self._cards["status"].set_value(snap["status"])
        self._cards["today"].set_value(snap["alerts_today"])
        self._cards["critical"].set_value(snap["critical_alerts"])
        self._cards["received"].set_value(snap["alerts_received"])
        self._cards["rules"].set_value(snap["rules_loaded"])

    def _load_alerts(self) -> None:
        clauses, params = [], []
        sev = self._sev_filter.get()
        if sev != "All":
            clauses.append("severity = %s")
            params.append(sev)
        status = self._status_filter.get()
        if status != "All":
            clauses.append("status = %s")
            params.append(status)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        try:
            alerts = self.context.db.query(
                f"""SELECT * FROM intrusion_alerts {where}
                        ORDER BY last_seen DESC LIMIT 300""", params)
        except Exception:  # noqa: BLE001
            alerts = []
        rows = []
        for a in alerts:
            rows.append({
                "timestamp": format_timestamp(a.get("timestamp")),
                "category": a.get("category"),
                "source_ip": a.get("source_ip"),
                "destination_ip": a.get("destination_ip"),
                "severity": a.get("severity"),
                "priority": a.get("priority"),
                "protocol": a.get("protocol"),
                "occurrences": a.get("occurrences"),
                "recommendation": "Available",
                "status": a.get("status"),
                "_severity": a.get("severity"),
                "_id": a.get("id"),
            })
        self._table.set_rows(rows)

    def _selected_id(self):
        row = self._table.selected_row()
        return row.get("_id") if row else None

    def _set_status(self, status: str) -> None:
        alert_id = self._selected_id()
        if not alert_id:
            messagebox.showinfo("Alerts", "Select an alert first.")
            return
        self.context.alert_processor.set_status(
            int(alert_id), status, user=self.context.session.username)
        self._load_alerts()

    def _mark_false_positive(self) -> None:
        alert_id = self._selected_id()
        if not alert_id:
            messagebox.showinfo("Alerts", "Select an alert first.")
            return
        from tkinter.simpledialog import askstring
        reason = askstring("False Positive", "Reason for marking as false positive:")
        if reason is None:
            return
        self.context.alert_processor.set_status(
            int(alert_id), AlertStatus.FALSE_POSITIVE.value,
            user=self.context.session.username, reason=reason)
        self._load_alerts()

    def _show_details(self, row) -> None:
        from gui.pages.detail_windows import AlertDetailWindow
        if row.get("_id"):
            AlertDetailWindow(self, self.context, int(row["_id"]))
