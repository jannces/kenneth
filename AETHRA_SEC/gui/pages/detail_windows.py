"""Detail dialogs: device details and alert details with mitigation."""

from __future__ import annotations

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, X, YES
from tkinter import messagebox

from gui.theme import severity_bootstyle
from utils.helpers import format_timestamp


class _ScrollableDialog(ttk.Toplevel):
    """Base dialog with a scrollable body."""

    def __init__(self, master, title: str, size: str = "640x680"):
        super().__init__(master)
        self.title(title)
        self.geometry(size)
        self.minsize(520, 420)
        canvas = ttk.Canvas(self, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.body = ttk.Frame(canvas, padding=16)
        self.body.bind("<Configure>",
                       lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.body, anchor="nw", width=600)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=LEFT, fill=BOTH, expand=YES)
        scrollbar.pack(side="right", fill="y")

    def section(self, title: str) -> None:
        ttk.Separator(self.body).pack(fill=X, pady=(12, 6))
        ttk.Label(self.body, text=title, font=("Segoe UI", 12, "bold"),
                  bootstyle="info").pack(anchor="w")

    def field(self, label: str, value: str) -> None:
        row = ttk.Frame(self.body)
        row.pack(fill=X, pady=1)
        ttk.Label(row, text=f"{label}:", width=20, font=("Segoe UI", 9, "bold")
                  ).pack(side=LEFT, anchor="nw")
        ttk.Label(row, text=str(value), wraplength=420, justify="left",
                  font=("Segoe UI", 9)).pack(side=LEFT, anchor="w")

    def paragraph(self, text: str) -> None:
        ttk.Label(self.body, text=text or "-", wraplength=560, justify="left",
                  font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))


class DeviceDetailWindow(_ScrollableDialog):
    def __init__(self, master, context, ip_address: str):
        super().__init__(master, f"Device - {ip_address}", "560x560")
        self._ctx = context
        self._ip = ip_address
        self._render()

    def _render(self) -> None:
        ctx = self._ctx
        dev = ctx.monitoring.devices.get_device(self._ip)
        db_dev = ctx.db.query_one("SELECT * FROM devices WHERE ip_address = %s",
                                  (self._ip,)) or {}

        ttk.Label(self.body, text=f"🖥  {self._ip}", font=("Segoe UI", 16, "bold")
                  ).pack(anchor="w")

        self.section("Device Information")
        self.field("IP Address", self._ip)
        self.field("Hostname", (dev.hostname if dev else "") or db_dev.get("hostname") or "-")
        self.field("MAC Address", (dev.mac_address if dev else "") or db_dev.get("mac_address") or "-")
        self.field("Vendor", db_dev.get("vendor") or "-")
        self.field("Operating System", db_dev.get("operating_system") or "-")
        self.field("Risk Level", db_dev.get("risk_level") or "Informational")
        self.field("Status", dev.status() if dev else db_dev.get("status", "-"))
        self.field("Open Ports", db_dev.get("open_ports") or "None known")

        self.section("Recent Scan Results")
        results = ctx.db.query(
            "SELECT port, protocol, service, version, risk_level FROM scan_results "
            "WHERE host = %s AND state='open' ORDER BY port LIMIT 50", (self._ip,))
        if results:
            for r in results:
                self.paragraph(
                    f"• {r['port']}/{r['protocol']}  {r['service']} "
                    f"{r.get('version','')}  [{r['risk_level']}]")
        else:
            self.paragraph("No open ports recorded for this device.")

        self.section("Related Alerts")
        alerts = ctx.db.query(
            "SELECT timestamp, category, severity, status FROM intrusion_alerts "
            "WHERE source_ip = %s OR destination_ip = %s "
            "ORDER BY timestamp DESC LIMIT 20", (self._ip, self._ip))
        if alerts:
            for a in alerts:
                self.paragraph(
                    f"• {format_timestamp(a['timestamp'])}  {a['category']} "
                    f"[{a['severity']}] - {a['status']}")
        else:
            self.paragraph("No alerts involving this device.")


class AlertDetailWindow(_ScrollableDialog):
    def __init__(self, master, context, alert_id: int):
        super().__init__(master, "Alert Details", "660x720")
        self._ctx = context
        self._alert_id = alert_id
        self._render()

    def _render(self) -> None:
        ctx = self._ctx
        alert = ctx.db.query_one("SELECT * FROM intrusion_alerts WHERE id = %s",
                                 (self._alert_id,))
        if not alert:
            self.paragraph("Alert not found.")
            return

        badge = ttk.Label(self.body,
                          text=f"🚨 {alert['category']}  [{alert['severity']}]",
                          font=("Segoe UI", 16, "bold"),
                          bootstyle=severity_bootstyle(alert["severity"]))
        badge.pack(anchor="w")

        self.section("Detection")
        self.field("Rule ID (SID)", alert.get("snort_sid") or "-")
        self.field("Classification", alert.get("classification") or "-")
        self.field("Priority", alert.get("priority"))
        self.field("Severity", alert.get("severity"))
        self.field("Protocol", alert.get("protocol") or "-")
        self.field("Source", f"{alert.get('source_ip')}:{alert.get('source_port')}")
        self.field("Destination",
                   f"{alert.get('destination_ip')}:{alert.get('destination_port')}")
        self.field("Occurrences", alert.get("occurrences"))
        self.field("First Seen", format_timestamp(alert.get("timestamp")))
        self.field("Last Seen", format_timestamp(alert.get("last_seen")))
        self.field("Status", alert.get("status"))
        self.field("Description", alert.get("description") or "-")

        # Mitigation + educational content.
        package = ctx.mitigation.recommend_for_alert(
            alert, viewer=ctx.session.username if ctx.session else "")
        rec = package.get("recommendation") or {}

        self.section("What Does This Mean?")
        self.paragraph(package.get("educational") or rec.get("educational")
                       or "No educational explanation available.")

        self.section("Mitigation Recommendation")
        self.field("Title", rec.get("recommendation_title", "-"))
        self.field("Difficulty", rec.get("difficulty", "-"))
        self.paragraph("Problem: " + (rec.get("problem") or "-"))
        self.paragraph("Why it happened: " + (rec.get("why_it_happened") or "-"))
        self.paragraph("Risk: " + (rec.get("risk") or "-"))
        self.paragraph("How to verify: " + (rec.get("how_to_verify") or "-"))
        self.paragraph("Immediate actions:\n" + (rec.get("immediate_actions") or "-"))
        self.paragraph("Long-term prevention:\n" + (rec.get("long_term_prevention") or "-"))
        self.field("References", rec.get("reference", "-"))

        self.section("Related Vulnerabilities")
        related = package.get("related_vulnerabilities") or []
        if related:
            for r in related:
                self.paragraph(
                    f"• {r.get('service','service')} on port {r.get('port')} "
                    f"[{r.get('risk_level','')}]")
        else:
            self.paragraph("No correlated scan findings for the target host.")

        self.section("Event Timeline")
        timeline = ctx.db.query(
            "SELECT timestamp, event FROM alert_timeline WHERE alert_id = %s "
            "ORDER BY timestamp", (self._alert_id,))
        if timeline:
            for t in timeline:
                self.paragraph(f"• {format_timestamp(t['timestamp'])}  {t['event']}")
        else:
            self.paragraph("No timeline entries.")

        # Admin notes (editable by admins).
        self.section("Administrator Notes")
        if ctx.session and ctx.session.is_admin:
            self._notes = ttk.Text(self.body, height=4, wrap="word")
            self._notes.insert("1.0", alert.get("admin_notes") or "")
            self._notes.pack(fill=X)
            ttk.Button(self.body, text="Save Notes", bootstyle="info",
                       command=self._save_notes).pack(anchor="e", pady=(6, 0))
        else:
            self.paragraph(alert.get("admin_notes") or "No notes.")

    def _save_notes(self) -> None:
        notes = self._notes.get("1.0", "end").strip()
        self._ctx.alert_processor.set_notes(self._alert_id, notes)
        messagebox.showinfo("Saved", "Administrator notes updated.")
