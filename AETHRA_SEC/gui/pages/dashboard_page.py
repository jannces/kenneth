"""Dashboard home - live security overview with cards and charts."""

from __future__ import annotations

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, X, YES

from dashboard.charts import BarChart, LineChart, PieChart
from dashboard.statistics import DashboardStatistics
from dashboard.widgets import StatCard
from gui.data_table import DataTable
from gui.pages.base_page import BasePage


class DashboardPage(BasePage):
    live = True
    title = "Security Dashboard"
    subtitle = "Real-time overview of monitoring, scans and threats"

    def build(self) -> None:
        self._stats = DashboardStatistics(self.context)
        self._cards = {}

        # -- summary cards ---------------------------------------------------
        cards = ttk.Frame(self.body)
        cards.pack(fill=X)
        specs = [
            ("devices_online", "Devices Online", "primary", "🖥"),
            ("active_connections", "Active Connections", "info", "🔗"),
            ("packets_captured", "Packets Captured", "secondary", "📦"),
            ("packets_per_second", "Packets / sec", "secondary", "⚡"),
            ("alerts_today", "Today's Alerts", "warning", "🚨"),
            ("critical_alerts", "Critical Threats", "danger", "⛔"),
            ("open_vulnerabilities", "Open Vulnerabilities", "warning", "🔓"),
            ("bandwidth", "Bandwidth (Up/Down)", "info", "📶"),
        ]
        for idx, (key, label, style, icon) in enumerate(specs):
            card = StatCard(cards, label, "0", bootstyle=style, icon=icon)
            card.grid(row=idx // 4, column=idx % 4, padx=6, pady=6, sticky="nsew")
            self._cards[key] = card
        for col in range(4):
            cards.columnconfigure(col, weight=1)

        # -- charts row ------------------------------------------------------
        charts = ttk.Frame(self.body)
        charts.pack(fill=BOTH, expand=YES, pady=(10, 0))
        for col in range(3):
            charts.columnconfigure(col, weight=1)
        charts.rowconfigure(0, weight=1)

        self._pps_chart = LineChart(charts, "Packets / sec", series=["Packets/s"])
        self._pps_chart.grid(row=0, column=0, sticky="nsew", padx=4)
        self._proto_chart = PieChart(charts, "Protocol Distribution")
        self._proto_chart.grid(row=0, column=1, sticky="nsew", padx=4)
        self._sev_chart = BarChart(charts, "Vulnerability Severity")
        self._sev_chart.grid(row=0, column=2, sticky="nsew", padx=4)

        charts2 = ttk.Frame(self.body)
        charts2.pack(fill=BOTH, expand=YES, pady=(8, 0))
        charts2.columnconfigure(0, weight=1)
        charts2.columnconfigure(1, weight=1)
        charts2.rowconfigure(0, weight=1)
        self._bw_chart = LineChart(charts2, "Bandwidth (KB/s)",
                                   series=["Upload", "Download"])
        self._bw_chart.grid(row=0, column=0, sticky="nsew", padx=4)
        self._threat_chart = BarChart(charts2, "Top Threat Types", horizontal=True)
        self._threat_chart.grid(row=0, column=1, sticky="nsew", padx=4)

        # -- device table ----------------------------------------------------
        table_frame = ttk.Labelframe(self.body, text="Observed Devices", padding=8)
        table_frame.pack(fill=BOTH, expand=YES, pady=(10, 0))
        self._device_table = DataTable(
            table_frame,
            columns=["hostname", "ip_address", "mac_address", "operating_system",
                     "risk_level", "status", "packets", "last_seen"],
            headings=["Hostname", "IP Address", "MAC", "OS", "Risk", "Status",
                      "Packets", "Last Seen"],
            on_double_click=self._show_device,
            height=8,
        )
        self._device_table.pack(fill=BOTH, expand=YES)

    def on_show(self) -> None:
        self.on_refresh()
        self._load_devices()

    def on_refresh(self) -> None:
        snap = self._stats.snapshot()
        self._cards["devices_online"].set_value(
            snap.devices_online, f"of {snap.total_devices} seen")
        self._cards["active_connections"].set_value(snap.active_connections)
        self._cards["packets_captured"].set_value(f"{snap.packets_captured:,}")
        self._cards["packets_per_second"].set_value(f"{snap.packets_per_second:.0f}")
        self._cards["alerts_today"].set_value(snap.alerts_today)
        self._cards["critical_alerts"].set_value(snap.critical_alerts)
        self._cards["open_vulnerabilities"].set_value(snap.open_vulnerabilities)
        self._cards["bandwidth"].set_value(
            snap.download, f"↑ {snap.upload}")

        self._pps_chart.push({"Packets/s": snap.packets_per_second})
        self._proto_chart.update_distribution(snap.protocol_distribution)
        self._sev_chart.update_values(snap.severity_distribution, severity_colored=True)
        self._threat_chart.update_values(snap.top_threats)

        bw = self.context.monitoring.bandwidth_snapshot()
        self._bw_chart.push({
            "Upload": bw.upload_bps / 1024.0,
            "Download": bw.download_bps / 1024.0,
        })

        # Refresh device table roughly every 5 seconds via a counter.
        self._tick = getattr(self, "_tick", 0) + 1
        if self._tick % 5 == 0:
            self._load_devices()

    def _load_devices(self) -> None:
        rows = []
        for dev in self.context.monitoring.devices.list_devices():
            rows.append({
                "hostname": dev.hostname or "-",
                "ip_address": dev.ip_address,
                "mac_address": dev.mac_address or "-",
                "operating_system": dev.operating_system or "-",
                "risk_level": dev.risk_level,
                "status": dev.status(),
                "packets": dev.packets_sent + dev.packets_received,
                "last_seen": dev.last_seen.strftime("%H:%M:%S"),
                "_severity": dev.risk_level,
            })
        if not rows:  # fall back to persisted device inventory
            try:
                for d in self.context.db.query(
                        "SELECT * FROM devices ORDER BY last_seen DESC LIMIT 100"):
                    rows.append({
                        "hostname": d.get("hostname") or "-",
                        "ip_address": d.get("ip_address"),
                        "mac_address": d.get("mac_address") or "-",
                        "operating_system": d.get("operating_system") or "-",
                        "risk_level": d.get("risk_level"),
                        "status": d.get("status"),
                        "packets": (d.get("packets_sent") or 0) + (d.get("packets_received") or 0),
                        "last_seen": str(d.get("last_seen") or ""),
                        "_severity": d.get("risk_level"),
                    })
            except Exception:  # noqa: BLE001
                pass
        self._device_table.set_rows(rows)

    def _show_device(self, row) -> None:
        from gui.pages.detail_windows import DeviceDetailWindow
        DeviceDetailWindow(self, self.context, row.get("ip_address", ""))
