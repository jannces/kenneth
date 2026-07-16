"""Live Monitoring page - interface status, statistics, graph and recent packets."""

from __future__ import annotations

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, X, YES
from tkinter import messagebox

from dashboard.charts import LineChart, PieChart
from dashboard.widgets import StatCard
from gui.data_table import DataTable
from gui.pages.base_page import BasePage
from utils.helpers import format_bytes, format_duration


class MonitoringPage(BasePage):
    live = True
    title = "Live Network Monitoring"
    subtitle = "Continuous packet capture and traffic analysis (PyShark)"

    def build(self) -> None:
        # -- control bar -----------------------------------------------------
        bar = ttk.Frame(self.body)
        bar.pack(fill=X)
        self._iface_label = ttk.Label(bar, text="Interface: —", font=("Segoe UI", 10))
        self._iface_label.pack(side=LEFT)
        self._start_btn = ttk.Button(bar, text="▶ Start Monitoring",
                                    bootstyle="success", command=self._start)
        self._start_btn.pack(side=RIGHT, padx=4)
        self._stop_btn = ttk.Button(bar, text="■ Stop", bootstyle="danger-outline",
                                   command=self._stop)
        self._stop_btn.pack(side=RIGHT, padx=4)

        if not self.context.monitoring.available:
            ttk.Label(self.body, bootstyle="warning",
                      text="⚠ PyShark/tshark not detected. Install Wireshark and the "
                           "pyshark package to enable live capture.").pack(anchor="w",
                                                                            pady=(8, 0))

        # -- stat cards ------------------------------------------------------
        cards = ttk.Frame(self.body)
        cards.pack(fill=X, pady=(10, 0))
        self._cards = {}
        specs = [
            ("packets", "Total Packets", "primary"),
            ("pps", "Packets / sec", "info"),
            ("bandwidth", "Bandwidth", "secondary"),
            ("avg", "Avg Packet Size", "secondary"),
            ("connections", "Active Connections", "info"),
            ("duration", "Monitoring Time", "primary"),
        ]
        for idx, (key, label, style) in enumerate(specs):
            card = StatCard(cards, label, "0", bootstyle=style)
            card.grid(row=0, column=idx, padx=5, sticky="nsew")
            self._cards[key] = card
        for col in range(len(specs)):
            cards.columnconfigure(col, weight=1)

        # -- charts ----------------------------------------------------------
        charts = ttk.Frame(self.body)
        charts.pack(fill=X, pady=(10, 0))
        charts.columnconfigure(0, weight=2)
        charts.columnconfigure(1, weight=1)
        self._traffic_chart = LineChart(charts, "Traffic (packets/sec)",
                                        series=["Packets/s"])
        self._traffic_chart.grid(row=0, column=0, sticky="nsew", padx=4)
        self._proto_chart = PieChart(charts, "Protocols")
        self._proto_chart.grid(row=0, column=1, sticky="nsew", padx=4)

        # -- recent packets --------------------------------------------------
        table_frame = ttk.Labelframe(self.body, text="Recent Packets", padding=8)
        table_frame.pack(fill=BOTH, expand=YES, pady=(10, 0))
        self._packets = DataTable(
            table_frame,
            columns=["time", "source", "destination", "protocol", "length",
                     "port", "direction", "application"],
            headings=["Time", "Source", "Destination", "Protocol", "Length",
                      "Port", "Direction", "Application"],
            height=12,
        )
        self._packets.pack(fill=BOTH, expand=YES)

    def on_show(self) -> None:
        self._update_iface()
        self.on_refresh()

    def on_refresh(self) -> None:
        mon = self.context.monitoring
        stats = mon.stats_snapshot()
        bw = mon.bandwidth_snapshot()
        self._cards["packets"].set_value(f"{stats.total_packets:,}")
        self._cards["pps"].set_value(f"{stats.packets_per_second:.0f}")
        self._cards["bandwidth"].set_value(
            f"{format_bytes(bw.total_bps)}/s",
            f"↑{format_bytes(bw.upload_bps)}/s ↓{format_bytes(bw.download_bps)}/s")
        self._cards["avg"].set_value(f"{stats.average_packet_size:.0f} B")
        self._cards["connections"].set_value(mon.connections.active_count())
        self._cards["duration"].set_value(format_duration(mon.monitoring_seconds()))

        self._traffic_chart.push({"Packets/s": stats.packets_per_second})
        self._proto_chart.update_distribution({
            "TCP": stats.tcp, "UDP": stats.udp, "ICMP": stats.icmp,
            "HTTP": stats.http, "HTTPS": stats.https, "DNS": stats.dns,
            "Other": stats.other,
        })
        self._render_packets()
        self._update_iface()

    def _render_packets(self) -> None:
        rows = []
        for p in self.context.monitoring.recent_packets(100):
            port = p.destination_port or p.source_port
            rows.append({
                "time": p.timestamp.strftime("%H:%M:%S"),
                "source": p.source_ip or "-",
                "destination": p.destination_ip or "-",
                "protocol": p.protocol,
                "length": p.packet_length,
                "port": port,
                "direction": p.direction,
                "application": p.application,
            })
        self._packets.set_rows(rows)

    def _update_iface(self) -> None:
        mon = self.context.monitoring
        state = "Active" if mon.running else "Stopped"
        self._iface_label.configure(
            text=f"Interface: {mon.interface}    Status: {state}")
        self._start_btn.configure(state="disabled" if mon.running else "normal")
        self._stop_btn.configure(state="normal" if mon.running else "disabled")

    def _start(self) -> None:
        if not self.can("start_monitoring"):
            messagebox.showwarning("Not permitted", "You cannot control monitoring.")
            return
        if self.context.monitoring.start():
            self.context.notify("Monitoring Started",
                                f"Capturing on {self.context.monitoring.interface}", "success")
            from logs.activity_logger import ACTIVITY
            ACTIVITY.monitoring_started(self.context.session.username,
                                        self.context.monitoring.interface)
        else:
            messagebox.showerror("Monitoring", self.context.monitoring.last_error
                                 or "Could not start monitoring.")
        self._update_iface()

    def _stop(self) -> None:
        self.context.monitoring.stop()
        from logs.activity_logger import ACTIVITY
        ACTIVITY.monitoring_stopped(self.context.session.username)
        self.context.notify("Monitoring Stopped", "Packet capture halted.", "info")
        self._update_iface()
