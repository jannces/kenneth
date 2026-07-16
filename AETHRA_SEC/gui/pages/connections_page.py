"""Active Connections page - live network conversations."""

from __future__ import annotations

from tkinter import messagebox

from ttkbootstrap.constants import BOTH, YES

from gui.data_table import DataTable
from gui.pages.base_page import BasePage
from utils.helpers import format_bytes, format_duration


class ConnectionsPage(BasePage):
    live = True
    title = "Active Connections"
    subtitle = "Live network conversations tracked from captured traffic"

    def build(self) -> None:
        self._table = DataTable(
            self.body,
            columns=["source", "destination", "protocol", "packets", "bytes",
                     "duration", "status", "last_activity"],
            headings=["Source", "Destination", "Protocol", "Packets", "Bytes",
                      "Duration", "Status", "Last Activity"],
            on_double_click=self._show_details,
            height=20,
        )
        self._table.pack(fill=BOTH, expand=YES)

    def on_show(self) -> None:
        self.on_refresh()

    def on_refresh(self) -> None:
        from config import CONFIG
        timeout = CONFIG.monitoring.connection_timeout
        rows = []
        for c in self.context.monitoring.connections.list_connections():
            src = f"{c.source}:{c.source_port}" if c.source_port else c.source
            dst = f"{c.destination}:{c.destination_port}" if c.destination_port else c.destination
            rows.append({
                "source": src,
                "destination": dst,
                "protocol": c.protocol,
                "packets": c.total_packets,
                "bytes": format_bytes(c.total_bytes),
                "duration": format_duration(c.duration_seconds),
                "status": c.status(timeout),
                "last_activity": c.last_activity.strftime("%H:%M:%S"),
                "_raw": c,
            })
        self._table.set_rows(rows)

    def _show_details(self, row) -> None:
        c = row.get("_raw")
        if not c:
            return
        detail = (
            f"Source: {c.source}:{c.source_port}\n"
            f"Destination: {c.destination}:{c.destination_port}\n"
            f"Protocol: {c.protocol}\n\n"
            f"Packets sent: {c.packets_sent}\n"
            f"Packets received: {c.packets_received}\n"
            f"Bytes sent: {format_bytes(c.bytes_sent)}\n"
            f"Bytes received: {format_bytes(c.bytes_received)}\n"
            f"Duration: {format_duration(c.duration_seconds)}\n"
            f"First seen: {c.first_seen.strftime('%H:%M:%S')}\n"
            f"Last activity: {c.last_activity.strftime('%H:%M:%S')}"
        )
        messagebox.showinfo("Conversation statistics", detail)
