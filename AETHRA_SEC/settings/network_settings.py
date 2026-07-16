"""Network / monitoring interface helpers for the Settings page."""

from __future__ import annotations

from typing import Any, Dict, List

from monitoring.pyshark_capture import InterfaceInfo, list_interfaces
from settings.settings import SettingsService


class NetworkSettings:
    """Exposes available capture interfaces and persists the chosen one."""

    def __init__(self, settings: SettingsService) -> None:
        self._settings = settings

    def available_interfaces(self) -> List[InterfaceInfo]:
        return list_interfaces()

    def interface_table(self) -> List[Dict[str, Any]]:
        """Rows for the interface selection widget."""
        rows = []
        for iface in self.available_interfaces():
            rows.append({
                "name": iface.name,
                "description": iface.description,
                "ip_address": iface.ip_address,
                "status": iface.status,
                "speed": iface.speed,
            })
        return rows

    def get_selected(self) -> str:
        return self._settings.get("capture_interface", "")

    def set_selected(self, interface: str, actor: str = "system") -> None:
        self._settings.set("capture_interface", interface, actor)
        self._settings.apply_to_config()
