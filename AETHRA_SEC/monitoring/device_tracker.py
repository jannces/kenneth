"""Device discovery from observed traffic.

Builds an in-memory inventory of hosts seen on the wire, enriched with scan
data (open ports / OS / risk) when available, and periodically flushes it to the
``devices`` table.  Hostnames are resolved lazily and cached to avoid blocking
the capture path.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from config import CONFIG
from monitoring.packet_parser import PacketMeta
from utils.helpers import now, resolve_hostname
from utils.validators import is_private_ip


@dataclass
class Device:
    ip_address: str
    mac_address: str = ""
    hostname: str = ""
    vendor: str = ""
    operating_system: str = ""
    first_seen: datetime = field(default_factory=now)
    last_seen: datetime = field(default_factory=now)
    packets_sent: int = 0
    packets_received: int = 0
    open_ports: str = ""
    risk_level: str = "Informational"

    def status(self) -> str:
        idle = (now() - self.last_seen).total_seconds()
        return "Online" if idle < CONFIG.monitoring.device_offline_after else "Offline"


class DeviceTracker:
    """Thread-safe inventory of observed network devices."""

    def __init__(self, database: Optional[Any] = None) -> None:
        self._lock = threading.Lock()
        self._devices: Dict[str, Device] = {}
        self._db = database
        self._resolved: set[str] = set()

    def attach_database(self, database: Any) -> None:
        self._db = database

    def record(self, meta: PacketMeta) -> None:
        for ip, mac, sent in (
            (meta.source_ip, meta.mac_source, True),
            (meta.destination_ip, meta.mac_destination, False),
        ):
            if not ip or ip in ("0.0.0.0", "255.255.255.255") or ip.endswith(".255"):
                continue
            with self._lock:
                dev = self._devices.get(ip)
                if dev is None:
                    dev = Device(ip_address=ip, mac_address=mac or "")
                    self._devices[ip] = dev
                if mac and not dev.mac_address:
                    dev.mac_address = mac
                if sent:
                    dev.packets_sent += 1
                else:
                    dev.packets_received += 1
                dev.last_seen = now()

    def resolve_pending(self, limit: int = 5) -> None:
        """Resolve a few hostnames per tick (called off the capture thread)."""
        with self._lock:
            pending = [ip for ip in self._devices
                       if ip not in self._resolved and is_private_ip(ip)][:limit]
        for ip in pending:
            hostname = resolve_hostname(ip)
            with self._lock:
                self._resolved.add(ip)
                if hostname and ip in self._devices:
                    self._devices[ip].hostname = hostname

    def count_online(self) -> int:
        with self._lock:
            return sum(1 for d in self._devices.values() if d.status() == "Online")

    def count_total(self) -> int:
        with self._lock:
            return len(self._devices)

    def list_devices(self) -> List[Device]:
        with self._lock:
            devices = list(self._devices.values())
        devices.sort(key=lambda d: d.last_seen, reverse=True)
        return devices

    def get_device(self, ip: str) -> Optional[Device]:
        with self._lock:
            return self._devices.get(ip)

    def flush_to_db(self) -> None:
        """Upsert the current inventory into the devices table."""
        if self._db is None:
            return
        for dev in self.list_devices():
            try:
                existing = self._db.query_one(
                    "SELECT id FROM devices WHERE ip_address = %s", (dev.ip_address,)
                )
                if existing:
                    self._db.execute(
                        """UPDATE devices SET mac_address = COALESCE(NULLIF(%s,''), mac_address),
                               hostname = COALESCE(NULLIF(%s,''), hostname),
                               last_seen = %s, status = %s,
                               packets_sent = %s, packets_received = %s
                               WHERE id = %s""",
                        (dev.mac_address, dev.hostname, dev.last_seen, dev.status(),
                         dev.packets_sent, dev.packets_received, existing["id"]),
                        commit=True,
                    )
                else:
                    self._db.execute(
                        """INSERT INTO devices (ip_address, mac_address, hostname,
                               vendor, operating_system, first_seen, last_seen,
                               status, packets_sent, packets_received, open_ports, risk_level)
                               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (dev.ip_address, dev.mac_address, dev.hostname, dev.vendor,
                         dev.operating_system, dev.first_seen, dev.last_seen,
                         dev.status(), dev.packets_sent, dev.packets_received,
                         dev.open_ports, dev.risk_level),
                        commit=True,
                    )
            except Exception:  # noqa: BLE001 - persistence must not crash capture
                continue

    def reset(self) -> None:
        with self._lock:
            self._devices.clear()
            self._resolved.clear()
