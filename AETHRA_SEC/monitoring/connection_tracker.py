"""Active connection (conversation) tracker.

Maintains a live table of network conversations keyed by the canonical
5-tuple (endpoints + protocol).  Idle conversations are aged out after the
configured timeout so the Active Connections page reflects only current flows.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List

from config import CONFIG
from monitoring.packet_parser import PacketMeta
from utils.helpers import now


@dataclass
class Connection:
    source: str
    destination: str
    protocol: str
    source_port: int = 0
    destination_port: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    first_seen: datetime = field(default_factory=now)
    last_activity: datetime = field(default_factory=now)

    @property
    def duration_seconds(self) -> float:
        return (self.last_activity - self.first_seen).total_seconds()

    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received

    def status(self, timeout: int) -> str:
        idle = (now() - self.last_activity).total_seconds()
        return "Active" if idle < timeout / 2 else "Idle"


class ConnectionTracker:
    """Thread-safe map of active conversations."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._connections: Dict[str, Connection] = {}

    @staticmethod
    def _key(a_ip: str, a_port: int, b_ip: str, b_port: int, proto: str) -> str:
        """Direction-independent conversation key."""
        end_a = (a_ip, a_port)
        end_b = (b_ip, b_port)
        low, high = sorted([end_a, end_b])
        return f"{low[0]}:{low[1]}|{high[0]}:{high[1]}|{proto}"

    def record(self, meta: PacketMeta) -> None:
        if not meta.source_ip or not meta.destination_ip:
            return
        key = self._key(meta.source_ip, meta.source_port,
                        meta.destination_ip, meta.destination_port, meta.transport)
        with self._lock:
            conn = self._connections.get(key)
            if conn is None:
                conn = Connection(
                    source=meta.source_ip,
                    destination=meta.destination_ip,
                    protocol=meta.protocol,
                    source_port=meta.source_port,
                    destination_port=meta.destination_port,
                )
                self._connections[key] = conn
            # Attribute direction relative to the stored 'source'.
            if meta.source_ip == conn.source:
                conn.packets_sent += 1
                conn.bytes_sent += meta.packet_length
            else:
                conn.packets_received += 1
                conn.bytes_received += meta.packet_length
            conn.last_activity = now()

    def prune(self) -> None:
        """Drop conversations idle beyond the configured timeout."""
        timeout = CONFIG.monitoring.connection_timeout
        cutoff = now()
        with self._lock:
            stale = [
                key for key, c in self._connections.items()
                if (cutoff - c.last_activity).total_seconds() > timeout
            ]
            for key in stale:
                del self._connections[key]

    def active_count(self) -> int:
        with self._lock:
            return len(self._connections)

    def list_connections(self) -> List[Connection]:
        timeout = CONFIG.monitoring.connection_timeout
        with self._lock:
            conns = list(self._connections.values())
        conns.sort(key=lambda c: c.last_activity, reverse=True)
        return conns

    def reset(self) -> None:
        with self._lock:
            self._connections.clear()
