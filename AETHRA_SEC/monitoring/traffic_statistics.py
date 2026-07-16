"""Real-time traffic statistics engine.

Maintains thread-safe cumulative counters and derives per-second rates.  The
monitoring engine feeds it one :class:`PacketMeta` at a time; the GUI reads a
consistent :class:`StatsSnapshot` on its refresh timer.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, Tuple

from monitoring.packet_parser import PacketMeta
from utils.helpers import now


@dataclass
class StatsSnapshot:
    """Immutable view of current statistics for the dashboard."""

    total_packets: int = 0
    total_bytes: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    http: int = 0
    https: int = 0
    dns: int = 0
    ftp: int = 0
    ssh: int = 0
    other: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    average_packet_size: float = 0.0
    largest_packet: int = 0
    smallest_packet: int = 0
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    monitoring_seconds: float = 0.0


class TrafficStatistics:
    """Accumulates packet statistics and computes live rates."""

    # Protocols we surface as first-class counters; everything else -> "other".
    _TRACKED = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "FTP", "SSH"}

    def __init__(self, rate_window: int = 5) -> None:
        self._lock = threading.Lock()
        self._start_time: datetime | None = None
        self._reset_counters()
        # Sliding window of (timestamp, byte_count) for rate calculation.
        self._recent: Deque[Tuple[float, int]] = deque()
        self._rate_window = rate_window

    def _reset_counters(self) -> None:
        self._total_packets = 0
        self._total_bytes = 0
        self._protocol_counts: Dict[str, int] = defaultdict(int)
        self._largest = 0
        self._smallest = 0

    def start(self) -> None:
        with self._lock:
            self._start_time = now()

    def reset(self) -> None:
        with self._lock:
            self._reset_counters()
            self._recent.clear()
            self._start_time = now()

    def record(self, meta: PacketMeta) -> None:
        """Incorporate one packet into the running statistics."""
        with self._lock:
            if self._start_time is None:
                self._start_time = now()
            self._total_packets += 1
            length = max(0, meta.packet_length)
            self._total_bytes += length

            proto = meta.protocol if meta.protocol in self._TRACKED else "Other"
            self._protocol_counts[proto] += 1
            # Also count transport-level so TCP/UDP/ICMP totals stay accurate
            # even when the app protocol (e.g. HTTP) is what was displayed.
            if meta.transport and meta.transport in self._TRACKED and meta.transport != proto:
                self._protocol_counts[meta.transport] += 1

            if length > self._largest:
                self._largest = length
            if self._smallest == 0 or (0 < length < self._smallest):
                self._smallest = length

            ts = meta.timestamp.timestamp() if isinstance(meta.timestamp, datetime) else now().timestamp()
            self._recent.append((ts, length))
            self._trim_window(ts)

    def _trim_window(self, current_ts: float) -> None:
        cutoff = current_ts - self._rate_window
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    def snapshot(self) -> StatsSnapshot:
        """Return a consistent snapshot of the current statistics."""
        with self._lock:
            current = now().timestamp()
            self._trim_window(current)
            window_bytes = sum(b for _, b in self._recent)
            window_packets = len(self._recent)
            span = self._rate_window if self._recent else 1
            pps = window_packets / span
            bps = window_bytes / span
            avg = (self._total_bytes / self._total_packets) if self._total_packets else 0.0
            elapsed = (now() - self._start_time).total_seconds() if self._start_time else 0.0
            counts = dict(self._protocol_counts)
            return StatsSnapshot(
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                tcp=counts.get("TCP", 0),
                udp=counts.get("UDP", 0),
                icmp=counts.get("ICMP", 0),
                http=counts.get("HTTP", 0),
                https=counts.get("HTTPS", 0),
                dns=counts.get("DNS", 0),
                ftp=counts.get("FTP", 0),
                ssh=counts.get("SSH", 0),
                other=counts.get("Other", 0),
                packets_per_second=round(pps, 2),
                bytes_per_second=round(bps, 2),
                average_packet_size=round(avg, 2),
                largest_packet=self._largest,
                smallest_packet=self._smallest,
                protocol_distribution=counts,
                monitoring_seconds=elapsed,
            )
