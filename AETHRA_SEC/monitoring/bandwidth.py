"""Bandwidth monitor.

Tracks upload/download throughput relative to the monitoring host by summing
packet sizes per direction over a short sliding window, and remembers the peak
throughput for the session.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from typing import Deque, Tuple

from monitoring.packet_parser import PacketMeta
from utils.helpers import now


@dataclass
class BandwidthSnapshot:
    upload_bps: float = 0.0
    download_bps: float = 0.0
    total_bps: float = 0.0
    peak_bps: float = 0.0
    average_bps: float = 0.0


class BandwidthMonitor:
    """Computes live upload/download rates from directional packet flow."""

    def __init__(self, window_seconds: int = 3) -> None:
        self._lock = threading.Lock()
        self._window = window_seconds
        # deque of (timestamp, up_bytes, down_bytes)
        self._samples: Deque[Tuple[float, int, int]] = deque()
        self._peak = 0.0
        self._cumulative_bytes = 0
        self._start = now().timestamp()

    def reset(self) -> None:
        with self._lock:
            self._samples.clear()
            self._peak = 0.0
            self._cumulative_bytes = 0
            self._start = now().timestamp()

    def record(self, meta: PacketMeta) -> None:
        with self._lock:
            ts = now().timestamp()
            length = max(0, meta.packet_length)
            self._cumulative_bytes += length
            up = length if meta.direction == "Outgoing" else 0
            down = length if meta.direction == "Incoming" else 0
            self._samples.append((ts, up, down))
            self._trim(ts)

    def _trim(self, current_ts: float) -> None:
        cutoff = current_ts - self._window
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()

    def snapshot(self) -> BandwidthSnapshot:
        with self._lock:
            current = now().timestamp()
            self._trim(current)
            span = self._window if self._samples else 1
            up_bytes = sum(s[1] for s in self._samples)
            down_bytes = sum(s[2] for s in self._samples)
            up_bps = up_bytes / span
            down_bps = down_bytes / span
            total = up_bps + down_bps
            self._peak = max(self._peak, total)
            elapsed = max(1.0, current - self._start)
            average = self._cumulative_bytes / elapsed
            return BandwidthSnapshot(
                upload_bps=round(up_bps, 2),
                download_bps=round(down_bps, 2),
                total_bps=round(total, 2),
                peak_bps=round(self._peak, 2),
                average_bps=round(average, 2),
            )
