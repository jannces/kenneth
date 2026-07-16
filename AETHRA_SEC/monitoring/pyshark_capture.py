"""Live packet capture and the top-level Monitoring Engine.

The :class:`MonitoringEngine` owns every monitoring component (statistics,
bandwidth, connections, devices) and runs the PyShark capture loop on a
background daemon thread.  It exposes thread-safe snapshot accessors the GUI
polls on its refresh timer, plus a *packet subscriber* hook so the IDS /
correlation layer can observe the same stream.

Capture runs until explicitly stopped or the application closes.  If capture
fails it is automatically restarted (bounded retries) to satisfy the
Availability requirement, and the engine never raises into the GUI.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional

from config import CONFIG
from logs.logger import LOG
from monitoring.bandwidth import BandwidthMonitor, BandwidthSnapshot
from monitoring.connection_tracker import ConnectionTracker
from monitoring.device_tracker import DeviceTracker
from monitoring.packet_parser import PacketMeta, parse_packet
from monitoring.traffic_statistics import StatsSnapshot, TrafficStatistics
from utils.helpers import now

try:
    import pyshark
    _PYSHARK_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    pyshark = None  # type: ignore
    _PYSHARK_AVAILABLE = False

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    _PSUTIL_AVAILABLE = False


@dataclass
class InterfaceInfo:
    name: str
    description: str = ""
    ip_address: str = ""
    status: str = "unknown"
    speed: str = ""


def list_interfaces() -> List[InterfaceInfo]:
    """Enumerate capture-capable network interfaces.

    Uses psutil for rich metadata (IP/status/speed) and falls back to a plain
    list from tshark if psutil is unavailable.
    """
    interfaces: List[InterfaceInfo] = []
    if _PSUTIL_AVAILABLE:
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for name, addr_list in addrs.items():
                ipv4 = next((a.address for a in addr_list
                             if getattr(a, "family", None) and "AF_INET" in str(a.family)
                             and ":" not in a.address), "")
                st = stats.get(name)
                interfaces.append(InterfaceInfo(
                    name=name,
                    description=name,
                    ip_address=ipv4,
                    status="Up" if (st and st.isup) else "Down",
                    speed=f"{st.speed} Mb/s" if (st and st.speed) else "",
                ))
        except Exception as exc:  # noqa: BLE001
            LOG.error("monitor", "iface_enum_failed", str(exc))
    if not interfaces and _PYSHARK_AVAILABLE:
        try:
            names = pyshark.LiveCapture().interfaces  # type: ignore[attr-defined]
            interfaces = [InterfaceInfo(name=n, description=n) for n in names]
        except Exception as exc:  # noqa: BLE001
            LOG.error("monitor", "tshark_iface_failed", str(exc))
    return interfaces


class MonitoringEngine:
    """Continuous packet-capture engine feeding all monitoring components."""

    _MAX_RECENT_PACKETS = 500
    _MAX_RESTART_ATTEMPTS = 5

    def __init__(self, database: Optional[Any] = None) -> None:
        self._db = database
        self.statistics = TrafficStatistics()
        self.bandwidth = BandwidthMonitor()
        self.connections = ConnectionTracker()
        self.devices = DeviceTracker(database)

        self._capture_thread: Optional[threading.Thread] = None
        self._maintenance_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        self._lock = threading.Lock()

        self._recent: Deque[PacketMeta] = deque(maxlen=self._MAX_RECENT_PACKETS)
        self._persist_buffer: List[tuple] = []
        self._subscribers: List[Callable[[PacketMeta], None]] = []
        self._local_ips: set[str] = self._discover_local_ips()

        self._interface: str = CONFIG.monitoring.interface
        self._start_time: Optional[float] = None
        self._capture = None
        self._error: str = ""

    # ------------------------------------------------------------- properties
    @property
    def available(self) -> bool:
        return _PYSHARK_AVAILABLE

    @property
    def running(self) -> bool:
        return self._running

    @property
    def interface(self) -> str:
        return self._interface or "auto"

    @property
    def last_error(self) -> str:
        return self._error

    def attach_database(self, database: Any) -> None:
        self._db = database
        self.devices.attach_database(database)

    def subscribe(self, callback: Callable[[PacketMeta], None]) -> None:
        """Register a packet observer (e.g. the IDS correlation layer)."""
        self._subscribers.append(callback)

    def monitoring_seconds(self) -> float:
        return (time.time() - self._start_time) if self._start_time else 0.0

    # --------------------------------------------------------------- control
    def start(self, interface: Optional[str] = None) -> bool:
        """Start capture on a background thread.  Returns True if it launched."""
        with self._lock:
            if self._running:
                return True
            if not _PYSHARK_AVAILABLE:
                self._error = ("PyShark/tshark not available. Install Wireshark and "
                               "the pyshark package to enable live monitoring.")
                LOG.error("monitor", "unavailable", self._error)
                return False
            self._interface = interface or CONFIG.monitoring.interface or self._auto_interface()
            self._stop_event.clear()
            self.statistics.start()
            self.bandwidth.reset()
            self._start_time = time.time()
            self._running = True
            self._error = ""

            self._capture_thread = threading.Thread(
                target=self._capture_loop, name="aethra-capture", daemon=True
            )
            self._maintenance_thread = threading.Thread(
                target=self._maintenance_loop, name="aethra-monitor-maint", daemon=True
            )
            self._capture_thread.start()
            self._maintenance_thread.start()
            LOG.info("monitor", "started", f"interface={self._interface}")
            return True

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stop_event.set()
        # Close the underlying capture if possible.
        try:
            if self._capture is not None:
                self._capture.close()
        except Exception:  # noqa: BLE001
            pass
        self._flush_persist_buffer()
        LOG.info("monitor", "stopped", "Monitoring engine stopped.")

    # ---------------------------------------------------------- capture loop
    def _capture_loop(self) -> None:
        attempts = 0
        while not self._stop_event.is_set() and attempts < self._MAX_RESTART_ATTEMPTS:
            try:
                self._run_capture()
                if self._stop_event.is_set():
                    break
            except Exception as exc:  # noqa: BLE001
                attempts += 1
                self._error = str(exc)
                LOG.exception("monitor", "capture_restart", exc)
                if self._stop_event.wait(3):
                    break
        if attempts >= self._MAX_RESTART_ATTEMPTS and not self._stop_event.is_set():
            LOG.error("monitor", "capture_gaveup",
                      "Capture failed repeatedly; monitoring paused.")
            self._running = False

    def _run_capture(self) -> None:
        kwargs: Dict[str, Any] = {}
        if self._interface and self._interface != "auto":
            kwargs["interface"] = self._interface
        if CONFIG.monitoring.capture_filter:
            kwargs["bpf_filter"] = CONFIG.monitoring.capture_filter

        self._capture = pyshark.LiveCapture(**kwargs)
        LOG.info("monitor", "capture_open", f"iface={self._interface}")
        for packet in self._capture.sniff_continuously():
            if self._stop_event.is_set():
                break
            meta = parse_packet(packet, self._local_ips)
            if meta is not None:
                self._process(meta)

    def _process(self, meta: PacketMeta) -> None:
        self.statistics.record(meta)
        self.bandwidth.record(meta)
        self.connections.record(meta)
        self.devices.record(meta)
        with self._lock:
            self._recent.append(meta)
            self._persist_buffer.append(meta.as_row())
        # Fan out to subscribers (IDS correlation) - isolate failures.
        for cb in self._subscribers:
            try:
                cb(meta)
            except Exception:  # noqa: BLE001
                continue
        if len(self._persist_buffer) >= CONFIG.monitoring.persist_batch_size:
            self._flush_persist_buffer()

    # ------------------------------------------------------- maintenance loop
    def _maintenance_loop(self) -> None:
        """Runs once per second: prune connections, persist stats, flush devices."""
        tick = 0
        while not self._stop_event.wait(1.0):
            tick += 1
            try:
                self.connections.prune()
                self._persist_traffic_stats()
                self.devices.resolve_pending()
                if tick % 10 == 0:  # every ~10s
                    self.devices.flush_to_db()
                    self._flush_persist_buffer()
            except Exception as exc:  # noqa: BLE001
                LOG.error("monitor", "maintenance_error", str(exc))

    def _persist_traffic_stats(self) -> None:
        if self._db is None:
            return
        snap = self.statistics.snapshot()
        try:
            self._db.execute(
                """INSERT INTO traffic_statistics
                       (timestamp, packets_per_second, bytes_per_second,
                        active_connections, tcp_count, udp_count, icmp_count,
                        http_count, https_count, dns_count)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (now(), snap.packets_per_second, snap.bytes_per_second,
                 self.connections.active_count(), snap.tcp, snap.udp, snap.icmp,
                 snap.http, snap.https, snap.dns),
                commit=True,
            )
        except Exception:  # noqa: BLE001
            pass

    def _flush_persist_buffer(self) -> None:
        if self._db is None:
            with self._lock:
                self._persist_buffer.clear()
            return
        with self._lock:
            if not self._persist_buffer:
                return
            batch = self._persist_buffer
            self._persist_buffer = []
        try:
            self._db.executemany(
                """INSERT INTO live_packets
                       (timestamp, source_ip, destination_ip, source_port,
                        destination_port, protocol, transport, application,
                        packet_length, ttl, tcp_flags, mac_source,
                        mac_destination, direction)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                batch, commit=True,
            )
        except Exception as exc:  # noqa: BLE001
            LOG.error("monitor", "packet_persist_failed", str(exc))

    # ------------------------------------------------------------- snapshots
    def stats_snapshot(self) -> StatsSnapshot:
        return self.statistics.snapshot()

    def bandwidth_snapshot(self) -> BandwidthSnapshot:
        return self.bandwidth.snapshot()

    def recent_packets(self, limit: int = 100) -> List[PacketMeta]:
        with self._lock:
            packets = list(self._recent)
        return packets[-limit:][::-1]

    # ------------------------------------------------------------- internals
    @staticmethod
    def _discover_local_ips() -> set[str]:
        ips: set[str] = {"127.0.0.1", "::1"}
        if _PSUTIL_AVAILABLE:
            try:
                for addr_list in psutil.net_if_addrs().values():
                    for addr in addr_list:
                        if getattr(addr, "family", None) and "AF_INET" in str(addr.family):
                            ips.add(addr.address)
            except Exception:  # noqa: BLE001
                pass
        return ips

    def _auto_interface(self) -> str:
        """Pick a sensible default interface (first non-loopback that is up)."""
        for iface in list_interfaces():
            if iface.status == "Up" and iface.ip_address and not iface.ip_address.startswith("127."):
                return iface.name
        ifaces = list_interfaces()
        return ifaces[0].name if ifaces else "auto"
