"""Snort listener + process control (Alert Socket IPC).

AETHRA-SEC does **not** repeatedly poll ``alert.fast``/``alert.csv`` files.
Instead it opens an Alert Socket and receives alerts in real time.  On Windows
(the target OS) the socket is a TCP loopback endpoint: AETHRA-SEC runs a small
TCP server; Snort's alert output (or a thin one-line forwarder bridging Snort's
output plugin to the socket) connects and streams newline-delimited alert
messages, which are parsed and pushed through the :class:`AlertProcessor`.

The listener:

* Runs on a background daemon thread and never stops listening on its own.
* Auto-recovers (rebinds / re-accepts) if a connection drops or Snort restarts.
* Optionally launches / stops / restarts the Snort process itself.
* Tracks status for the IDS Status Panel.
"""

from __future__ import annotations

import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from config import CONFIG
from ids.alert_parser import parse_alert
from ids.alert_processor import AlertProcessor
from logs.logger import LOG
from utils.helpers import now


class SnortStatus:
    RUNNING = "Running"       # 🟢
    STARTING = "Starting"     # 🟡
    STOPPED = "Stopped"       # 🔴
    DISCONNECTED = "Disconnected"  # ⚪


@dataclass
class ListenerStats:
    status: str = SnortStatus.STOPPED
    last_alert: Optional[datetime] = None
    engine_started: Optional[datetime] = None
    alerts_received: int = 0
    dropped: int = 0
    listening_socket: str = ""
    connected_clients: int = 0


class SnortListener:
    """Background service that receives and processes Snort alerts."""

    def __init__(self, database: Any, processor: Optional[AlertProcessor] = None,
                 notify_cb: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self._db = database
        self.processor = processor or AlertProcessor(database, notify_cb)
        self._cfg = CONFIG.snort

        self._server: Optional[socket.socket] = None
        self._listen_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._snort_proc: Optional[subprocess.Popen] = None

        self.stats = ListenerStats(
            listening_socket=f"{self._cfg.alert_host}:{self._cfg.alert_port}"
        )
        self._client_count = 0

    # --------------------------------------------------------------- listener
    def start_listener(self) -> bool:
        """Begin accepting alert connections on a background thread."""
        with self._lock:
            if self._listen_thread and self._listen_thread.is_alive():
                return True
            self._stop_event.clear()
            self.stats.status = SnortStatus.DISCONNECTED
            self.stats.engine_started = now()
            self._listen_thread = threading.Thread(
                target=self._serve_loop, name="aethra-snort-listener", daemon=True
            )
            self._listen_thread.start()
            LOG.info("snort", "listener_start", self.stats.listening_socket)
            return True

    def stop_listener(self) -> None:
        self._stop_event.set()
        with self._lock:
            self.stats.status = SnortStatus.STOPPED
        try:
            if self._server is not None:
                self._server.close()
        except Exception:  # noqa: BLE001
            pass
        LOG.info("snort", "listener_stop", "Alert listener stopped.")

    def _serve_loop(self) -> None:
        """Bind and accept connections, recovering automatically on failure."""
        while not self._stop_event.is_set():
            try:
                self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._server.settimeout(1.0)
                self._server.bind((self._cfg.alert_host, self._cfg.alert_port))
                self._server.listen(4)
                LOG.info("snort", "listening", self.stats.listening_socket)
                self._accept_loop()
            except OSError as exc:
                self.stats.status = SnortStatus.DISCONNECTED
                LOG.error("snort", "bind_failed",
                          f"{self.stats.listening_socket}: {exc}")
                if self._stop_event.wait(self._cfg.reconnect_delay):
                    break
            finally:
                try:
                    if self._server:
                        self._server.close()
                except Exception:  # noqa: BLE001
                    pass

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                client, addr = self._server.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            self._client_count += 1
            self.stats.connected_clients = self._client_count
            self.stats.status = SnortStatus.RUNNING
            LOG.info("snort", "client_connected", f"{addr[0]}:{addr[1]}")
            handler = threading.Thread(
                target=self._handle_client, args=(client, addr),
                name="aethra-snort-client", daemon=True,
            )
            handler.start()

    def _handle_client(self, client: socket.socket, addr) -> None:
        buffer = b""
        client.settimeout(1.0)
        try:
            while not self._stop_event.is_set():
                try:
                    chunk = client.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buffer += chunk
                # Newline-delimited messages.
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    self._ingest(line.decode("utf-8", errors="replace"))
        finally:
            client.close()
            self._client_count = max(0, self._client_count - 1)
            self.stats.connected_clients = self._client_count
            if self._client_count == 0 and not self._stop_event.is_set():
                self.stats.status = SnortStatus.DISCONNECTED
            LOG.info("snort", "client_disconnected", f"{addr[0]}:{addr[1]}")

    def ingest_line(self, raw: str) -> Optional[Dict[str, Any]]:
        """Public hook to feed a single alert line (used by tests / forwarders)."""
        return self._ingest(raw)

    def _ingest(self, raw: str) -> Optional[Dict[str, Any]]:
        raw = raw.strip()
        if not raw:
            return None
        parsed = parse_alert(raw, interface=CONFIG.monitoring.interface)
        if parsed is None:
            self.stats.dropped += 1
            return None
        self.stats.alerts_received += 1
        self.stats.last_alert = now()
        return self.processor.process(parsed)

    # ------------------------------------------------------- Snort process
    def start_snort(self) -> str:
        """Launch the Snort process (best-effort).  Returns a status message."""
        import os

        if self._snort_proc and self._snort_proc.poll() is None:
            return "Snort is already running."
        if not os.path.exists(self._cfg.executable):
            msg = (f"Snort executable not found at {self._cfg.executable}. "
                   "Configure the path in Settings > Snort.")
            LOG.error("snort", "exe_missing", msg)
            self.stats.status = SnortStatus.STOPPED
            return msg

        self.stats.status = SnortStatus.STARTING
        cmd = [
            self._cfg.executable,
            "-c", self._cfg.config_file,
            "-i", CONFIG.monitoring.interface or "1",
            "-A", "fast",
        ]
        try:
            self._snort_proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self.stats.engine_started = now()
            LOG.info("snort", "process_started", " ".join(cmd))
            return "Snort started."
        except Exception as exc:  # noqa: BLE001
            self.stats.status = SnortStatus.STOPPED
            LOG.exception("snort", "start_failed", exc)
            return f"Failed to start Snort: {exc}"

    def stop_snort(self) -> str:
        if not self._snort_proc or self._snort_proc.poll() is not None:
            return "Snort is not running."
        try:
            self._snort_proc.terminate()
            try:
                self._snort_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._snort_proc.kill()
            LOG.info("snort", "process_stopped", "Snort terminated.")
            return "Snort stopped."
        except Exception as exc:  # noqa: BLE001
            LOG.exception("snort", "stop_failed", exc)
            return f"Failed to stop Snort: {exc}"

    def restart_snort(self) -> str:
        self.stop_snort()
        time.sleep(1)
        return self.start_snort()

    def snort_running(self) -> bool:
        return bool(self._snort_proc and self._snort_proc.poll() is None)

    # ------------------------------------------------------------- status
    def status_snapshot(self) -> Dict[str, Any]:
        alerts_today = self._db.scalar(
            "SELECT COUNT(*) FROM intrusion_alerts WHERE DATE(timestamp) = CURDATE()"
        ) if self._db else 0
        critical = self._db.scalar(
            "SELECT COUNT(*) FROM intrusion_alerts "
            "WHERE severity = 'Critical' AND status = 'Open'"
        ) if self._db else 0
        rules_loaded = self._count_rules()
        uptime = ((now() - self.stats.engine_started).total_seconds()
                  if self.stats.engine_started else 0)
        return {
            "status": self.stats.status,
            "last_alert": self.stats.last_alert,
            "alerts_today": alerts_today or 0,
            "critical_alerts": critical or 0,
            "rules_loaded": rules_loaded,
            "listening_socket": self.stats.listening_socket,
            "engine_uptime": uptime,
            "alerts_received": self.stats.alerts_received,
            "dropped": self.stats.dropped,
            "connected_clients": self.stats.connected_clients,
            "snort_process": self.snort_running(),
        }

    def _count_rules(self) -> int:
        import os
        import glob

        try:
            rules_dir = self._cfg.rules_dir
            if not os.path.isdir(rules_dir):
                return 0
            count = 0
            for path in glob.glob(os.path.join(rules_dir, "*.rules")):
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    count += sum(1 for line in fh
                                 if line.strip() and not line.strip().startswith("#"))
            return count
        except Exception:  # noqa: BLE001
            return 0
