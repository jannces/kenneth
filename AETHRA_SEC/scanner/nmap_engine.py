"""Nmap integration via the python-nmap wrapper.

The engine translates a high-level :class:`ScanType` into nmap arguments, runs
the scan, and yields structured results.  It degrades gracefully when either
python-nmap or the nmap binary is unavailable so the rest of the application
(and the test suite) can still import it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from config import CONFIG
from logs.logger import LOG
from utils.constants import ScanType

try:
    import nmap  # python-nmap
    _NMAP_LIB_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    nmap = None  # type: ignore
    _NMAP_LIB_AVAILABLE = False


# Mapping of scan type -> nmap argument string.  These are intentionally
# read-only vulnerability-assessment scans; no exploitation is performed.
SCAN_ARGUMENTS: Dict[str, str] = {
    ScanType.HOST_DISCOVERY.value: "-sn",
    ScanType.QUICK.value: "-T4 -F",
    ScanType.NORMAL.value: "-T4 -sS",
    ScanType.INTENSE.value: "-T4 -A -v",
    ScanType.SERVICE_DETECTION.value: "-T4 -sV",
    ScanType.VERSION_DETECTION.value: "-T4 -sV --version-intensity 5",
    ScanType.OS_DETECTION.value: "-T4 -O",
    ScanType.UDP_SCAN.value: "-T4 -sU --top-ports 50",
    ScanType.TCP_SCAN.value: "-T4 -sT",
    ScanType.CUSTOM.value: "-T4 -sV -O",
}


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""


@dataclass
class HostResult:
    host: str
    hostname: str = ""
    mac_address: str = ""
    vendor: str = ""
    os_guess: str = ""
    status: str = "up"
    latency: str = ""
    ports: List[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanOutcome:
    hosts: List[HostResult] = field(default_factory=list)
    raw_command: str = ""
    error: str = ""

    @property
    def total_hosts(self) -> int:
        return len(self.hosts)

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)


class NmapEngine:
    """Runs nmap scans and returns structured :class:`ScanOutcome` objects."""

    def __init__(self) -> None:
        self._available = _NMAP_LIB_AVAILABLE
        self._scanner = None
        if self._available:
            try:
                self._scanner = nmap.PortScanner(nmap_search_path=(CONFIG.nmap.executable,
                                                                   "nmap",
                                                                   "/usr/bin/nmap",
                                                                   "/usr/local/bin/nmap"))
            except Exception as exc:  # noqa: BLE001 - nmap binary missing
                LOG.error("nmap", "binary_missing",
                          f"python-nmap present but nmap binary not found: {exc}")
                self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def build_arguments(self, scan_type: str) -> str:
        args = SCAN_ARGUMENTS.get(scan_type, SCAN_ARGUMENTS[ScanType.QUICK.value])
        cfg = CONFIG.nmap
        # Respect settings toggles for the richer scan types.
        if scan_type in (ScanType.NORMAL.value, ScanType.TCP_SCAN.value):
            if cfg.service_detection and "-sV" not in args:
                args += " -sV"
            if cfg.os_detection and "-O" not in args:
                args += " -O"
        return args

    def scan(self, target: str, scan_type: str,
             progress_cb: Optional[callable] = None) -> ScanOutcome:
        """Execute a scan synchronously (call from a background thread).

        ``progress_cb`` (optional) receives a status string for the live
        progress panel.
        """
        if not self._available or self._scanner is None:
            return ScanOutcome(
                error="Nmap is not available on this system. Install Nmap and "
                      "python-nmap, then set AETHRA_NMAP_PATH if needed.",
            )

        arguments = self.build_arguments(scan_type)
        if progress_cb:
            progress_cb(f"Starting {scan_type} scan of {target}…")
        LOG.info("nmap", "scan_start", f"{target} args='{arguments}'")

        try:
            self._scanner.scan(hosts=target, arguments=arguments,
                               timeout=CONFIG.nmap.scan_timeout)
        except Exception as exc:  # noqa: BLE001
            LOG.exception("nmap", "scan_error", exc)
            return ScanOutcome(error=str(exc), raw_command=arguments)

        outcome = self._parse(progress_cb)
        outcome.raw_command = getattr(self._scanner, "command_line", lambda: arguments)()
        LOG.info("nmap", "scan_done",
                 f"{target}: {outcome.total_hosts} host(s), "
                 f"{outcome.total_open_ports} open port(s)")
        return outcome

    def _parse(self, progress_cb: Optional[callable] = None) -> ScanOutcome:
        outcome = ScanOutcome()
        for host in self._scanner.all_hosts():
            entry = self._scanner[host]
            if progress_cb:
                progress_cb(f"Parsing results for {host}…")

            host_result = HostResult(host=host)
            host_result.status = entry.state()

            names = entry.get("hostnames") or []
            if names and isinstance(names, list):
                host_result.hostname = names[0].get("name", "")

            if "addresses" in entry and entry["addresses"].get("mac"):
                host_result.mac_address = entry["addresses"]["mac"]
            vendors = entry.get("vendor") or {}
            if vendors:
                host_result.vendor = next(iter(vendors.values()), "")

            osmatch = entry.get("osmatch") or []
            if osmatch:
                host_result.os_guess = osmatch[0].get("name", "")

            # Latency (from nmap's 'uptime'/rtt is not always available).
            host_result.latency = str(entry.get("status", {}).get("reason", ""))

            for proto in entry.all_protocols():
                for port in sorted(entry[proto].keys()):
                    pdata = entry[proto][port]
                    host_result.ports.append(PortResult(
                        port=int(port),
                        protocol=proto,
                        state=pdata.get("state", ""),
                        service=pdata.get("name", ""),
                        product=pdata.get("product", ""),
                        version=pdata.get("version", ""),
                    ))
            outcome.hosts.append(host_result)
        return outcome
