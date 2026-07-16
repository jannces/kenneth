"""Transform raw Nmap output into risk-assessed, database-ready records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from scanner.nmap_engine import HostResult, ScanOutcome
from scanner.vulnerability_mapper import assess_host, assess_port, PortRisk
from utils.constants import Severity


@dataclass
class AssessedPort:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    risk: str
    reason: str
    recommendation_available: bool
    related_threat: str


@dataclass
class AssessedHost:
    host: str
    hostname: str
    mac_address: str
    vendor: str
    os_guess: str
    status: str
    risk: str
    ports: List[AssessedPort] = field(default_factory=list)

    @property
    def open_port_count(self) -> int:
        return sum(1 for p in self.ports if p.state == "open")


@dataclass
class AssessedScan:
    hosts: List[AssessedHost] = field(default_factory=list)

    @property
    def total_hosts(self) -> int:
        return len(self.hosts)

    @property
    def total_open_ports(self) -> int:
        return sum(h.open_port_count for h in self.hosts)

    @property
    def highest_risk(self) -> str:
        if not self.hosts:
            return Severity.INFORMATIONAL.value
        return max((Severity(h.risk) for h in self.hosts),
                   key=lambda s: s.rank).value


def assess_outcome(outcome: ScanOutcome) -> AssessedScan:
    """Attach risk levels to every host/port in a :class:`ScanOutcome`."""
    scan = AssessedScan()
    for host in outcome.hosts:
        scan.hosts.append(_assess_host(host))
    return scan


def _assess_host(host: HostResult) -> AssessedHost:
    assessed_ports: List[AssessedPort] = []
    risks: List[PortRisk] = []
    for port in host.ports:
        risk = assess_port(port.port, port.service, port.state, port.version)
        risks.append(risk)
        assessed_ports.append(AssessedPort(
            port=port.port,
            protocol=port.protocol,
            state=port.state,
            service=port.service,
            product=port.product,
            version=port.version,
            risk=risk.severity.value,
            reason=risk.reason,
            recommendation_available=risk.recommendation_available,
            related_threat=risk.related_threat or "",
        ))
    open_ports = sum(1 for p in host.ports if p.state == "open")
    host_risk = assess_host([r for r, p in zip(risks, host.ports) if p.state == "open"],
                            open_ports)
    return AssessedHost(
        host=host.host,
        hostname=host.hostname,
        mac_address=host.mac_address,
        vendor=host.vendor,
        os_guess=host.os_guess,
        status=host.status,
        risk=host_risk.value,
        ports=assessed_ports,
    )


def to_db_rows(scan_id: int, scan: AssessedScan) -> List[Dict[str, Any]]:
    """Flatten an assessed scan into ``scan_results`` insert dicts.

    Hosts with no ports still get a single summary row so host discovery scans
    are represented.
    """
    rows: List[Dict[str, Any]] = []
    for host in scan.hosts:
        if not host.ports:
            rows.append({
                "scan_id": scan_id, "host": host.host, "hostname": host.hostname,
                "mac_address": host.mac_address, "vendor": host.vendor,
                "os_guess": host.os_guess, "port": 0, "protocol": "",
                "service": "", "product": "", "version": "", "state": host.status,
                "risk_level": host.risk, "cve_reference": "",
                "description": "Host discovered (no port details).",
            })
            continue
        for port in host.ports:
            rows.append({
                "scan_id": scan_id, "host": host.host, "hostname": host.hostname,
                "mac_address": host.mac_address, "vendor": host.vendor,
                "os_guess": host.os_guess, "port": port.port,
                "protocol": port.protocol, "service": port.service,
                "product": port.product, "version": port.version,
                "state": port.state, "risk_level": port.risk,
                "cve_reference": "", "description": port.reason,
            })
    return rows
