"""Protocol and application-layer classification.

Given transport info (ports/protocol) and any high-level layers PyShark exposes,
infer a human-readable protocol name and a best-effort application label.  When
exact identification is impossible we fall back to the port-derived service
name rather than discarding the packet.
"""

from __future__ import annotations

from typing import Optional

from utils.constants import WELL_KNOWN_PORTS


# Highest-layer protocol names PyShark reports -> canonical protocol label.
_APP_LAYER_MAP = {
    "HTTP": "HTTP", "HTTP2": "HTTP", "OCSP": "HTTP",
    "TLS": "HTTPS", "SSL": "HTTPS",
    "DNS": "DNS", "MDNS": "DNS", "LLMNR": "DNS",
    "DHCP": "DHCP", "BOOTP": "DHCP", "DHCPV6": "DHCP",
    "FTP": "FTP", "FTP-DATA": "FTP",
    "SSH": "SSH", "SMTP": "SMTP", "POP": "POP3", "IMAP": "IMAP",
    "TELNET": "TELNET", "NTP": "NTP", "SMB": "SMB", "SMB2": "SMB",
    "LDAP": "LDAP", "SNMP": "SNMP", "ARP": "ARP", "ICMP": "ICMP",
    "ICMPV6": "ICMPv6", "TCP": "TCP", "UDP": "UDP",
}

# Application inference from destination port -> friendly activity label.
_PORT_ACTIVITY = {
    80: "HTTP Request", 443: "HTTPS Request", 53: "DNS Query",
    22: "SSH Session", 21: "FTP Transfer", 23: "Telnet Session",
    25: "Email (SMTP)", 110: "Email (POP3)", 143: "Email (IMAP)",
    3389: "Remote Desktop", 445: "SMB File Sharing", 139: "SMB File Sharing",
    67: "DHCP", 68: "DHCP", 123: "Time Sync (NTP)", 161: "SNMP",
    389: "Directory (LDAP)", 3306: "MySQL", 5432: "PostgreSQL",
}


def resolve_protocol(highest_layer: str, transport: str,
                     src_port: int, dst_port: int) -> str:
    """Return a canonical protocol label for display and statistics."""
    hl = (highest_layer or "").upper()
    if hl in _APP_LAYER_MAP:
        return _APP_LAYER_MAP[hl]

    # Fall back to well-known ports over the transport protocol.
    for port in (dst_port, src_port):
        svc = WELL_KNOWN_PORTS.get(port)
        if svc:
            return svc

    if transport:
        return transport.upper()
    if hl:
        return hl
    return "Unknown"


def infer_application(protocol: str, src_port: int, dst_port: int,
                      transport: str) -> str:
    """Best-effort application/activity label for the packet table."""
    for port in (dst_port, src_port):
        if port in _PORT_ACTIVITY:
            return _PORT_ACTIVITY[port]
    if protocol in {"HTTP", "HTTPS", "DNS", "SMB", "SSH", "FTP"}:
        return f"{protocol} Traffic"
    if transport:
        return f"{transport.upper()} Traffic"
    return protocol or "Unknown"


def port_service_name(port: int) -> Optional[str]:
    return WELL_KNOWN_PORTS.get(port)
