"""Application-wide constants shared by every layer of AETHRA-SEC.

Keeping these in one place avoids magic strings scattered through the code and
gives a single source of truth for roles, severities, statuses, colour codes,
and the well-known port/protocol tables used by the monitoring and scanning
engines.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List


# ---------------------------------------------------------------------------
# Roles & RBAC
# ---------------------------------------------------------------------------
class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"


class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"


# ---------------------------------------------------------------------------
# Severity model (shared by scans, alerts and mitigation)
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

    @classmethod
    def order(cls) -> List["Severity"]:
        return [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFORMATIONAL]

    @property
    def rank(self) -> int:
        """Higher number = more severe (useful for ``max`` comparisons)."""
        return {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


# Severity colours (bootstrap-style names + hex) - never rely on colour alone,
# the UI also renders a text label / icon.
SEVERITY_COLORS: Dict[str, str] = {
    Severity.CRITICAL.value: "#d9534f",      # red
    Severity.HIGH.value: "#f0ad4e",          # orange
    Severity.MEDIUM.value: "#f7d154",        # yellow
    Severity.LOW.value: "#5bc0de",           # blue
    Severity.INFORMATIONAL.value: "#9e9e9e",  # gray
}

SEVERITY_BOOTSTYLE: Dict[str, str] = {
    Severity.CRITICAL.value: "danger",
    Severity.HIGH.value: "warning",
    Severity.MEDIUM.value: "warning",
    Severity.LOW.value: "info",
    Severity.INFORMATIONAL.value: "secondary",
}

SUCCESS_COLOR = "#5cb85c"  # green


# ---------------------------------------------------------------------------
# Alert / threat lifecycle
# ---------------------------------------------------------------------------
class AlertStatus(str, Enum):
    OPEN = "Open"
    ACKNOWLEDGED = "Acknowledged"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"


class ThreatCategory(str, Enum):
    PORT_SCAN = "Port Scan"
    BRUTE_FORCE = "Brute Force"
    TCP_FLOOD = "TCP Flood"
    UDP_FLOOD = "UDP Flood"
    ICMP_FLOOD = "ICMP Flood"
    HTTP_ATTACK = "HTTP Attack"
    DNS_ATTACK = "DNS Attack"
    FTP_ATTACK = "FTP Attack"
    SSH_ATTACK = "SSH Attack"
    SUSPICIOUS_TRAFFIC = "Suspicious Traffic"
    RECONNAISSANCE = "Reconnaissance"
    MALFORMED_PACKET = "Malformed Packet"
    WEB_ATTACK = "Web Attack"
    UNKNOWN_THREAT = "Unknown Threat"


# ---------------------------------------------------------------------------
# Scan types (mapped to nmap arguments in scanner.nmap_engine)
# ---------------------------------------------------------------------------
class ScanType(str, Enum):
    HOST_DISCOVERY = "host_discovery"
    QUICK = "quick"
    NORMAL = "normal"
    INTENSE = "intense"
    SERVICE_DETECTION = "service_detection"
    VERSION_DETECTION = "version_detection"
    OS_DETECTION = "os_detection"
    UDP_SCAN = "udp_scan"
    TCP_SCAN = "tcp_scan"
    CUSTOM = "custom"


SCAN_TYPE_LABELS: Dict[str, str] = {
    ScanType.HOST_DISCOVERY.value: "Host Discovery",
    ScanType.QUICK.value: "Quick Scan",
    ScanType.NORMAL.value: "Normal Scan",
    ScanType.INTENSE.value: "Intense Scan",
    ScanType.SERVICE_DETECTION.value: "Service Detection",
    ScanType.VERSION_DETECTION.value: "Version Detection",
    ScanType.OS_DETECTION.value: "OS Detection",
    ScanType.UDP_SCAN.value: "UDP Scan",
    ScanType.TCP_SCAN.value: "TCP Scan",
    ScanType.CUSTOM.value: "Custom Scan",
}


# ---------------------------------------------------------------------------
# Well-known ports -> service names (used for application inference)
# ---------------------------------------------------------------------------
WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC", 137: "NETBIOS",
    138: "NETBIOS", 139: "NETBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "ORACLE", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL",
    5900: "VNC", 5985: "WINRM", 6379: "REDIS", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MONGODB",
}

# Ports considered sensitive when exposed (feeds risk classification).
HIGH_RISK_PORTS = {23, 21, 3389, 445, 139, 135, 5900, 512, 513, 514}
REMOTE_ADMIN_PORTS = {22, 23, 3389, 5900, 5985}
INSECURE_PROTOCOL_PORTS = {21, 23, 25, 110, 143, 80, 69}


# Transport-layer protocol numbers.
IP_PROTO_NAMES: Dict[int, str] = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 58: "ICMPv6",
    89: "OSPF", 132: "SCTP",
}


# ---------------------------------------------------------------------------
# Logging severities for system_logs
# ---------------------------------------------------------------------------
class LogLevel(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    DEBUG = "DEBUG"


# Navigation identifiers for the GUI router.
class Page(str, Enum):
    DASHBOARD = "dashboard"
    SCANNER = "scanner"
    MONITORING = "monitoring"
    CONNECTIONS = "connections"
    ALERTS = "alerts"
    MITIGATION = "mitigation"
    LOGS = "logs"
    REPORTS = "reports"
    USERS = "users"
    SETTINGS = "settings"
    HELP = "help"
    ABOUT = "about"


# Feature -> permission key mapping consumed by authentication.permissions.
PERMISSIONS: Dict[str, Dict[str, bool]] = {
    Role.ADMIN.value: {
        "view_dashboard": True, "run_scan": True, "start_monitoring": True,
        "view_alerts": True, "manage_alert_status": True, "view_reports": True,
        "generate_report": True, "view_logs": True, "view_all_logs": True,
        "manage_users": True, "manage_settings": True, "manage_mitigation": True,
        "configure_snort": True, "configure_nmap": True, "delete_records": True,
    },
    Role.USER.value: {
        "view_dashboard": True, "run_scan": True, "start_monitoring": True,
        "view_alerts": True, "manage_alert_status": False, "view_reports": True,
        "generate_report": True, "view_logs": True, "view_all_logs": False,
        "manage_users": False, "manage_settings": False, "manage_mitigation": False,
        "configure_snort": False, "configure_nmap": False, "delete_records": False,
    },
}
