"""Map Snort alerts into human-understandable threat categories and severity.

Classification is signature/keyword based: the Snort rule message and
classification text are matched against category keyword tables.  Severity is
then derived from Snort priority, the category, and observed frequency.
"""

from __future__ import annotations

from typing import Optional

from utils.constants import Severity, ThreatCategory


# Keyword -> category.  Checked in order; first match wins.
_CATEGORY_KEYWORDS = [
    (("port scan", "portscan", "sfportscan", "nmap", "scan"), ThreatCategory.PORT_SCAN),
    (("brute force", "brute-force", "login", "password", "auth"), ThreatCategory.BRUTE_FORCE),
    (("ssh",), ThreatCategory.SSH_ATTACK),
    (("ftp",), ThreatCategory.FTP_ATTACK),
    (("syn flood", "tcp flood", "syn-flood"), ThreatCategory.TCP_FLOOD),
    (("udp flood", "udp-flood"), ThreatCategory.UDP_FLOOD),
    (("icmp flood", "ping flood", "icmp-flood"), ThreatCategory.ICMP_FLOOD),
    (("dns",), ThreatCategory.DNS_ATTACK),
    (("sql injection", "xss", "web attack", "web-application", "traversal"),
     ThreatCategory.WEB_ATTACK),
    (("http",), ThreatCategory.HTTP_ATTACK),
    (("recon", "reconnaissance", "discovery", "sweep"), ThreatCategory.RECONNAISSANCE),
    (("malformed", "invalid", "bad-traffic", "protocol"), ThreatCategory.MALFORMED_PACKET),
    (("dos", "denial of service", "flood"), ThreatCategory.TCP_FLOOD),
    (("trojan", "malware", "suspicious", "policy"), ThreatCategory.SUSPICIOUS_TRAFFIC),
]

# Category -> baseline severity.
_CATEGORY_SEVERITY = {
    ThreatCategory.PORT_SCAN: Severity.MEDIUM,
    ThreatCategory.BRUTE_FORCE: Severity.HIGH,
    ThreatCategory.TCP_FLOOD: Severity.HIGH,
    ThreatCategory.UDP_FLOOD: Severity.HIGH,
    ThreatCategory.ICMP_FLOOD: Severity.MEDIUM,
    ThreatCategory.HTTP_ATTACK: Severity.HIGH,
    ThreatCategory.DNS_ATTACK: Severity.MEDIUM,
    ThreatCategory.FTP_ATTACK: Severity.HIGH,
    ThreatCategory.SSH_ATTACK: Severity.HIGH,
    ThreatCategory.WEB_ATTACK: Severity.HIGH,
    ThreatCategory.RECONNAISSANCE: Severity.LOW,
    ThreatCategory.SUSPICIOUS_TRAFFIC: Severity.MEDIUM,
    ThreatCategory.MALFORMED_PACKET: Severity.MEDIUM,
    ThreatCategory.UNKNOWN_THREAT: Severity.LOW,
}


def classify_category(message: str, classification: str = "") -> ThreatCategory:
    """Return the best-matching :class:`ThreatCategory` for an alert."""
    haystack = f"{message} {classification}".lower()
    for keywords, category in _CATEGORY_KEYWORDS:
        if any(kw in haystack for kw in keywords):
            return category
    return ThreatCategory.UNKNOWN_THREAT


def classify_severity(category: ThreatCategory, priority: int,
                      occurrences: int = 1) -> Severity:
    """Derive severity from category, Snort priority and repetition.

    Snort priority is 1 (highest) .. 4 (lowest).  We combine that with the
    category baseline and escalate for repeated/flooding occurrences.
    """
    base = _CATEGORY_SEVERITY.get(category, Severity.LOW)

    # Priority-driven floor.
    priority_severity = {
        1: Severity.CRITICAL,
        2: Severity.HIGH,
        3: Severity.MEDIUM,
        4: Severity.LOW,
    }.get(priority, Severity.LOW)

    severity = base if base.rank >= priority_severity.rank else priority_severity

    # Frequency escalation: sustained repetition raises severity a notch.
    if occurrences >= 100:
        severity = _bump(severity, 2)
    elif occurrences >= 20:
        severity = _bump(severity, 1)

    return severity


def _bump(sev: Severity, steps: int) -> Severity:
    order = Severity.order()  # Critical..Informational (descending)
    idx = order.index(sev)
    new_idx = max(0, idx - steps)  # lower index = more severe
    return order[new_idx]
