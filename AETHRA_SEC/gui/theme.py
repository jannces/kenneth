"""Theme + styling helpers shared by the GUI.

Centralises colour tokens, severity styling, and sidebar icons so the look is
consistent across every page and easy to retheme.  Uses ttkbootstrap "bootstyle"
keywords where possible so widgets follow the active theme.
"""

from __future__ import annotations

from utils.constants import SEVERITY_BOOTSTYLE, SEVERITY_COLORS, Severity

# Brand palette (works on the default dark "darkly" theme and light themes).
BRAND_PRIMARY = "#1F3A5F"
BRAND_ACCENT = "#3E7CB1"
SUCCESS = "#2e7d32"
WARNING = "#ed6c02"
DANGER = "#c62828"
INFO = "#0277bd"
MUTED = "#8a8f98"

# Sidebar navigation: (page id, icon, label, admin_only).
NAV_ITEMS = [
    ("dashboard", "🏠", "Dashboard", False),
    ("scanner", "🔍", "Vulnerability Scanner", False),
    ("monitoring", "🌐", "Live Monitoring", False),
    ("connections", "🔗", "Active Connections", False),
    ("alerts", "🚨", "Intrusion Alerts", False),
    ("mitigation", "🛡", "Mitigation Center", False),
    ("logs", "📜", "Logs", False),
    ("reports", "📊", "Reports", False),
    ("users", "👥", "User Management", True),
    ("settings", "⚙", "Settings", True),
    ("help", "❓", "Help", False),
    ("about", "ℹ", "About", False),
]

# Notification level -> (bootstyle, icon).
NOTIFY_STYLES = {
    "info": ("info", "ℹ"),
    "success": ("success", "✅"),
    "warning": ("warning", "⚠"),
    "critical": ("danger", "⛔"),
    "error": ("danger", "⛔"),
}


def severity_bootstyle(severity: str) -> str:
    return SEVERITY_BOOTSTYLE.get(severity, "secondary")


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity, MUTED)


def severity_symbol(severity: str) -> str:
    """A text/emoji marker so severity is not conveyed by colour alone."""
    return {
        Severity.CRITICAL.value: "⛔",
        Severity.HIGH.value: "▲",
        Severity.MEDIUM.value: "◆",
        Severity.LOW.value: "▼",
        Severity.INFORMATIONAL.value: "•",
    }.get(severity, "•")


def status_symbol(status: str) -> str:
    return {
        "Running": "🟢", "Online": "🟢", "Active": "🟢",
        "Starting": "🟡",
        "Stopped": "🔴", "Offline": "🔴",
        "Disconnected": "⚪", "Idle": "⚪",
    }.get(status, "⚪")
