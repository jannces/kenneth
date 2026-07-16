"""Miscellaneous formatting / conversion helpers used across the UI and engines."""

from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timedelta
from typing import Optional


def now() -> datetime:
    """Return the current local time (single call-site for easy testing)."""
    return datetime.now()


def format_timestamp(value: Optional[datetime], fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    if value is None:
        return "-"
    if isinstance(value, str):
        return value
    return value.strftime(fmt)


def format_bytes(num: float) -> str:
    """Human-readable byte size (e.g. ``1.5 MB``)."""
    if num is None:
        return "0 B"
    num = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


def format_rate(bytes_per_sec: float) -> str:
    """Format a throughput value (bytes/second) as ``X.Y MB/s``."""
    return f"{format_bytes(bytes_per_sec)}/s"


def format_duration(seconds: float) -> str:
    """Format a duration in seconds as ``HH:MM:SS`` or ``Xd HH:MM:SS``."""
    if seconds is None or seconds < 0:
        return "00:00:00"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def humanize_number(value: int) -> str:
    """Compact large counters: 1500 -> ``1.5K``."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return "0"
    if abs(value) < 1000:
        return str(value)
    for suffix, threshold in (("B", 1_000_000_000), ("M", 1_000_000), ("K", 1000)):
        if abs(value) >= threshold:
            return f"{value / threshold:.1f}{suffix}"
    return str(value)


def resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    """Best-effort reverse DNS lookup; returns ``""`` on failure/timeout."""
    if not ip:
        return ""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


def classify_ip_direction(src: str, dst: str, local_ips: set[str]) -> str:
    """Classify a packet's direction relative to the monitoring host."""
    try:
        dst_addr = ipaddress.ip_address(dst) if dst else None
    except ValueError:
        dst_addr = None

    if dst_addr is not None:
        if dst_addr.is_multicast:
            return "Multicast"
        if dst == "255.255.255.255" or (dst.endswith(".255")):
            return "Broadcast"
        if dst_addr.is_loopback:
            return "Loopback"

    src_local = src in local_ips
    dst_local = dst in local_ips
    if src_local and dst_local:
        return "Local"
    if src_local and not dst_local:
        return "Outgoing"
    if dst_local and not src_local:
        return "Incoming"
    return "External"


def truncate(text: str, length: int = 60) -> str:
    text = text or ""
    return text if len(text) <= length else text[: length - 1] + "…"


def safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def start_of_day(dt: Optional[datetime] = None) -> datetime:
    dt = dt or now()
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def days_ago(days: int) -> datetime:
    return now() - timedelta(days=days)
