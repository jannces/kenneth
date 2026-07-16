"""Parse Snort alerts received over the Alert Socket into structured objects.

AETHRA-SEC listens on a socket rather than tailing alert files.  Two on-the-wire
formats are accepted so the platform works with common Snort output plugins:

1. **JSON** - one JSON object per message (preferred, fully structured). This is
   what Snort 3's ``alert_json`` output produces, and what a thin forwarder can
   emit.
2. **Fast text** - the classic Snort ``alert_fast`` single-line format, e.g.::

     06/12-10:15:03.123456 [**] [1:1000001:0] SSH brute force [**]
     [Classification: Attempted Admin] [Priority: 1] {TCP} 10.0.0.9:5512 -> 10.0.0.1:22

Both are converted into a :class:`ParsedAlert` with the same fields, so the rest
of the pipeline is format-agnostic.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from utils.helpers import now

# Regex for the classic alert_fast single-line format.
_FAST_RE = re.compile(
    r"(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)?\s*"
    r"\[\*\*\]\s*"
    r"(?:\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*)?"
    r"(?P<msg>.*?)\s*\[\*\*\]"
    r"(?:.*?\[Classification:\s*(?P<cls>[^\]]+)\])?"
    r"(?:.*?\[Priority:\s*(?P<pri>\d+)\])?"
    r"(?:.*?\{(?P<proto>\w+)\})?"
    r"(?:\s*(?P<src>[0-9a-fA-F:.]+?)(?::(?P<sport>\d+))?\s*->\s*"
    r"(?P<dst>[0-9a-fA-F:.]+?)(?::(?P<dport>\d+))?)?\s*$",
    re.DOTALL,
)


@dataclass
class ParsedAlert:
    """A normalised Snort alert."""

    timestamp: datetime = field(default_factory=now)
    sid: str = ""
    gid: str = ""
    rev: str = ""
    message: str = ""
    classification: str = ""
    priority: int = 3
    protocol: str = ""
    source_ip: str = ""
    source_port: int = 0
    destination_ip: str = ""
    destination_port: int = 0
    interface: str = ""
    raw: str = ""

    @property
    def rule_id(self) -> str:
        if self.gid and self.sid:
            return f"{self.gid}:{self.sid}:{self.rev or 0}"
        return self.sid or ""


def _to_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_alert(raw: str, interface: str = "") -> Optional[ParsedAlert]:
    """Parse a single raw alert message (JSON or fast text)."""
    raw = (raw or "").strip()
    if not raw:
        return None

    # Try JSON first.
    if raw.startswith("{"):
        parsed = _parse_json(raw)
        if parsed is not None:
            parsed.interface = interface or parsed.interface
            parsed.raw = raw
            return parsed

    # Fall back to fast text.
    parsed = _parse_fast(raw)
    if parsed is not None:
        parsed.interface = interface or parsed.interface
        parsed.raw = raw
    return parsed


def _parse_json(raw: str) -> Optional[ParsedAlert]:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    alert = ParsedAlert()
    alert.sid = str(obj.get("sid", obj.get("rule", "")))
    alert.gid = str(obj.get("gid", ""))
    alert.rev = str(obj.get("rev", ""))
    alert.message = obj.get("msg", obj.get("message", "")) or ""
    alert.classification = obj.get("class", obj.get("classification", "")) or ""
    alert.priority = _to_int(obj.get("priority", obj.get("pri", 3)), 3)
    alert.protocol = (obj.get("proto", obj.get("protocol", "")) or "").upper()
    alert.source_ip = obj.get("src_addr", obj.get("src_ip", obj.get("src", ""))) or ""
    alert.destination_ip = obj.get("dst_addr", obj.get("dst_ip", obj.get("dst", ""))) or ""
    alert.source_port = _to_int(obj.get("src_port", obj.get("sport", 0)))
    alert.destination_port = _to_int(obj.get("dst_port", obj.get("dport", 0)))
    alert.interface = obj.get("interface", obj.get("iface", "")) or ""
    ts = obj.get("timestamp", obj.get("ts"))
    if ts:
        alert.timestamp = _parse_timestamp(str(ts))
    return alert


def _parse_fast(raw: str) -> Optional[ParsedAlert]:
    match = _FAST_RE.search(raw)
    if not match or not (match.group("msg") or "").strip():
        # Not a recognisable alert line.
        return None
    g = match.groupdict()
    alert = ParsedAlert()
    alert.sid = g.get("sid") or ""
    alert.gid = g.get("gid") or ""
    alert.rev = g.get("rev") or ""
    alert.message = (g.get("msg") or "").strip()
    alert.classification = (g.get("cls") or "").strip()
    alert.priority = _to_int(g.get("pri"), 3)
    alert.protocol = (g.get("proto") or "").upper()
    alert.source_ip = g.get("src") or ""
    alert.destination_ip = g.get("dst") or ""
    alert.source_port = _to_int(g.get("sport"))
    alert.destination_port = _to_int(g.get("dport"))
    if g.get("ts"):
        alert.timestamp = _parse_fast_timestamp(g["ts"])
    return alert


def _parse_fast_timestamp(ts: str) -> datetime:
    """Snort fast timestamps omit the year (MM/DD-HH:MM:SS.uuuuuu)."""
    try:
        current_year = now().year
        return datetime.strptime(f"{current_year}/{ts}", "%Y/%m/%d-%H:%M:%S.%f")
    except ValueError:
        return now()


def _parse_timestamp(ts: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return now()
