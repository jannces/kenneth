"""Parse PyShark packet objects into a lightweight metadata record.

We never keep the raw packet around: only the structured :class:`PacketMeta`
fields required by the spec are extracted, which is what gets displayed and
(optionally) persisted to ``live_packets``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from monitoring.protocol_analyzer import infer_application, resolve_protocol
from utils.helpers import classify_ip_direction, now


@dataclass
class PacketMeta:
    """Structured, display-ready packet metadata."""

    timestamp: datetime = field(default_factory=now)
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "Unknown"
    transport: str = ""
    application: str = ""
    packet_length: int = 0
    ttl: int = 0
    tcp_flags: str = ""
    mac_source: str = ""
    mac_destination: str = ""
    direction: str = ""

    def as_row(self) -> tuple:
        """Tuple ordered for the ``live_packets`` INSERT."""
        return (
            self.timestamp, self.source_ip, self.destination_ip,
            self.source_port, self.destination_port, self.protocol,
            self.transport, self.application, self.packet_length, self.ttl,
            self.tcp_flags, self.mac_source, self.mac_destination, self.direction,
        )


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _decode_tcp_flags(tcp_layer) -> str:
    """Build a compact flag string like ``SYN,ACK`` from a PyShark TCP layer."""
    flags = []
    mapping = [
        ("flags_syn", "SYN"), ("flags_ack", "ACK"), ("flags_fin", "FIN"),
        ("flags_reset", "RST"), ("flags_push", "PSH"), ("flags_urg", "URG"),
    ]
    for attr, label in mapping:
        try:
            if str(getattr(tcp_layer, attr, "0")) in ("1", "True"):
                flags.append(label)
        except Exception:  # noqa: BLE001
            continue
    return ",".join(flags)


def parse_packet(packet, local_ips: set[str]) -> Optional[PacketMeta]:
    """Convert a PyShark packet into :class:`PacketMeta`.

    Returns ``None`` for packets we cannot make sense of at all (extremely
    rare); all other packets - including unknown protocols - are represented.
    """
    try:
        meta = PacketMeta()

        # Length + timestamp.
        try:
            meta.packet_length = _safe_int(packet.length)
        except Exception:  # noqa: BLE001
            meta.packet_length = 0
        try:
            meta.timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp))
        except Exception:  # noqa: BLE001
            meta.timestamp = now()

        highest_layer = getattr(packet, "highest_layer", "") or ""

        # Ethernet / MAC.
        if hasattr(packet, "eth"):
            meta.mac_source = getattr(packet.eth, "src", "") or ""
            meta.mac_destination = getattr(packet.eth, "dst", "") or ""

        # IP layer (v4 or v6).
        if hasattr(packet, "ip"):
            meta.source_ip = getattr(packet.ip, "src", "") or ""
            meta.destination_ip = getattr(packet.ip, "dst", "") or ""
            meta.ttl = _safe_int(getattr(packet.ip, "ttl", 0))
        elif hasattr(packet, "ipv6"):
            meta.source_ip = getattr(packet.ipv6, "src", "") or ""
            meta.destination_ip = getattr(packet.ipv6, "dst", "") or ""
            meta.ttl = _safe_int(getattr(packet.ipv6, "hlim", 0))

        # Transport layer.
        if hasattr(packet, "tcp"):
            meta.transport = "TCP"
            meta.source_port = _safe_int(getattr(packet.tcp, "srcport", 0))
            meta.destination_port = _safe_int(getattr(packet.tcp, "dstport", 0))
            meta.tcp_flags = _decode_tcp_flags(packet.tcp)
        elif hasattr(packet, "udp"):
            meta.transport = "UDP"
            meta.source_port = _safe_int(getattr(packet.udp, "srcport", 0))
            meta.destination_port = _safe_int(getattr(packet.udp, "dstport", 0))
        elif hasattr(packet, "icmp") or hasattr(packet, "icmpv6"):
            meta.transport = "ICMP"
        elif hasattr(packet, "arp"):
            meta.transport = "ARP"
            meta.source_ip = getattr(packet.arp, "src_proto_ipv4", "") or meta.source_ip
            meta.destination_ip = getattr(packet.arp, "dst_proto_ipv4", "") or meta.destination_ip

        meta.protocol = resolve_protocol(
            highest_layer, meta.transport, meta.source_port, meta.destination_port
        )
        meta.application = infer_application(
            meta.protocol, meta.source_port, meta.destination_port, meta.transport
        )
        meta.direction = classify_ip_direction(
            meta.source_ip, meta.destination_ip, local_ips
        )
        return meta
    except Exception:  # noqa: BLE001 - never let a bad packet crash capture
        return None
