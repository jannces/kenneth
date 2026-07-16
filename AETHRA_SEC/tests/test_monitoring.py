"""Unit tests for the monitoring pipeline (parsing-independent components)."""

import unittest

from monitoring.bandwidth import BandwidthMonitor
from monitoring.connection_tracker import ConnectionTracker
from monitoring.packet_parser import PacketMeta
from monitoring.protocol_analyzer import infer_application, resolve_protocol
from monitoring.traffic_statistics import TrafficStatistics
from utils.helpers import classify_ip_direction


def make_packet(**kwargs) -> PacketMeta:
    base = dict(source_ip="192.168.1.5", destination_ip="8.8.8.8",
                source_port=54321, destination_port=443, protocol="HTTPS",
                transport="TCP", packet_length=200, direction="Outgoing")
    base.update(kwargs)
    return PacketMeta(**base)


class ProtocolTests(unittest.TestCase):
    def test_tls_to_https(self):
        self.assertEqual(resolve_protocol("TLS", "TCP", 5000, 443), "HTTPS")

    def test_port_fallback(self):
        self.assertEqual(resolve_protocol("", "TCP", 12345, 22), "SSH")

    def test_unknown_transport_fallback(self):
        self.assertEqual(resolve_protocol("", "", 40000, 40001), "Unknown")

    def test_application_inference(self):
        self.assertEqual(infer_application("HTTPS", 5000, 443, "TCP"),
                         "HTTPS Request")


class StatisticsTests(unittest.TestCase):
    def test_counts_and_totals(self):
        stats = TrafficStatistics()
        stats.start()
        for _ in range(5):
            stats.record(make_packet(protocol="HTTPS", transport="TCP",
                                     packet_length=100))
        for _ in range(3):
            stats.record(make_packet(protocol="DNS", transport="UDP",
                                     packet_length=60))
        snap = stats.snapshot()
        self.assertEqual(snap.total_packets, 8)
        self.assertEqual(snap.total_bytes, 5 * 100 + 3 * 60)
        self.assertEqual(snap.https, 5)
        self.assertEqual(snap.dns, 3)
        self.assertEqual(snap.tcp, 5)
        self.assertEqual(snap.udp, 3)
        self.assertEqual(snap.largest_packet, 100)


class ConnectionTrackerTests(unittest.TestCase):
    def test_conversation_is_bidirectional(self):
        tracker = ConnectionTracker()
        outbound = make_packet(source_ip="10.0.0.2", destination_ip="10.0.0.9",
                               source_port=5000, destination_port=22,
                               transport="TCP")
        inbound = make_packet(source_ip="10.0.0.9", destination_ip="10.0.0.2",
                              source_port=22, destination_port=5000,
                              transport="TCP")
        tracker.record(outbound)
        tracker.record(inbound)
        # Both packets belong to the SAME conversation.
        self.assertEqual(tracker.active_count(), 1)
        conn = tracker.list_connections()[0]
        self.assertEqual(conn.total_packets, 2)


class BandwidthTests(unittest.TestCase):
    def test_direction_split(self):
        bw = BandwidthMonitor()
        bw.record(make_packet(direction="Outgoing", packet_length=1000))
        bw.record(make_packet(direction="Incoming", packet_length=2000))
        snap = bw.snapshot()
        self.assertGreaterEqual(snap.upload_bps, 0)
        self.assertGreaterEqual(snap.download_bps, 0)


class DirectionTests(unittest.TestCase):
    def test_directions(self):
        local = {"10.0.0.2"}
        self.assertEqual(classify_ip_direction("10.0.0.2", "8.8.8.8", local), "Outgoing")
        self.assertEqual(classify_ip_direction("8.8.8.8", "10.0.0.2", local), "Incoming")
        self.assertEqual(classify_ip_direction("1.1.1.1", "224.0.0.1", local), "Multicast")


if __name__ == "__main__":
    unittest.main()
