"""Unit tests for IDS classification and alert parsing."""

import unittest

from ids.alert_parser import parse_alert
from ids.threat_classifier import classify_category, classify_severity
from mitigation.severity import escalate, highest, rank
from utils.constants import Severity, ThreatCategory


class ClassifierTests(unittest.TestCase):
    def test_port_scan_category(self):
        self.assertEqual(classify_category("Nmap port scan detected"),
                         ThreatCategory.PORT_SCAN)

    def test_icmp_flood_category(self):
        self.assertEqual(classify_category("ICMP flood"),
                         ThreatCategory.ICMP_FLOOD)

    def test_unknown_category(self):
        self.assertEqual(classify_category("something completely unrelated"),
                         ThreatCategory.UNKNOWN_THREAT)

    def test_severity_from_priority(self):
        sev = classify_severity(ThreatCategory.PORT_SCAN, priority=1)
        self.assertEqual(sev, Severity.CRITICAL)

    def test_severity_escalates_with_occurrences(self):
        low = classify_severity(ThreatCategory.ICMP_FLOOD, priority=4, occurrences=1)
        high = classify_severity(ThreatCategory.ICMP_FLOOD, priority=4, occurrences=150)
        self.assertGreaterEqual(high.rank, low.rank)


class AlertParserTests(unittest.TestCase):
    def test_parse_fast_format(self):
        line = ("06/12-10:15:03.123456 [**] [1:1000001:0] SSH brute force [**] "
                "[Classification: Attempted Admin] [Priority: 1] {TCP} "
                "10.0.0.9:5512 -> 10.0.0.1:22")
        alert = parse_alert(line)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.sid, "1000001")
        self.assertEqual(alert.source_ip, "10.0.0.9")
        self.assertEqual(alert.destination_port, 22)
        self.assertEqual(alert.priority, 1)
        self.assertEqual(alert.protocol, "TCP")

    def test_parse_json_format(self):
        raw = ('{"sid": 2000, "msg": "ICMP flood", "priority": 2, '
               '"proto": "ICMP", "src": "10.0.0.5", "dst": "10.0.0.1"}')
        alert = parse_alert(raw)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.message, "ICMP flood")
        self.assertEqual(alert.protocol, "ICMP")
        self.assertEqual(alert.source_ip, "10.0.0.5")

    def test_parse_garbage_returns_none(self):
        self.assertIsNone(parse_alert(""))
        self.assertIsNone(parse_alert("   "))


class SeverityHelperTests(unittest.TestCase):
    def test_highest(self):
        self.assertEqual(highest("Low", "Critical", "Medium"), "Critical")

    def test_rank_ordering(self):
        self.assertGreater(rank("Critical"), rank("Low"))

    def test_escalate(self):
        self.assertEqual(escalate("Low", 150), "High")


if __name__ == "__main__":
    unittest.main()
