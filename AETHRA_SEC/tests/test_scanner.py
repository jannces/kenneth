"""Unit tests for scan risk assessment."""

import unittest

from scanner.nmap_engine import NmapEngine, SCAN_ARGUMENTS
from scanner.vulnerability_mapper import assess_host, assess_port
from utils.constants import ScanType, Severity


class RiskAssessmentTests(unittest.TestCase):
    def test_telnet_is_high_risk(self):
        risk = assess_port(23, "telnet", "open")
        self.assertEqual(risk.severity, Severity.HIGH)

    def test_https_is_informational(self):
        risk = assess_port(443, "https", "open")
        self.assertEqual(risk.severity, Severity.INFORMATIONAL)

    def test_rdp_flags_recommendation(self):
        risk = assess_port(3389, "ms-wbt-server", "open")
        self.assertTrue(risk.recommendation_available)
        self.assertEqual(risk.related_threat, "Brute Force")

    def test_closed_port_informational(self):
        risk = assess_port(80, "http", "closed")
        self.assertEqual(risk.severity, Severity.INFORMATIONAL)

    def test_host_takes_highest_port_risk(self):
        risks = [
            assess_port(443, "https", "open"),
            assess_port(23, "telnet", "open"),
        ]
        self.assertEqual(assess_host(risks, 2), Severity.HIGH)

    def test_host_no_ports_is_informational(self):
        self.assertEqual(assess_host([], 0), Severity.INFORMATIONAL)

    def test_many_ports_raises_floor(self):
        risks = [assess_port(1000 + i, "http", "open") for i in range(9)]
        # http alone is Low; 9 open ports should raise to at least Medium.
        self.assertGreaterEqual(assess_host(risks, 9).rank, Severity.MEDIUM.rank)


class NmapEngineTests(unittest.TestCase):
    def test_scan_arguments_exist_for_all_types(self):
        for scan_type in ScanType:
            self.assertIn(scan_type.value, SCAN_ARGUMENTS)

    def test_engine_reports_unavailable_gracefully(self):
        engine = NmapEngine()
        # In an environment without nmap, scanning returns an error, not a crash.
        if not engine.available:
            outcome = engine.scan("127.0.0.1", ScanType.QUICK.value)
            self.assertTrue(outcome.error)


if __name__ == "__main__":
    unittest.main()
