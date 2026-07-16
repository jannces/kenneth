"""Integration test for the alert processing pipeline using an in-memory DB.

A small pattern-matching fake database stands in for MySQL so the deduplication
and correlation logic in :class:`AlertProcessor` can be exercised end-to-end
without a live server.
"""

import unittest

from ids.alert_parser import parse_alert
from ids.alert_processor import AlertProcessor


class FakeDB:
    """Minimal in-memory stand-in supporting the queries AlertProcessor uses."""

    def __init__(self):
        self.alerts = {}       # id -> row
        self.timeline = []
        self.metrics = []
        self.scan_results = []  # list of dict rows
        self._next_id = 1

    def query_one(self, sql, params=()):
        s = " ".join(sql.split())
        if "FROM intrusion_alerts WHERE dedup_key" in s:
            dedup_key, status = params
            for row in self.alerts.values():
                if row["dedup_key"] == dedup_key and row["status"] == status:
                    return dict(row)
            return None
        if "FROM intrusion_alerts WHERE id" in s:
            return dict(self.alerts.get(params[0], {})) or None
        return None

    def query(self, sql, params=()):
        s = " ".join(sql.split())
        if "FROM scan_results" in s:
            host = params[0]
            return [r for r in self.scan_results
                    if r["host"] == host and r["state"] == "open"]
        return []

    def execute(self, sql, params=(), commit=True):
        s = " ".join(sql.split())
        if s.startswith("INSERT INTO intrusion_alerts"):
            row_id = self._next_id
            self._next_id += 1
            # Column order from AlertProcessor._insert_new.
            cols = ["timestamp", "last_seen", "snort_sid", "classification",
                    "category", "priority", "source_ip", "destination_ip",
                    "source_port", "destination_port", "protocol", "interface",
                    "description", "severity", "occurrences", "status", "dedup_key"]
            row = dict(zip(cols, params))
            row["id"] = row_id
            self.alerts[row_id] = row
            return row_id
        if s.startswith("INSERT INTO alert_timeline"):
            self.timeline.append(params)
            return len(self.timeline)
        if s.startswith("INSERT INTO detection_metrics"):
            self.metrics.append(params)
            return len(self.metrics)
        if s.startswith("UPDATE intrusion_alerts SET occurrences"):
            occurrences, last_seen, severity, alert_id = params
            self.alerts[alert_id].update(
                occurrences=occurrences, last_seen=last_seen, severity=severity)
            return 1
        return 0

    def executemany(self, sql, seq, commit=True):
        return len(seq)

    def scalar(self, sql, params=()):
        return 0


class AlertPipelineTests(unittest.TestCase):
    def setUp(self):
        self.db = FakeDB()
        self.notified = []
        self.processor = AlertProcessor(self.db, notify_cb=self.notified.append)

    def _feed(self, line):
        return self.processor.process(parse_alert(line))

    def test_new_alert_is_stored(self):
        line = ("06/12-10:00:00.0 [**] [1:1000:0] ICMP flood [**] "
                "[Priority: 2] {ICMP} 10.0.0.5 -> 10.0.0.1")
        stored = self._feed(line)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["category"], "ICMP Flood")
        self.assertEqual(stored["occurrences"], 1)
        self.assertEqual(len(self.db.alerts), 1)

    def test_duplicate_alerts_are_deduplicated(self):
        line = ("06/12-10:00:00.0 [**] [1:1000:0] ICMP flood [**] "
                "[Priority: 2] {ICMP} 10.0.0.5 -> 10.0.0.1")
        for _ in range(50):
            self._feed(line)
        # 50 identical alerts collapse into ONE row with occurrence counter 50.
        self.assertEqual(len(self.db.alerts), 1)
        row = next(iter(self.db.alerts.values()))
        self.assertEqual(row["occurrences"], 50)

    def test_distinct_sources_create_separate_alerts(self):
        base = ("06/12-10:00:00.0 [**] [1:1000:0] ICMP flood [**] "
                "[Priority: 2] {{ICMP}} {src} -> 10.0.0.1")
        self._feed(base.format(src="10.0.0.5"))
        self._feed(base.format(src="10.0.0.6"))
        self.assertEqual(len(self.db.alerts), 2)

    def test_correlation_links_scan_findings(self):
        self.db.scan_results.append(
            {"host": "10.0.0.1", "service": "ssh", "port": 22,
             "risk_level": "Medium", "state": "open"})
        line = ("06/12-10:00:00.0 [**] [1:2000:0] SSH login brute force [**] "
                "[Priority: 1] {TCP} 10.0.0.9:5000 -> 10.0.0.1:22")
        stored = self._feed(line)
        related = stored.get("related_vulnerabilities", [])
        self.assertTrue(any(r["service"] == "ssh" for r in related))

    def test_notification_fired(self):
        line = ("06/12-10:00:00.0 [**] [1:2000:0] SSH brute force [**] "
                "[Priority: 1] {TCP} 10.0.0.9:5000 -> 10.0.0.1:22")
        self._feed(line)
        self.assertTrue(self.notified)


if __name__ == "__main__":
    unittest.main()
