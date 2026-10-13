#!/usr/bin/env python3
"""Unit tests for ResultsHandler export edge cases (src/results_handler.py).

Regression: _save_csv returned early on an empty result set, so save()
reported success (and the CLI printed "Results saved") while no file
was written. An empty CSV export must produce a header-only file.
"""

import os
import tempfile
import unittest

from src.results_handler import ResultsHandler


class TestCsvExport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="shibacuddles_results_test_")
        self.handler = ResultsHandler()

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def test_empty_results_write_header_only_csv(self):
        path = os.path.join(self.tmp, "empty.csv")

        self.assertTrue(self.handler.save([], path, "csv"))

        self.assertTrue(os.path.isfile(path))
        with open(path, "r", encoding="utf-8", newline="") as fh:
            lines = fh.read().splitlines()
        self.assertEqual(lines, ["ip,alive,open_ports,port_count,scan_time"])

    def test_nonempty_csv_keeps_header_and_rows(self):
        path = os.path.join(self.tmp, "out.csv")
        results = [
            {
                "ip": "192.168.1.1",
                "alive": True,
                "open_ports": [22, 80],
                "scan_time": 1.5,
            }
        ]

        self.assertTrue(self.handler.save(results, path, "csv"))

        with open(path, "r", encoding="utf-8", newline="") as fh:
            lines = fh.read().splitlines()
        self.assertEqual(lines[0], "ip,alive,open_ports,port_count,scan_time")
        self.assertEqual(len(lines), 2)
        self.assertIn("192.168.1.1", lines[1])
        self.assertIn('"22,80"', lines[1])


if __name__ == "__main__":
    unittest.main()
