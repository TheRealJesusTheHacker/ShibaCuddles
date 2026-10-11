#!/usr/bin/env python3
"""
Unit tests for the scan orchestration layer (src/scanner.py).

Covers the paths fixed in the 2026-10-11 bug hunt:
  - NetworkScanner._scan_ports existed at all (every scan crashed without it)
  - progress callbacks are wired and can never break a scan
  - a failing per-host port scan degrades to an empty result, not a crash
  - oversized target ranges are refused before any work starts
"""

import threading
import unittest
from unittest.mock import MagicMock

from src.scanner import NetworkScanner, ScanResult


def _scanner(**kwargs):
    """Build a scanner that never touches the network."""
    defaults = dict(network="127.0.0.0/30", threads=2, timeout=0.5)
    defaults.update(kwargs)
    scanner = NetworkScanner(**defaults)
    # Stub the port scanner: tests exercise orchestration, not sockets.
    scanner.port_scanner = MagicMock()
    scanner.port_scanner.scan.return_value = [22, 80]
    return scanner


class TestScanPorts(unittest.TestCase):
    def test_scan_ports_returns_one_result_per_host(self):
        scanner = _scanner()
        results = scanner._scan_ports(["127.0.0.1", "127.0.0.2"], "22,80")

        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIsInstance(result, ScanResult)
            self.assertTrue(result.alive)
            self.assertEqual(result.open_ports, [22, 80])
        # One port-scanner call per host, in host order
        calls = scanner.port_scanner.scan.call_args_list
        self.assertEqual([c.args[0] for c in calls], ["127.0.0.1", "127.0.0.2"])
        self.assertTrue(all(c.args[1] == "22,80" for c in calls))

    def test_scan_ports_progress_callback(self):
        seen = []
        scanner = _scanner(
            progress_callback=lambda done, total: seen.append((done, total))
        )

        scanner._scan_ports(["127.0.0.1", "127.0.0.2"], "22")

        self.assertEqual(seen, [(1, 2), (2, 2)])

    def test_scan_ports_progress_callback_exception_does_not_break_scan(self):
        def bad_callback(done, total):
            raise RuntimeError("callback exploded")

        scanner = _scanner(progress_callback=bad_callback)

        results = scanner._scan_ports(["127.0.0.1", "127.0.0.2"], "22")

        self.assertEqual(len(results), 2)

    def test_scan_ports_invalid_port_spec_returns_empty(self):
        scanner = _scanner()

        self.assertEqual(scanner._scan_ports(["127.0.0.1"], "not-a-port"), [])

    def test_scan_ports_host_failure_degrades_gracefully(self):
        # A per-host scan raising must not crash the whole scan; the host
        # is recorded with no open ports.
        scanner = _scanner()
        scanner.port_scanner.scan.side_effect = OSError("unreachable")

        results = scanner._scan_ports(["127.0.0.1"], "22")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].ip, "127.0.0.1")
        self.assertEqual(results[0].open_ports, [])

    def test_scan_ports_stop_event_aborts(self):
        stop = threading.Event()
        stop.set()
        scanner = _scanner(stop_event=stop)

        results = scanner._scan_ports(["127.0.0.1", "127.0.0.2"], "22")

        self.assertEqual(results, [])
        scanner.port_scanner.scan.assert_not_called()


class TestScanPipeline(unittest.TestCase):
    def test_scan_wires_progress_through_discovery_and_ports(self):
        # End-to-end through scan(): discovery (mocked ping) then port scan.
        seen = []
        scanner = _scanner(
            progress_callback=lambda done, total: seen.append((done, total))
        )
        scanner.device_discovery.is_alive = lambda ip: True

        results = scanner.scan("22")

        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.alive for r in results))
        # Progress reported per host in both phases (2 discovery + 2 ports)
        self.assertEqual(len(seen), 4)
        self.assertEqual(seen[-1], (2, 2))

    def test_get_target_hosts_refuses_oversized_range(self):
        scanner = NetworkScanner(network="10.0.0.0/8", threads=2, timeout=0.5)

        with self.assertRaises(ValueError):
            scanner._get_target_hosts()

    def test_get_target_hosts_invalid_network(self):
        scanner = NetworkScanner(network="not-a-network", threads=2, timeout=0.5)

        with self.assertRaises(ValueError):
            scanner._get_target_hosts()


if __name__ == "__main__":
    unittest.main()
