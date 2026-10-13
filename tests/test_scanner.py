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


class TestDetectServicesNoNestedPool(unittest.TestCase):
    """Service detection must not nest a per-port pool inside the per-host
    pool (_map_parallel): that multiplies thread counts (threads^2, up to
    ~1,280 threads). The pipeline probes each host's ports serially via
    detect_service; the standalone ServiceDetector.detect() keeps its own
    pool for direct API use."""

    def _detector_scanner(self):
        scanner = _scanner()
        scanner.service_detector = MagicMock()
        scanner.service_detector.detect_service.side_effect = lambda host, port: (
            {"name": "SSH", "protocol": "tcp"} if port == 22 else None
        )
        return scanner

    def test_detect_calls_detect_service_per_port(self):
        scanner = self._detector_scanner()
        results = [ScanResult(ip="127.0.0.1", alive=True, open_ports=[22, 9999])]

        out = scanner._detect_services(results)

        self.assertEqual(out[0].services, {22: {"name": "SSH", "protocol": "tcp"}})
        calls = scanner.service_detector.detect_service.call_args_list
        self.assertEqual([c.args[1] for c in calls], [22, 9999])

    def test_detect_does_not_use_pooling_detect(self):
        scanner = self._detector_scanner()

        def boom(host, ports):
            raise AssertionError("nested per-port thread pool used")

        scanner.service_detector.detect.side_effect = boom
        results = [
            ScanResult(ip="127.0.0.1", alive=True, open_ports=[22, 80]),
            ScanResult(ip="127.0.0.2", alive=True, open_ports=[]),
        ]

        out = scanner._detect_services(results)

        # No AssertionError: detect() (the pooling path) was never called.
        self.assertEqual(out[0].services, {22: {"name": "SSH", "protocol": "tcp"}})
        self.assertEqual(out[1].services, {})

    def test_detect_service_exception_degrades_gracefully(self):
        scanner = self._detector_scanner()
        scanner.service_detector.detect_service.side_effect = RuntimeError("boom")
        results = [ScanResult(ip="127.0.0.1", alive=True, open_ports=[22])]

        out = scanner._detect_services(results)

        self.assertEqual(out[0].services, {})


class TestThreadCountClamping(unittest.TestCase):
    """NetworkScanner must floor the thread count at 1 like its sibling
    classes: ThreadPoolExecutor raises ValueError for max_workers < 1,
    so threads=0 (reachable via CLI --threads 0) crashed scan()."""

    def test_zero_threads_clamped_to_one(self):
        scanner = NetworkScanner(network="127.0.0.0/30", threads=0, timeout=0.5)
        self.assertEqual(scanner.threads, 1)

    def test_negative_threads_clamped_to_one(self):
        scanner = NetworkScanner(network="127.0.0.0/30", threads=-5, timeout=0.5)
        self.assertEqual(scanner.threads, 1)

    def test_huge_thread_count_still_capped(self):
        scanner = NetworkScanner(network="127.0.0.0/30", threads=10000, timeout=0.5)
        self.assertEqual(scanner.threads, 64)

    def test_scan_with_zero_thread_arg_completes(self):
        scanner = _scanner(threads=0)
        scanner.device_discovery.is_alive = lambda ip: True

        results = scanner.scan("22")

        self.assertEqual(len(results), 2)

    def test_save_results_returns_handler_outcome(self):
        scanner = _scanner()
        scanner.results_handler = MagicMock()
        scanner.results_handler.save.return_value = False

        self.assertFalse(scanner.save_results([], "x.json", "json"))
        scanner.results_handler.save.return_value = True
        self.assertTrue(scanner.save_results([], "x.json", "json"))


if __name__ == "__main__":
    unittest.main()
