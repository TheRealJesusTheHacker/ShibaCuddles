#!/usr/bin/env python3
"""
Regression tests for the 2026-10-13 performance / code-quality pass:

  - parse_port_spec is memoized (PortScanner.scan re-parses per host)
    without callers being able to poison the cache by mutating results
  - thread clamping lives in one shared helper (utils.clamp_threads)
    with each scanner class keeping its own cap
  - PortScanner/UDPScanner submit probes in bounded windows instead of
    queueing an entire port spec as futures up front; results, stop
    behavior, and KeyboardInterrupt cancellation are unchanged
  - discovery results are sorted numerically with a single-parse key
"""

import threading
import unittest
from unittest.mock import MagicMock, patch

import src.port_scanner as port_scanner_module
from src.port_scanner import PortScanner, UDPScanner
from src.scanner import NetworkScanner
from src.utils import clamp_threads, parse_port_spec


class TestParsePortSpecMemoization(unittest.TestCase):
    def test_repeated_parse_equal(self):
        self.assertEqual(parse_port_spec("1-1024"), parse_port_spec("1-1024"))

    def test_mutating_result_does_not_poison_cache(self):
        first = parse_port_spec("22,80,443")
        first.append(9999)
        first.clear()
        self.assertEqual(parse_port_spec("22,80,443"), [22, 80, 443])

    def test_results_are_distinct_list_objects(self):
        self.assertIsNot(parse_port_spec("22"), parse_port_spec("22"))

    def test_invalid_spec_raises_every_time(self):
        for _ in range(2):
            with self.assertRaises(ValueError):
                parse_port_spec("1024-1")
            with self.assertRaises(ValueError):
                parse_port_spec("0-100")


class TestClampThreads(unittest.TestCase):
    def test_floor(self):
        self.assertEqual(clamp_threads(0, 100), 1)
        self.assertEqual(clamp_threads(-5, 100), 1)

    def test_cap(self):
        self.assertEqual(clamp_threads(10000, 100), 100)
        self.assertEqual(clamp_threads(10000, 64), 64)

    def test_passthrough(self):
        self.assertEqual(clamp_threads(10, 100), 10)
        self.assertEqual(clamp_threads(1, 100), 1)
        self.assertEqual(clamp_threads(100, 100), 100)

    def test_port_scanner_uses_shared_clamp(self):
        self.assertEqual(PortScanner(threads=0).threads, 1)
        self.assertEqual(PortScanner(threads=10000).threads, 100)

    def test_udp_scanner_uses_shared_clamp(self):
        self.assertEqual(UDPScanner(threads=0).threads, 1)
        self.assertEqual(UDPScanner(threads=10000).threads, 100)


class TestWindowedSubmission(unittest.TestCase):
    """With a tiny submit window forced, scans must still return the
    complete, sorted result set -- windowing changes only how many
    futures exist at once, never what is probed or reported."""

    def test_tcp_scan_complete_across_windows(self):
        scanner = PortScanner(threads=4, timeout=1)
        with patch.object(port_scanner_module, "_SUBMIT_WINDOW", 3), patch.object(
            PortScanner, "_check_port", side_effect=lambda h, p: p % 2 == 0
        ):
            result = scanner.scan("127.0.0.1", "20-29")
        self.assertEqual(result, [20, 22, 24, 26, 28])

    def test_udp_scan_complete_across_windows(self):
        scanner = UDPScanner(threads=4, timeout=1)
        with patch.object(port_scanner_module, "_SUBMIT_WINDOW", 2), patch.object(
            UDPScanner, "_check_udp_port", side_effect=lambda h, p: p in (53, 123)
        ):
            result = scanner.scan("127.0.0.1", [53, 67, 123, 500, 514])
        self.assertEqual(result, [53, 123])

    def test_tcp_scan_stop_event_set_returns_empty(self):
        stop = threading.Event()
        stop.set()
        scanner = PortScanner(threads=2, timeout=1, stop_event=stop)
        with patch.object(PortScanner, "_check_port") as mock_check:
            self.assertEqual(scanner.scan("127.0.0.1", "1-100"), [])
        mock_check.assert_not_called()

    def test_udp_scan_stop_event_set_returns_empty(self):
        stop = threading.Event()
        stop.set()
        scanner = UDPScanner(threads=2, timeout=1, stop_event=stop)
        with patch.object(UDPScanner, "_check_udp_port") as mock_check:
            self.assertEqual(scanner.scan("127.0.0.1", [53, 123]), [])
        mock_check.assert_not_called()

    def test_keyboard_interrupt_cancels_submitted_window(self):
        # Window of 2 over 5 ports: Ctrl+C during the first window must
        # cancel exactly the futures submitted so far and propagate.
        futures = [MagicMock() for _ in range(5)]
        executor = MagicMock()
        executor.__enter__.return_value = executor
        executor.submit.side_effect = futures
        scanner = PortScanner(threads=2, timeout=0.1)
        with patch.object(port_scanner_module, "_SUBMIT_WINDOW", 2), patch(
            "src.port_scanner.ThreadPoolExecutor", return_value=executor
        ), patch("src.port_scanner.as_completed", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                scanner.scan("127.0.0.1", "1-5")
        futures[0].cancel.assert_called_once_with()
        futures[1].cancel.assert_called_once_with()
        # Later windows were never submitted, so nothing to cancel there.
        futures[2].cancel.assert_not_called()


class TestDiscoverySortKey(unittest.TestCase):
    def test_alive_hosts_sorted_numerically(self):
        scanner = NetworkScanner(network="10.0.0.0/24", threads=4, timeout=0.5)
        scanner.device_discovery.is_alive = lambda ip: True

        alive = scanner._discover_devices(
            ["10.0.0.10", "10.0.0.9", "10.0.0.2", "10.0.0.100"]
        )

        self.assertEqual(alive, ["10.0.0.2", "10.0.0.9", "10.0.0.10", "10.0.0.100"])


if __name__ == "__main__":
    unittest.main()
