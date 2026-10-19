"""Regression tests: every long-running sudo'd tool in src/deauth.py must
carry the GNU `timeout` orphan backstop (the pattern jam_channel already
used for mdk3).

Why: subprocess.run(timeout=...) kills only the direct child — the
`sudo` parent. The real tool (airodump-ng, aireplay-ng, hostapd,
tcpdump) is sudo's child and is ORPHANED, not killed. For
`aireplay-ng --deauth 0` (continuous mode) that meant an infinite
broadcast deauth surviving the program; for hostapd, a rogue AP
broadcasting a live generated passphrase forever; for airodump-ng /
tcpdump, captures (and the monitor interface) held indefinitely.

These tests mock subprocess.run and assert the wrapper is present in
argv, the run-level timeout sits beyond the wrapper (backstop of the
backstop), and the surrounding success/failure semantics are unchanged.
"""

import logging
import subprocess
import unittest
from unittest.mock import patch

from src.deauth import DeauthTarget, NetworkInterruptor, WiFiDeauthenticator


def _deauth():
    d = WiFiDeauthenticator.__new__(WiFiDeauthenticator)
    d.logger = logging.getLogger("test")
    d.system = "linux"
    return d


def _interruptor():
    n = NetworkInterruptor.__new__(NetworkInterruptor)
    n.logger = logging.getLogger("test")
    return n


def _completed(rc=0):
    return subprocess.CompletedProcess(args=[], returncode=rc)


class TestBroadcastDeauthBackstop(unittest.TestCase):
    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_continuous_deauth_is_timeout_wrapped(self, run, _auth):
        run.return_value = _completed(124)
        d = _deauth()
        self.assertEqual(
            d.deauthenticate_all_devices(
                "AA:BB:CC:DD:EE:FF", "Lab", "wlan0mon", duration=30
            ),
            0,
        )
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["sudo", "timeout", "30"])
        self.assertIn("--deauth", argv)
        self.assertEqual(argv[argv.index("--deauth") + 1], "0")  # continuous mode
        # run-level kill must sit beyond the wrapper's own deadline
        self.assertEqual(run.call_args.kwargs["timeout"], 40)

    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_non_positive_duration_refused_without_spawning(self, run, _auth):
        d = _deauth()
        for bad in (0, -1, -30):
            self.assertEqual(
                d.deauthenticate_all_devices(
                    "AA:BB:CC:DD:EE:FF", "Lab", "wlan0mon", duration=bad
                ),
                0,
            )
        run.assert_not_called()

    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_non_integer_duration_refused_without_spawning(self, run, _auth):
        d = _deauth()
        self.assertEqual(
            d.deauthenticate_all_devices(
                "AA:BB:CC:DD:EE:FF", "Lab", "wlan0mon", duration="soon"
            ),
            0,
        )
        run.assert_not_called()


class TestSingleDeauthBackstop(unittest.TestCase):
    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_finite_deauth_is_timeout_wrapped(self, run, _auth):
        run.return_value = _completed(0)
        d = _deauth()
        target = DeauthTarget(
            mac_address="11:22:33:44:55:66",
            gateway_mac="AA:BB:CC:DD:EE:FF",
            ssid="Lab",
            channel=6,
            interface="wlan0mon",
            packet_count=10,
        )
        self.assertTrue(d.deauthenticate_device(target))
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["sudo", "timeout", "25"])
        self.assertEqual(run.call_args.kwargs["timeout"], 30)


class TestAirodumpBackstop(unittest.TestCase):
    @patch("src.deauth.subprocess.run")
    def test_scan_is_timeout_wrapped(self, run):
        run.return_value = _completed(124)
        d = _deauth()
        self.assertEqual(d.scan_nearby_networks("wlan0mon", duration=10), [])
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["sudo", "timeout", "15"])  # duration + 5
        self.assertEqual(run.call_args.kwargs["timeout"], 25)  # duration + 15


class TestRogueApBackstop(unittest.TestCase):
    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_hostapd_is_timeout_wrapped(self, run, _auth):
        run.return_value = _completed(0)
        d = _deauth()
        self.assertTrue(d.create_rogue_ap("wlan0mon", "LabAP", 6))
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["sudo", "timeout", "60", "hostapd"])
        self.assertEqual(run.call_args.kwargs["timeout"], 75)

    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_wrapper_exit_124_means_full_window_success(self, run, _auth):
        # timeout(1) exits 124 when it has to kill the command: hostapd
        # stayed up for the whole window — the same success case the
        # TimeoutExpired branch has always treated as True.
        run.return_value = _completed(124)
        d = _deauth()
        self.assertTrue(d.create_rogue_ap("wlan0mon", "LabAP", 6))

    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_hostapd_failure_still_false(self, run, _auth):
        run.return_value = _completed(1)
        d = _deauth()
        self.assertFalse(d.create_rogue_ap("wlan0mon", "LabAP", 6))

    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_run_timeout_still_true(self, run, _auth):
        run.side_effect = subprocess.TimeoutExpired(cmd=["hostapd"], timeout=75)
        d = _deauth()
        self.assertTrue(d.create_rogue_ap("wlan0mon", "LabAP", 6))


class TestTcpdumpBackstop(unittest.TestCase):
    @patch("src.deauth.subprocess.run")
    def test_capture_is_timeout_wrapped_on_linux(self, run):
        run.return_value = _completed(124)
        n = _interruptor()
        stats = n.analyze_traffic_patterns("wlan0mon", duration=20)
        self.assertEqual(stats.get("duration"), 20)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["sudo", "timeout", "20"])
        self.assertIn("tcpdump", argv)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    @patch("src.deauth.subprocess.run")
    def test_non_positive_duration_refused_without_spawning(self, run):
        n = _interruptor()
        for bad in (0, -5):
            self.assertEqual(n.analyze_traffic_patterns("wlan0mon", duration=bad), {})
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
