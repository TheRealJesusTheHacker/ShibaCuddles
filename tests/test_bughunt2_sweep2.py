#!/usr/bin/env python3
"""Regression tests for bug hunt #2 (2026-10-19, second sweep).

Each test pins a defect demonstrated against the pre-fix code:

* Option injection through the interface argument: jam_channel
  validated its channel (a leading "-" would be parsed as an mdk3
  option) but NO tool path validated the interface, which sits in the
  same argv — ``jam_channel("-h", ...)`` spawned ``mdk3 -h b -c 6``
  and reported success, and ``scan_nearby_networks("--output-format")``
  handed airodump-ng an extra option in the interface slot. MAC
  arguments to the deauth paths were likewise unvalidated.
* enable/disable_monitor_mode were the two sudo'd tool paths the
  timeout-backstop sweep did not reach: no `timeout` wrapper, so a
  wedged airmon-ng would be orphaned when the run-level timeout
  killed only the sudo parent.
* disable_monitor_mode discarded the airmon-ng stop result and
  reported success even when every command failed;
  deauthenticate_all_devices likewise logged "completed" when
  aireplay-ng exited 1 immediately; jam_channel reported True even
  when mdk3 died mid-window.
* DeviceDiscovery.is_alive / get_mac_address placed an unvalidated
  value at the end of the ping/arp argv ("-f" = ping flood mode).
* ResultsHandler.save used Path.exists() (symlink-following) for its
  no-overwrite refusal, so a planted dangling symlink was written
  through despite force=False.
"""

import logging
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from src.deauth import DeauthTarget, NetworkInterruptor, WiFiDeauthenticator
from src.device import DeviceDiscovery
from src.results_handler import ResultsHandler


def _deauth():
    d = WiFiDeauthenticator.__new__(WiFiDeauthenticator)
    d.logger = logging.getLogger("test-sweep2")
    d.system = "linux"
    return d


def _interruptor():
    n = NetworkInterruptor.__new__(NetworkInterruptor)
    n.logger = logging.getLogger("test-sweep2")
    return n


def _completed(rc=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=rc, stderr=stderr)


class TestInterfaceInjection(unittest.TestCase):
    @patch("src.deauth.subprocess.Popen")
    @patch("src.deauth.require_scope_configured")
    def test_jam_channel_option_like_interface_refused(self, _scope, popen):
        n = _interruptor()
        for bad in ("-h", "--help", "wlan0 mon", "wlan/0", "", None):
            self.assertFalse(n.jam_channel(bad, 6, duration=1))
        popen.assert_not_called()

    @patch("src.deauth.subprocess.run")
    def test_scan_option_like_interface_refused(self, run):
        d = _deauth()
        self.assertEqual(d.scan_nearby_networks("--output-format", duration=1), [])
        run.assert_not_called()

    @patch("src.deauth.subprocess.run")
    def test_enable_monitor_option_like_interface_refused(self, run):
        d = _deauth()
        self.assertFalse(d.enable_monitor_mode("-wlan0"))
        run.assert_not_called()

    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_broadcast_deauth_option_like_interface_refused(self, run, _auth):
        d = _deauth()
        self.assertEqual(
            d.deauthenticate_all_devices(
                "AA:BB:CC:DD:EE:FF", "Lab", "--deauth", duration=5
            ),
            0,
        )
        run.assert_not_called()

    @patch("src.deauth.subprocess.run")
    def test_analyze_option_like_interface_refused(self, run):
        n = _interruptor()
        self.assertEqual(n.analyze_traffic_patterns("-r", duration=5), {})
        run.assert_not_called()

    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_rogue_ap_option_like_interface_refused(self, run, _auth):
        d = _deauth()
        self.assertFalse(d.create_rogue_ap("--interface", "LabAP", 6))
        run.assert_not_called()

    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_single_deauth_bad_mac_refused(self, run, _auth):
        d = _deauth()
        target = DeauthTarget(
            mac_address="not-a-mac",
            gateway_mac="--deauth",
            ssid="Lab",
            channel=6,
            interface="wlan0mon",
            packet_count=5,
        )
        self.assertFalse(d.deauthenticate_device(target))
        run.assert_not_called()

    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_broadcast_deauth_bad_mac_refused(self, run, _auth):
        d = _deauth()
        self.assertEqual(
            d.deauthenticate_all_devices("bogus", "Lab", "wlan0mon", duration=5),
            0,
        )
        run.assert_not_called()

    def test_hostapd_config_rejects_option_like_interface(self):
        d = _deauth()
        with self.assertRaises(ValueError):
            d._generate_hostapd_config("-wlan0", "LabAP", 6, "passphrase")


class TestMonitorModeBackstop(unittest.TestCase):
    @patch("src.deauth.subprocess.run")
    def test_enable_monitor_mode_wraps_airmon(self, run):
        run.return_value = _completed(0)
        d = _deauth()
        self.assertTrue(d.enable_monitor_mode("wlan0"))
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            argv = call.args[0]
            # Wrapper present, and its deadline sits INSIDE the
            # run-level timeout (the backstop-of-the-backstop pattern).
            self.assertEqual(argv[:4], ["sudo", "timeout", "8", "airmon-ng"])
            self.assertEqual(call.kwargs["timeout"], 10)

    @patch("src.deauth.subprocess.run")
    def test_disable_monitor_mode_wraps_airmon_stop(self, run):
        run.return_value = _completed(0)
        d = _deauth()
        self.assertTrue(d.disable_monitor_mode("wlan0mon"))
        first = run.call_args_list[0].args[0]
        self.assertEqual(first[:4], ["sudo", "timeout", "8", "airmon-ng"])
        self.assertIn("stop", first)

    @patch("src.deauth.subprocess.run")
    def test_disable_monitor_mode_reports_stop_failure(self, run):
        # airmon stop fails (rc=1); the networking restart succeeds.
        # Previously the stop result was discarded and True returned.
        run.side_effect = [_completed(1, stderr="boom"), _completed(0)]
        d = _deauth()
        self.assertFalse(d.disable_monitor_mode("wlan0mon"))


class TestMisleadingStatus(unittest.TestCase):
    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_broadcast_deauth_failure_is_logged_as_failure(self, run, _auth):
        run.return_value = _completed(1, stderr="no such interface")
        d = _deauth()
        with self.assertLogs(d.logger, level="INFO") as logs:
            self.assertEqual(
                d.deauthenticate_all_devices(
                    "AA:BB:CC:DD:EE:FF", "Lab", "wlan0mon", duration=5
                ),
                0,  # return contract unchanged: 0 always
            )
        joined = "\n".join(logs.output)
        self.assertIn("failed", joined)
        self.assertNotIn("completed", joined)

    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_broadcast_deauth_full_window_still_completed(self, run, _auth):
        run.return_value = _completed(124)  # wrapper ended the stream
        d = _deauth()
        with self.assertLogs(d.logger, level="INFO") as logs:
            self.assertEqual(
                d.deauthenticate_all_devices(
                    "AA:BB:CC:DD:EE:FF", "Lab", "wlan0mon", duration=5
                ),
                0,
            )
        self.assertIn("completed", "\n".join(logs.output))

    @patch("src.deauth.time.sleep")
    @patch("src.deauth.subprocess.Popen")
    @patch("src.deauth.require_scope_configured")
    def test_jam_channel_mid_window_death_is_failure(self, _scope, popen, _sleep):
        n = _interruptor()
        proc = MagicMock()
        # Alive at the t=0 check, dead by the end of the window (third
        # value is the finally block's poll).
        proc.poll.side_effect = [None, 1, 1]
        proc.returncode = 1
        popen.return_value = proc
        self.assertFalse(n.jam_channel("wlan0mon", 6, duration=1))


class TestDeviceArgInjection(unittest.TestCase):
    @patch("src.device.subprocess.run")
    def test_is_alive_refuses_option_like_target(self, run):
        discovery = DeviceDiscovery(timeout=1)
        self.assertFalse(discovery.is_alive("-f"))
        self.assertFalse(discovery.is_alive("not-an-ip"))
        run.assert_not_called()

    @patch("src.device.subprocess.run")
    def test_is_alive_still_pings_valid_ip(self, run):
        run.return_value = _completed(0)
        discovery = DeviceDiscovery(timeout=1)
        self.assertTrue(discovery.is_alive("192.168.1.1"))
        self.assertEqual(run.call_args.args[0][-1], "192.168.1.1")

    @patch("src.device.subprocess.run")
    def test_get_mac_address_refuses_option_like_target(self, run):
        discovery = DeviceDiscovery(timeout=1)
        self.assertIsNone(discovery.get_mac_address("--help"))
        run.assert_not_called()


class TestResultsSymlinkRefusal(unittest.TestCase):
    def setUp(self):
        self.handler = ResultsHandler(logger=logging.getLogger("test-sweep2"))
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlink support")
    def test_dangling_symlink_not_written_through_without_force(self):
        target = Path(self.tmp.name) / "victim.txt"
        link = Path(self.tmp.name) / "out.json"
        os.symlink(target, link)
        ok = self.handler.save(
            [{"ip": "1.2.3.4", "alive": True, "open_ports": []}],
            str(link),
            "json",
            force=False,
        )
        self.assertFalse(ok)
        self.assertFalse(target.exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlink support")
    def test_force_still_writes_through_chosen_path(self):
        # --force semantics are the caller's explicit choice and are
        # unchanged: only the no-force refusal was widened.
        target = Path(self.tmp.name) / "victim.txt"
        link = Path(self.tmp.name) / "out.json"
        os.symlink(target, link)
        ok = self.handler.save(
            [{"ip": "1.2.3.4", "alive": True, "open_ports": []}],
            str(link),
            "json",
            force=True,
        )
        self.assertTrue(ok)
        self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
