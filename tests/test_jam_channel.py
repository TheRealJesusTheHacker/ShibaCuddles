#!/usr/bin/env python3
"""Unit tests for NetworkInterruptor.jam_channel input validation.

jam_channel interpolated its channel argument into the mdk3 command
line verbatim while _generate_hostapd_config (same module) validates
its channel as an in-range integer. A non-integer channel string --
especially one starting with "-" -- could be parsed by mdk3 as an
option instead of a channel. Validation now matches the hostapd path:
non-integer or out-of-range values are refused before any subprocess
is spawned.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

from src.deauth import NetworkInterruptor


def _interruptor():
    n = NetworkInterruptor.__new__(NetworkInterruptor)
    n.logger = logging.getLogger("test")
    return n


class TestJamChannelValidation(unittest.TestCase):
    @patch("src.deauth.subprocess.Popen")
    @patch("src.deauth.require_scope_configured")
    def test_non_integer_channel_refused_without_spawning(self, _scope, popen):
        n = _interruptor()
        self.assertFalse(n.jam_channel("wlan0mon", "6 -c 11", duration=1))
        self.assertFalse(n.jam_channel("wlan0mon", "-h", duration=1))
        popen.assert_not_called()

    @patch("src.deauth.subprocess.Popen")
    @patch("src.deauth.require_scope_configured")
    def test_out_of_range_channel_refused_without_spawning(self, _scope, popen):
        n = _interruptor()
        for bad in (0, -1, 197, 1000):
            self.assertFalse(n.jam_channel("wlan0mon", bad, duration=1))
        popen.assert_not_called()

    @patch("src.deauth.time.sleep")
    @patch("src.deauth.subprocess.Popen")
    @patch("src.deauth.require_scope_configured")
    def test_valid_channel_runs_and_is_terminated(self, _scope, popen, _sleep):
        n = _interruptor()
        proc = MagicMock()
        proc.poll.return_value = None
        popen.return_value = proc

        self.assertTrue(n.jam_channel("wlan0mon", 6, duration=1))

        argv = popen.call_args.args[0]
        self.assertEqual(argv[argv.index("-c") + 1], "6")
        proc.terminate.assert_called()

    @patch("src.deauth.time.sleep")
    @patch("src.deauth.subprocess.Popen")
    @patch("src.deauth.require_scope_configured")
    def test_string_channel_that_is_a_valid_integer_is_coerced(
        self, _scope, popen, _sleep
    ):
        n = _interruptor()
        proc = MagicMock()
        proc.poll.return_value = None
        popen.return_value = proc

        self.assertTrue(n.jam_channel("wlan0mon", "11", duration=1))

        argv = popen.call_args.args[0]
        self.assertEqual(argv[argv.index("-c") + 1], "11")


if __name__ == "__main__":
    unittest.main()
