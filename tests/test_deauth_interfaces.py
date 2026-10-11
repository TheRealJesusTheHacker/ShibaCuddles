#!/usr/bin/env python3
"""Unit tests for WiFiDeauthenticator.get_wireless_interfaces (src/deauth.py).

The method was unreachable dead code (defined after a ``return`` inside a
module-level function), so calling it raised AttributeError. It is now a
real method of WiFiDeauthenticator.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

from src.deauth import WiFiDeauthenticator


def _deauth():
    d = WiFiDeauthenticator.__new__(WiFiDeauthenticator)
    d.system = "linux"
    d.logger = logging.getLogger("test")
    return d


class TestGetWirelessInterfaces(unittest.TestCase):
    def test_method_is_reachable(self):
        d = _deauth()
        self.assertTrue(callable(getattr(d, "get_wireless_interfaces", None)))

    def test_parses_iwconfig_output(self):
        d = _deauth()
        fake = MagicMock()
        fake.stdout = (
            "wlan0     IEEE 802.11  ESSID:off/any  Mode:Managed\n"
            "eth0      no wireless extensions.\n"
        )
        with patch("src.deauth.subprocess.run", return_value=fake):
            self.assertEqual(d.get_wireless_interfaces(), ["wlan0"])

    def test_iwconfig_failure_returns_empty_list(self):
        d = _deauth()
        with patch("src.deauth.subprocess.run", side_effect=FileNotFoundError()):
            self.assertEqual(d.get_wireless_interfaces(), [])

    def test_non_linux_returns_empty_list(self):
        d = _deauth()
        d.system = "windows"
        with patch("src.deauth.subprocess.run") as run:
            self.assertEqual(d.get_wireless_interfaces(), [])
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
