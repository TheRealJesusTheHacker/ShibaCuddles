#!/usr/bin/env python3
"""Unit tests for hostapd config generation hardening (src/deauth.py).

_generate_hostapd_config interpolates caller-supplied values into a
hostapd.conf file, so CR/LF bytes must be rejected (config-line
injection) and the channel must be a real integer.
"""

import unittest

from src.deauth import WiFiDeauthenticator, _require_single_line


class TestHostapdConfigHardening(unittest.TestCase):
    def setUp(self):
        self.d = WiFiDeauthenticator.__new__(WiFiDeauthenticator)

    def test_normal_values_pass(self):
        cfg = self.d._generate_hostapd_config(
            "wlan0mon", "TestLab", 6, "s3cret-passphrase"
        )
        self.assertIn("interface=wlan0mon", cfg)
        self.assertIn("ssid=TestLab", cfg)
        self.assertIn("channel=6", cfg)

    def test_newline_ssid_rejected(self):
        with self.assertRaises(ValueError):
            self.d._generate_hostapd_config(
                "wlan0mon", "Evil\nwpa_passphrase=pwned", 6, "x"
            )

    def test_crlf_interface_rejected(self):
        with self.assertRaises(ValueError):
            self.d._generate_hostapd_config("wlan0\r\nfoo=bar", "TestLab", 6, "x")

    def test_non_integer_channel_rejected(self):
        with self.assertRaises(ValueError):
            self.d._generate_hostapd_config("wlan0mon", "TestLab", "6\nfoo", "x")

    def test_channel_out_of_range_rejected(self):
        for bad in (0, -1, 197, 1000):
            with self.assertRaises(ValueError):
                self.d._generate_hostapd_config("wlan0mon", "TestLab", bad, "x")

    def test_require_single_line_passthrough(self):
        self.assertEqual(_require_single_line("wlan0", "interface"), "wlan0")
        with self.assertRaises(ValueError):
            _require_single_line("a\nb", "ssid")
        with self.assertRaises(ValueError):
            _require_single_line("a\rb", "ssid")


if __name__ == "__main__":
    unittest.main()
