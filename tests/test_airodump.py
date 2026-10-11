#!/usr/bin/env python3
"""
Unit tests for the airodump-ng CSV parser (src/deauth.py).

_parse_airodump_csv is a pure function (static method): given a directory
of airodump-ng CSV captures it returns a list of network dicts. No
wireless hardware or root needed.
"""

import os
import tempfile
import unittest

from src.deauth import WiFiDeauthenticator

parse = WiFiDeauthenticator._parse_airodump_csv

AP_HEADER = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
    "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, "
    "ESSID, Key"
)
STATION_HEADER = (
    "Station MAC, First time seen, Last time seen, Power, # packets, "
    "BSSID, Probed ESSIDs"
)


def ap_row(bssid, channel, privacy, power, ssid):
    return (
        f"{bssid}, 2026-10-11 00:00:00, 2026-10-11 00:00:10, {channel}, "
        f"54, {privacy}, CCMP, PSK, {power}, 100, 0, 0.0.0.0, "
        f"{len(ssid)}, {ssid}, "
    )


class TestParseAirodumpCsv(unittest.TestCase):
    def _write_csv(self, directory, name, body):
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        return path

    def test_parses_ap_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_csv(
                tmp,
                "scan-01.csv",
                AP_HEADER
                + "\n"
                + ap_row("AA:BB:CC:DD:EE:FF", 6, "WPA2", -50, "HomeNet")
                + "\n"
                + ap_row("11:22:33:44:55:66", 11, "WPA2 WPA3", -70, "CoffeeShop")
                + "\n",
            )

            networks = parse(tmp)

        self.assertEqual(len(networks), 2)
        first = networks[0]
        self.assertEqual(
            first,
            {
                "bssid": "AA:BB:CC:DD:EE:FF",
                "channel": "6",
                "privacy": "WPA2",
                "power": "-50",
                "ssid": "HomeNet",
            },
        )

    def test_stops_at_station_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_csv(
                tmp,
                "scan-01.csv",
                AP_HEADER
                + "\n"
                + ap_row("AA:BB:CC:DD:EE:FF", 6, "WPA2", -50, "HomeNet")
                + "\n\n"
                + STATION_HEADER
                + "\n\n"
                + "AA:BB:CC:DD:EE:01, 2026-10-11 00:00:05, "
                "2026-10-11 00:00:09, -40, 12, AA:BB:CC:DD:EE:FF, HomeNet\n",
            )

            networks = parse(tmp)

        # Only the access point above the "Station MAC" line is parsed.
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["ssid"], "HomeNet")

    def test_ssid_containing_commas(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_csv(
                tmp,
                "scan-01.csv",
                AP_HEADER
                + "\n"
                + ap_row("AA:BB:CC:DD:EE:FF", 1, "OPN", -60, "Cafe, Free, WiFi")
                + "\n",
            )

            networks = parse(tmp)

        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["ssid"], "Cafe, Free, WiFi")

    def test_ignores_non_csv_files_and_malformed_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_csv(tmp, "scan-01.kismet", "not a csv at all")
            self._write_csv(
                tmp,
                "scan-01.csv",
                AP_HEADER
                + "\n"
                + "short,row\n"
                + ", 2026-10-11 00:00:00, x, 6\n"
                + ap_row("AA:BB:CC:DD:EE:FF", 6, "WPA2", -50, "HomeNet")
                + "\n",
            )

            networks = parse(tmp)

        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["bssid"], "AA:BB:CC:DD:EE:FF")

    def test_missing_directory_returns_empty(self):
        self.assertEqual(parse("/nonexistent/dir/does/not/exist"), [])

    def test_empty_directory_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(parse(tmp), [])


if __name__ == "__main__":
    unittest.main()
