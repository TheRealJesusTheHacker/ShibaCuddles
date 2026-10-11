#!/usr/bin/env python3
"""Windows-correctness regression tests (PASS 4 audit).

These run on any platform but simulate Windows-specific conditions:
- legacy console codepages that cannot encode the startup banner
- non-ASCII scan data exported on a locale-codepage system
- uppercase file extensions (common on Windows)
"""

import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.results_handler import ResultsHandler
from src.utils import print_banner


class _Cp437Stdout:
    """Fake stdout that behaves like a legacy Windows console (cp437).

    write() raises UnicodeEncodeError for anything outside cp437, exactly
    like print() to a real codepage-limited console.
    """

    def __init__(self, real):
        self._real = real

    def write(self, s):
        s.encode("cp437")  # raises UnicodeEncodeError on emoji/box-drawing
        return self._real.write(s)

    def flush(self):
        pass


def _sample_results():
    class R:
        __dataclass_fields__ = {}  # duck-type: not a dataclass

    return [
        {
            "ip": "192.168.1.1",
            "alive": True,
            "open_ports": [22, 80],
            "closed_ports": [],
            "filtered_ports": [],
            "services": {22: {"name": "SSH", "banner": "OpenSSH_9.0 🐕"}},
            "os_info": {"name": "Linux/Unix", "confidence": 95},
            "scan_time": 1.23,
        },
        {
            "ip": "192.168.1.2",
            "alive": True,
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "services": {},
            "os_info": {},
            "scan_time": 0.5,
        },
    ]


class TestBannerLegacyConsole(unittest.TestCase):
    def test_banner_falls_back_on_codepage_limited_console(self):
        """print_banner must not raise on cp437/cp1252 consoles."""
        real = sys.stdout
        with patch("sys.stdout", _Cp437Stdout(real)):
            buf = io.StringIO()
            with patch("sys.stdout", _Cp437Stdout(buf)):
                print_banner()  # must not raise
        self.assertIn("ShibaCuddles", buf.getvalue())
        buf.getvalue().encode("cp437")  # fallback is console-safe


class TestExportEncoding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="shibacuddles_win_test_")
        self.handler = ResultsHandler()

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def _save_and_read_bytes(self, name, fmt):
        path = os.path.join(self.tmp, name)
        self.assertTrue(self.handler.save(_sample_results(), path, fmt, force=True))
        with open(path, "rb") as fh:
            return fh.read()

    def test_json_export_is_utf8(self):
        import json

        raw = self._save_and_read_bytes("out.json", "json")
        raw.decode("utf-8")  # must be valid UTF-8 bytes
        # ensure_ascii=True escapes non-ASCII; the data must round-trip
        self.assertIn("🐕", json.loads(raw)[0]["services"]["22"]["banner"])

    def test_csv_export_is_utf8(self):
        raw = self._save_and_read_bytes("out.csv", "csv")
        raw.decode("utf-8")
        self.assertIn(b"ip,alive,open_ports", raw.split(b"\n")[0])

    def test_xml_export_is_utf8(self):
        raw = self._save_and_read_bytes("out.xml", "xml")
        raw.decode("utf-8")

    def test_txt_export_is_utf8(self):
        raw = self._save_and_read_bytes("out.txt", "txt")
        text = raw.decode("utf-8")  # must be valid UTF-8, no locale mojibake
        self.assertIn("192.168.1.1", text)

    def test_uppercase_extension_autodetect(self):
        """RESULTS.CSV must be detected as CSV on case-insensitive Windows."""
        raw = self._save_and_read_bytes("RESULTS.CSV", "json")
        self.assertTrue(raw.startswith(b"ip,alive,open_ports"))

    def test_uppercase_json_extension_autodetect(self):
        raw = self._save_and_read_bytes("RESULTS.JSON", "json")
        raw.decode("utf-8")
        self.assertTrue(raw.lstrip().startswith(b"["))


class TestDeauthToolDetection(unittest.TestCase):
    def test_check_uses_shutil_which(self):
        """Tool detection must not shell out to the Unix-only `which`."""
        from src import deauth

        with patch.object(deauth.shutil, "which", return_value=None) as w:
            import logging

            d = deauth.WiFiDeauthenticator.__new__(deauth.WiFiDeauthenticator)
            d.logger = logging.getLogger("test")
            self.assertFalse(d._check_airmon_ng())
            self.assertFalse(d._check_aireplay_ng())
            self.assertEqual(w.call_count, 2)


if __name__ == "__main__":
    unittest.main()
