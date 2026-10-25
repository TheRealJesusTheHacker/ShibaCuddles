"""Sweep #6 CodeQL regression for the rogue-AP hostapd config.

CodeQL flagged the write of the generated hostapd config as
clear-text storage of sensitive data (src/deauth.py,
py/clear-text-storage-sensitive-data). hostapd's interface
requires a clear-text wpa_passphrase in its config file, so the
disposition is mitigated-by-design: the file must be a private
(0600) mkstemp file for exactly the duration of the hostapd run
and must not exist afterwards. This test pins those properties
from inside the (mocked) hostapd invocation.
"""

import logging
import os
import stat
import subprocess
import unittest
from unittest.mock import patch

from src.deauth import WiFiDeauthenticator


def _deauth():
    d = WiFiDeauthenticator.__new__(WiFiDeauthenticator)
    d.logger = logging.getLogger("test")
    d.system = "linux"
    return d


def _completed(code):
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=b"", stderr=b"")


class TestHostapdConfigPrivacy(unittest.TestCase):
    @patch("src.deauth.require_authorized")
    @patch("src.deauth.subprocess.run")
    def test_config_file_is_0600_during_run_and_gone_after(self, run, _auth):
        seen = {}

        def fake_run(argv, **kwargs):
            conf_path = argv[4]
            seen["mode"] = stat.S_IMODE(os.stat(conf_path).st_mode)
            with open(conf_path) as f:
                seen["config"] = f.read()
            return _completed(0)

        run.side_effect = fake_run
        d = _deauth()
        self.assertTrue(d.create_rogue_ap("wlan0mon", "LabAP", 6))
        self.assertEqual(seen["mode"], 0o600)
        self.assertIn("wpa_passphrase=", seen["config"])
        conf_path = run.call_args.args[0][4]
        self.assertFalse(os.path.exists(conf_path))


if __name__ == "__main__":
    unittest.main()
