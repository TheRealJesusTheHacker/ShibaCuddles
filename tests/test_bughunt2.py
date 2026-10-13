#!/usr/bin/env python3
"""Regression tests for the 2026-10-13 round-2 bug hunt.

Each test pins a defect demonstrated against the pre-fix code:
banner-pattern precedence, UDP reply-source verification, the
parse_port_spec ValueError contract, skip_broadcast erasing targets,
discover_subnet's missing size cap, XML export control characters,
CSV export with open_ports=None, and jam_channel's duration floor.
"""

import logging
import socket
import unittest
import xml.dom.minidom as minidom
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from src.deauth import NetworkInterruptor
from src.device import DeviceDiscovery
from src.port_scanner import PortScanner, UDPScanner
from src.results_handler import ResultsHandler
from src.scanner import NetworkScanner, ScanResult
from src.service_detector import ServiceDetector, VulnerabilityScanner
from src.utils import parse_port_spec


class TestBannerPatternPrecedence(unittest.TestCase):
    """The generic HTTP "Server:" pattern captured the whole header
    value, so Apache/Nginx banners were reported as name="HTTP" with
    the product string as their "version"."""

    def setUp(self):
        self.detector = ServiceDetector()

    def test_apache_server_header_identifies_apache(self):
        info = self.detector._parse_banner(
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n", 80
        )
        self.assertEqual(info["name"], "Apache")
        self.assertEqual(info["version"], "2.4.49")

    def test_apache_version_reaches_vulnerability_scanner(self):
        # The demo table has a CVE keyed to Apache 2.4.49; it can only
        # match if _parse_banner surfaces the product name + version.
        info = self.detector._parse_banner(
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n", 80
        )
        findings = VulnerabilityScanner().scan({80: info})
        self.assertEqual(list(findings), ["Apache-2.4.49"])

    def test_nginx_server_header_identifies_nginx(self):
        info = self.detector._parse_banner(
            "HTTP/1.1 200 OK\r\nServer: nginx/1.25.1\r\n\r\n", 8080
        )
        self.assertEqual(info["name"], "Nginx")
        self.assertEqual(info["version"], "1.25.1")

    def test_generic_server_header_still_http(self):
        info = self.detector._parse_banner(
            "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n", 80
        )
        self.assertEqual(info["name"], "HTTP")
        self.assertEqual(info["version"], "Microsoft-IIS/10.0")

    def test_ssh_banner_unchanged(self):
        info = self.detector._parse_banner("SSH-2.0-OpenSSH_8.9\r\n", 22)
        self.assertEqual(info["name"], "SSH")
        self.assertEqual(info["version"], "8.9")


class TestParsePortSpecContract(unittest.TestCase):
    """parse_port_spec documents ValueError for invalid specs, but
    non-string input raised AttributeError/TypeError instead, crashing
    callers that only catch ValueError (PortScanner.scan)."""

    def test_non_string_specs_raise_value_error(self):
        for bad in (None, 80, ["80"], {"p": 80}):
            with self.assertRaises(ValueError):
                parse_port_spec(bad)

    def test_scanner_scan_with_none_spec_returns_empty(self):
        scanner = PortScanner(threads=1, timeout=0.5)
        self.assertEqual(scanner.scan("127.0.0.1", None), [])

    def test_network_scan_ports_with_none_spec_returns_empty(self):
        scanner = NetworkScanner("127.0.0.0/30")
        self.assertEqual(scanner._scan_ports(["127.0.0.1"], None), [])


class TestUDPSourceVerification(unittest.TestCase):
    """An unconnected UDP socket receives datagrams from ANY sender;
    a stray packet must not mark the probed port open."""

    def _scan_with_reply(self, reply_addr, host="192.168.1.1", port=53):
        with patch("socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_sock.recvfrom.return_value = (b"data", reply_addr)
            mock_cls.return_value = mock_sock
            scanner = UDPScanner(timeout=1)
            return scanner.scan(host, [port])

    def test_reply_from_target_counts_open(self):
        self.assertEqual(
            self._scan_with_reply(("192.168.1.1", 53)), [53]
        )

    def test_reply_from_other_host_ignored(self):
        self.assertEqual(self._scan_with_reply(("10.9.9.9", 53)), [])

    def test_reply_from_wrong_port_ignored(self):
        self.assertEqual(
            self._scan_with_reply(("192.168.1.1", 9999)), []
        )

    def test_hostname_target_matches_resolved_address(self):
        infos = [
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 53))
        ]
        with patch("socket.getaddrinfo", return_value=infos):
            self.assertEqual(
                self._scan_with_reply(
                    ("127.0.0.1", 53), host="localhost", port=53
                ),
                [53],
            )
            self.assertEqual(
                self._scan_with_reply(
                    ("127.0.0.2", 53), host="localhost", port=53
                ),
                [],
            )


class TestSkipBroadcastTargets(unittest.TestCase):
    """skip_broadcast erased the only host of a /32 target and the
    last host of IPv6 ranges (broadcast is IPv4-only)."""

    def test_single_host_network_survives_skip_broadcast(self):
        scanner = NetworkScanner("192.168.1.5/32", skip_broadcast=True)
        self.assertEqual(scanner._get_target_hosts(), ["192.168.1.5"])

    def test_ipv6_range_keeps_all_hosts(self):
        scanner = NetworkScanner("2001:db8::/126", skip_broadcast=True)
        self.assertEqual(
            scanner._get_target_hosts(),
            ["2001:db8::1", "2001:db8::2", "2001:db8::3"],
        )

    def test_ipv4_broadcast_still_skipped(self):
        scanner = NetworkScanner("192.168.1.0/31", skip_broadcast=True)
        self.assertEqual(scanner._get_target_hosts(), ["192.168.1.0"])

    def test_normal_network_unaffected(self):
        scanner = NetworkScanner("192.168.1.0/30", skip_broadcast=True)
        self.assertEqual(
            scanner._get_target_hosts(), ["192.168.1.1", "192.168.1.2"]
        )


class TestDiscoverSubnetCap(unittest.TestCase):
    """discover_subnet materialized the full host list with no size
    ceiling, unlike NetworkScanner's 65,536-address limit."""

    def test_oversized_subnet_refused_without_discovering(self):
        discovery = DeviceDiscovery(timeout=0.2)
        with patch.object(
            DeviceDiscovery, "discover", return_value=[]
        ) as mock_discover:
            result = discovery.discover_subnet(
                "10.0.0.0/15", resolve_hostname=False
            )
        self.assertEqual(result, [])
        mock_discover.assert_not_called()

    def test_normal_subnet_still_discovers(self):
        discovery = DeviceDiscovery(timeout=0.2)
        with patch.object(
            DeviceDiscovery, "is_alive", return_value=False
        ):
            self.assertEqual(
                discovery.discover_subnet(
                    "192.168.1.0/30", resolve_hostname=False
                ),
                [],
            )


class TestExportEdgeCases(unittest.TestCase):
    def setUp(self):
        self.handler = ResultsHandler(logger=logging.getLogger("test"))
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _path(self, name):
        return str(Path(self.tmp.name) / name)

    def test_xml_export_survives_control_characters(self):
        # Banners are network-controlled; a version string carrying
        # XML-forbidden control bytes made save() return False while
        # the JSON/TXT exports of the same results succeeded.
        result = ScanResult(
            ip="192.168.1.1",
            alive=True,
            open_ports=[80],
            services={80: {"name": "HTTP", "version": "odd\x00\x0b\x1f srv"}},
            scan_time=1.0,
        )
        path = self._path("out.xml")
        self.assertTrue(self.handler.save([result], path, "xml", force=True))
        doc = minidom.parse(path)  # must be well-formed
        service = doc.getElementsByTagName("Service")[0]
        self.assertEqual(service.getAttribute("version"), "odd srv")

    def test_csv_export_with_none_open_ports(self):
        path = self._path("out.csv")
        ok = self.handler.save(
            [{"ip": "1.2.3.4", "alive": True, "open_ports": None,
              "scan_time": 0.5}],
            path, "csv", force=True,
        )
        self.assertTrue(ok)
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[1], "1.2.3.4,True,,0,0.5")

    def test_txt_export_with_none_open_ports(self):
        path = self._path("out.txt")
        ok = self.handler.save(
            [{"ip": "1.2.3.4", "alive": True, "open_ports": None}],
            path, "txt", force=True,
        )
        self.assertTrue(ok)
        self.assertIn("Open Ports: None", Path(path).read_text("utf-8"))


class TestJamChannelDurationFloor(unittest.TestCase):
    """duration <= 0 was not a no-op: the `timeout` backstop wrapper
    received duration+5 (0 disables it at duration=-5) and mdk3 was
    spawned before the negative sleep raised."""

    def _interruptor(self):
        n = NetworkInterruptor.__new__(NetworkInterruptor)
        n.logger = logging.getLogger("test")
        return n

    @patch("src.deauth.subprocess.Popen")
    @patch("src.deauth.require_scope_configured")
    def test_non_positive_duration_refused_without_spawning(self, _s, popen):
        n = self._interruptor()
        for bad in (0, -1, -5):
            self.assertFalse(n.jam_channel("wlan0mon", 6, duration=bad))
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
