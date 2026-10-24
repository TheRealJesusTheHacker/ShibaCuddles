"""Sweep #5 regression tests.

1. _is_private_target CGNAT guardrail: a target that merely OVERLAPS
   100.64.0.0/10 (e.g. 100.0.0.0/8, mostly public) must not be
   classified private -- the old overlaps() check skipped the
   authorization warning for it. Only targets wholly inside the
   CGNAT range count as private via that check.
2. ResultsHandler.generate_report summary counts for dict results:
   the exporters accept dicts, and the report's HOST DETAILS section
   handled them, but the SUMMARY used getattr() on the dicts and
   always reported 0 alive / 0 open ports.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import _is_private_target
from src.results_handler import ResultsHandler
from src.scanner import ScanResult


class TestPrivateTargetCgnat:
    def test_cgnat_range_itself_is_private(self):
        assert _is_private_target("100.64.0.0/10") is True

    def test_cgnat_subnet_is_private(self):
        assert _is_private_target("100.64.1.0/24") is True
        assert _is_private_target("100.127.0.0/16") is True

    def test_supernet_merely_overlapping_cgnat_is_not_private(self):
        # 100.0.0.0/8 contains the CGNAT /10 but is mostly public.
        assert _is_private_target("100.0.0.0/8") is False
        # 100.64.0.0/9 is half CGNAT, half public (100.128.0.0/9 side
        # is inside the /9's second half) -- not wholly private.
        assert _is_private_target("100.0.0.0/9") is False

    def test_public_neighbour_of_cgnat_is_not_private(self):
        assert _is_private_target("100.128.0.0/9") is False
        assert _is_private_target("8.8.8.0/24") is False

    def test_rfc1918_still_private(self):
        assert _is_private_target("10.0.0.0/8") is True
        assert _is_private_target("172.16.0.0/12") is True
        assert _is_private_target("192.168.1.0/24") is True

    def test_ipv6_does_not_raise_and_classifies(self):
        # subnet_of against the v4 CGNAT range would raise TypeError
        # for v6 targets without the version guard.
        assert _is_private_target("::1/128") is True
        assert _is_private_target("2001:4860:4860::/48") is False

    def test_invalid_is_not_private(self):
        assert _is_private_target("not-a-network") is False


class TestGenerateReportDictResults:
    def test_dict_summary_counts(self):
        report = ResultsHandler().generate_report(
            [
                {"ip": "192.168.1.1", "alive": True, "open_ports": [80, 443]},
                {"ip": "192.168.1.2", "alive": False, "open_ports": []},
                {"ip": "192.168.1.3", "alive": True, "open_ports": [22]},
            ]
        )
        assert "Total Hosts Scanned: 3" in report
        assert "Alive Hosts: 2" in report
        assert "Dead Hosts: 1" in report
        assert "Total Open Ports: 3" in report

    def test_dataclass_summary_counts_unchanged(self):
        report = ResultsHandler().generate_report(
            [
                ScanResult(ip="192.168.1.1", alive=True, open_ports=[80]),
                ScanResult(ip="192.168.1.2", alive=False, open_ports=[]),
            ]
        )
        assert "Alive Hosts: 1" in report
        assert "Total Open Ports: 1" in report
