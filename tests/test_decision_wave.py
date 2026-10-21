#!/usr/bin/env python3
"""Tests for the 2026-10-21 decision-execution wave.

* S-2: analyze_traffic_patterns parses the capture for real. A fixture
  pcap with a known protocol/IP mix must produce a breakdown matching
  ground truth, end to end through the capture path; with scapy absent
  the result must say parsing is unavailable instead of returning
  zeroed numbers dressed as analysis.
* S-3: UDPScanner / VulnerabilityScanner are wired into the scan
  pipeline, the CLI (--udp / --vuln-scan) and the GUI toggles, and the
  results reach the presented output.
"""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.deauth import NetworkInterruptor, parse_pcap_file
from src.scanner import NetworkScanner

scapy = pytest.importorskip("scapy.all")
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, wrpcap  # noqa: E402

A = "192.168.1.10"
B = "192.168.1.20"


def _fixture_pcap(tmp_path) -> str:
    """7 packets: TCP x3, UDP x2, ICMP x1, ARP x1 with known talkers."""
    packets = [
        Ether() / IP(src=A, dst=B) / TCP(dport=80),
        Ether() / IP(src=A, dst=B) / TCP(dport=443),
        Ether() / IP(src=B, dst=A) / TCP(sport=80),
        Ether() / IP(src=A, dst="8.8.8.8") / UDP(dport=53),
        Ether() / IP(src=A, dst="8.8.8.8") / UDP(dport=53),
        Ether() / IP(src=A, dst=B) / ICMP(),
        Ether() / ARP(psrc=A, pdst=B),
    ]
    path = str(tmp_path / "fixture.pcap")
    wrpcap(path, packets)
    return path


# ---------------------------------------------------------------------------
# S-2: ground truth
# ---------------------------------------------------------------------------


def test_parse_pcap_matches_ground_truth(tmp_path):
    stats = parse_pcap_file(_fixture_pcap(tmp_path))
    assert stats["parsing_available"] is True
    assert stats["total_packets"] == 7
    assert stats["protocols"] == {"TCP": 3, "UDP": 2, "ICMP": 1, "ARP": 1}
    assert stats["src_ips"] == {A: 6, B: 1}
    assert stats["dst_ips"] == {B: 4, A: 1, "8.8.8.8": 2}
    assert stats["top_ips"][0] == {"ip": A, "packets": 7}
    assert stats["top_sources"][0] == {"ip": A, "packets": 6}
    assert stats["top_destinations"][0] == {"ip": B, "packets": 4}


def test_parse_pcap_empty_file_is_zero_not_unavailable(tmp_path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    stats = parse_pcap_file(str(empty))
    assert stats["parsing_available"] is True
    assert stats["total_packets"] == 0
    assert stats["protocols"] == {}


def test_analyze_traffic_end_to_end(tmp_path):
    fixture = _fixture_pcap(tmp_path)

    def fake_run(cmd, **kwargs):
        # tcpdump's argv ends with "-w <pcap_path>": stand in for the
        # capture by copying the known fixture over that path.
        target = cmd[cmd.index("-w") + 1]
        Path(target).write_bytes(Path(fixture).read_bytes())
        return subprocess.CompletedProcess(cmd, 0)

    with patch("src.deauth.subprocess.run", side_effect=fake_run):
        stats = NetworkInterruptor().analyze_traffic_patterns("wlan0mon", duration=5)
    assert stats["duration"] == 5
    assert stats["parsing_available"] is True
    assert stats["total_packets"] == 7
    assert stats["protocols"] == {"TCP": 3, "UDP": 2, "ICMP": 1, "ARP": 1}
    assert stats["top_ips"][0] == {"ip": A, "packets": 7}


# ---------------------------------------------------------------------------
# S-2: scapy absent -> honest unavailable, never fabricated zeros
# ---------------------------------------------------------------------------


def _without_scapy(monkeypatch):
    for name in [m for m in list(sys.modules) if m.startswith("scapy")]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "scapy", None)


def test_parse_pcap_without_scapy_is_honest(tmp_path, monkeypatch):
    fixture = _fixture_pcap(tmp_path)  # build BEFORE scapy is blocked
    _without_scapy(monkeypatch)
    stats = parse_pcap_file(fixture)
    assert stats["parsing_available"] is False
    assert stats["total_packets"] is None
    assert "scapy" in stats["parsing_unavailable_reason"]


def test_analyze_without_scapy_is_honest(monkeypatch):
    _without_scapy(monkeypatch)
    with patch("src.deauth.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0)
        stats = NetworkInterruptor().analyze_traffic_patterns("wlan0mon", duration=5)
    assert stats["parsing_available"] is False
    assert stats["total_packets"] is None
    assert stats["protocols"] == {}


# ---------------------------------------------------------------------------
# S-3: pipeline wiring
# ---------------------------------------------------------------------------


def _scanner(**kwargs):
    scanner = NetworkScanner(network="192.168.1.10/32", **kwargs)
    scanner.ping_sweep = False
    return scanner


def test_udp_scan_reaches_results(monkeypatch):
    scanner = _scanner()
    scanner.enable_udp_scan = True
    monkeypatch.setattr(scanner.port_scanner, "scan", lambda h, spec: [22])
    monkeypatch.setattr(scanner.udp_scanner, "scan", lambda h, ports: [53])
    results = scanner.scan("22,53")
    assert results[0].open_ports == [22]
    assert results[0].udp_open_ports == [53]
    assert scanner.stats["udp_open_ports_found"] == 1


def test_udp_scan_off_by_default(monkeypatch):
    scanner = _scanner()
    monkeypatch.setattr(scanner.port_scanner, "scan", lambda h, spec: [22])
    called = []
    monkeypatch.setattr(
        scanner.udp_scanner, "scan", lambda h, p: called.append(1) or []
    )
    results = scanner.scan("22")
    assert results[0].udp_open_ports == []
    assert called == []


def test_vuln_scan_matches_detected_services(monkeypatch):
    scanner = _scanner()
    # Service detection itself NOT requested: vuln scan must imply it.
    scanner.enable_vuln_scan = True
    monkeypatch.setattr(scanner.port_scanner, "scan", lambda h, spec: [22])
    monkeypatch.setattr(
        scanner.service_detector,
        "detect_service",
        lambda h, p: {"name": "SSH", "version": "7.0", "protocol": "tcp"},
    )
    results = scanner.scan("22")
    assert results[0].services[22]["version"] == "7.0"
    assert any("CVE-2016-3113" in v for v in results[0].vulnerabilities.values())
    assert scanner.stats["vulnerabilities_found"] == 1


def test_vuln_scan_off_by_default(monkeypatch):
    scanner = _scanner()
    monkeypatch.setattr(scanner.port_scanner, "scan", lambda h, spec: [22])
    results = scanner.scan("22")
    assert results[0].vulnerabilities == {}
    assert results[0].services == {}


# ---------------------------------------------------------------------------
# S-3: CLI flags
# ---------------------------------------------------------------------------


def test_cli_flags_parse(monkeypatch):
    import main as cli

    monkeypatch.setattr(
        sys, "argv", ["main.py", "192.168.1.0/24", "--udp", "--vuln-scan"]
    )
    args = cli.parse_arguments()
    assert args.udp is True
    assert args.vuln_scan is True

    monkeypatch.setattr(sys, "argv", ["main.py", "192.168.1.0/24"])
    args = cli.parse_arguments()
    assert args.udp is False
    assert args.vuln_scan is False


def test_cli_flags_reach_scanner(monkeypatch):
    import main as cli

    seen = {}

    real_scanner = cli.NetworkScanner

    class RecordingScanner(real_scanner):
        def scan(self, spec):
            seen["udp"] = self.enable_udp_scan
            seen["vuln"] = self.enable_vuln_scan
            return []

    monkeypatch.setattr(cli, "NetworkScanner", RecordingScanner)
    monkeypatch.setattr(
        sys, "argv", ["main.py", "192.168.1.0/24", "--udp", "--vuln-scan"]
    )
    assert cli.main() == 0
    assert seen == {"udp": True, "vuln": True}


# ---------------------------------------------------------------------------
# S-3: GUI toggles (offscreen)
# ---------------------------------------------------------------------------


def test_gui_toggles_reach_engine(monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets")
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication

    import gui.main_window as gw

    app = QApplication.instance() or QApplication([])
    window = gw.ShibaCuddlesGUI()
    assert not window.udp_scan_check.isChecked()
    assert not window.vuln_scan_check.isChecked()
    window.udp_scan_check.setChecked(True)
    window.vuln_scan_check.setChecked(True)

    seen = {}

    class RecordingScanner(gw.NetworkScanner):
        def scan(self, spec):
            seen["udp"] = self.enable_udp_scan
            seen["vuln"] = self.enable_vuln_scan
            return []

    monkeypatch.setattr(gw, "NetworkScanner", RecordingScanner)
    thread = gw.ScannerThread(
        "192.168.1.0/24",
        "22",
        10,
        5,
        udp_scan=window.udp_scan_check.isChecked(),
        vuln_scan=window.vuln_scan_check.isChecked(),
    )
    finished = []
    thread.finished.connect(finished.append)
    thread.run()  # synchronous: no event loop needed
    assert seen == {"udp": True, "vuln": True}
    assert finished == [[]]
    window.close()
    app.quit()
