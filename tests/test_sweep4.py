"""Sweep #4 regression tests (2026-10-23).

Pin: parse_pcap_file streams the capture (PcapReader) instead of
rdpcap()'s load-everything-into-memory read, and malformed input is
reported as parsing-unavailable — never as an invented empty result
and never as a partial breakdown dressed up as a complete one.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.deauth import parse_pcap_file  # noqa: E402

scapy = pytest.importorskip("scapy", reason="pcap parsing needs scapy")


def _fixture_pcap(tmp_path):
    from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, wrpcap

    packets = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=5353),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
        Ether() / ARP(psrc="10.0.0.1", pdst="10.0.0.2"),
    ]
    path = str(tmp_path / "sweep4.pcap")
    wrpcap(path, packets)
    return path


def test_parse_pcap_streaming_matches_ground_truth(tmp_path):
    stats = parse_pcap_file(_fixture_pcap(tmp_path))
    assert stats["parsing_available"] is True
    assert stats["total_packets"] == 4
    assert stats["protocols"] == {"TCP": 1, "UDP": 1, "ICMP": 1, "ARP": 1}
    assert stats["src_ips"] == {"10.0.0.1": 3, "10.0.0.2": 1}
    assert stats["dst_ips"] == {"10.0.0.2": 3, "10.0.0.1": 1}


def test_parse_pcap_garbage_is_unavailable_not_zero(tmp_path):
    path = str(tmp_path / "garbage.pcap")
    with open(path, "wb") as f:
        f.write(b"\xff" * 200)
    stats = parse_pcap_file(path)
    assert stats["parsing_available"] is False
    assert stats["total_packets"] is None
    assert "could not be parsed" in stats["parsing_unavailable_reason"]


def test_parse_pcap_missing_file_is_unavailable(tmp_path):
    stats = parse_pcap_file(str(tmp_path / "does-not-exist.pcap"))
    assert stats["parsing_available"] is False
    assert stats["total_packets"] is None
