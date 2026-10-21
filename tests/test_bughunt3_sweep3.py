#!/usr/bin/env python3
"""Regression tests for bug hunt sweep #3 (2026-10-21).

Each test pins a defect demonstrated against the pre-fix code:

* The CLI accepted an invalid --ports spec, logged one error line, and
  exited 0 with "No results to display" — a failed scan dressed as a
  completed empty one. (The GUI already validated the spec up front.)
  main() must now refuse the spec before scanning, exit code 1.
* VulnerabilityScanner never matched OpenSSH through the real
  pipeline: _parse_banner names the product "SSH" (its pattern key)
  while the vuln table is keyed "OpenSSH", so the OpenSSH CVEs were
  silently never reported.
* The vuln version match was a bare startswith: detected "7.05"
  matched known "7.0" and "2.4.490" matched "2.4.49", attributing CVEs
  to versions that never had them. A non-digit patch suffix ("7.0p1")
  must still match.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.service_detector import ServiceDetector, VulnerabilityScanner


def test_cli_refuses_invalid_port_spec(monkeypatch):
    import main as cli

    monkeypatch.setattr(sys, "argv", ["main.py", "192.168.1.0/24", "--ports", "bogus"])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 1


def test_cli_accepts_valid_port_spec_shape(monkeypatch):
    # Validation must not refuse good specs: stub the scan itself so
    # the test only proves main() gets past spec validation.
    import main as cli

    monkeypatch.setattr(
        sys, "argv", ["main.py", "192.168.1.0/24", "--ports", "22,80-90"]
    )
    monkeypatch.setattr(cli.NetworkScanner, "scan", lambda self, spec: [])
    assert cli.main() == 0


def test_openssh_banner_reaches_vuln_table():
    info = ServiceDetector()._parse_banner("SSH-2.0-OpenSSH_7.0", 22)
    findings = VulnerabilityScanner().scan({22: info})
    assert any("CVE-2016-3113" in v for v in findings.values())


def test_vuln_version_digit_boundary():
    vs = VulnerabilityScanner()
    # Digit continuation is a DIFFERENT version: no match.
    assert vs.scan({22: {"name": "OpenSSH", "version": "7.05"}}) == {}
    assert vs.scan({80: {"name": "Apache", "version": "2.4.490"}}) == {}
    # Exact and non-digit patch suffixes still match.
    assert vs.scan({22: {"name": "OpenSSH", "version": "7.0"}}) != {}
    assert vs.scan({22: {"name": "OpenSSH", "version": "7.0p1"}}) != {}
    assert vs.scan({80: {"name": "Apache", "version": "2.4.49"}}) != {}
