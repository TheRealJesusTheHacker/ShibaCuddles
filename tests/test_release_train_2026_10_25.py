"""Release-train functional regressions (2026-10-25).

Found by exercising the CLI and GUI end-to-end against a local fixture
listener on 127.0.0.1 (a fake SSH banner), not by reading code alone:

1. A --no-ping scan reported "Alive: 0 | Dead: 0" in its statistics
   even though it scanned (and found alive) every target: scan() only
   set the alive/dead counters on the ping-sweep path.
2. The service line in printed and TXT-exported results lost its
   indentation: the formatted string was .strip()ed (to drop a
   trailing space when no version was detected), which also removed
   the leading spaces that nest it under "Services:".
3. GUI export: the overwrite confirmation checked the path the user
   typed BEFORE the format extension was appended, so exporting to a
   bare name ("report") silently overwrote an existing "report.json"
   without ever asking. And when the prompt WAS reached (name typed
   with its extension), it used the Qt5-era QMessageBox.Yes/No, which
   do not exist in PyQt6 — the export raised AttributeError and died.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.results_handler import ResultsHandler
from src.scanner import NetworkScanner, ScanResult


def _no_ping_scanner(monkeypatch, open_ports=(22,)):
    scanner = NetworkScanner(network="192.168.1.10/32")
    scanner.ping_sweep = False
    monkeypatch.setattr(
        scanner.port_scanner, "scan", lambda host, spec: list(open_ports)
    )
    return scanner


class TestNoPingStatistics:
    def test_alive_stats_count_scanned_hosts(self, monkeypatch):
        scanner = _no_ping_scanner(monkeypatch)
        results = scanner.scan("22")
        assert len(results) == 1
        assert scanner.stats["total_hosts"] == 1
        assert scanner.stats["alive_hosts"] == 1
        assert scanner.stats["dead_hosts"] == 0

    def test_statistics_line_is_consistent(self, monkeypatch):
        scanner = _no_ping_scanner(monkeypatch)
        scanner.scan("22")
        line = scanner._format_statistics()
        assert "Alive: 1" in line
        assert "Dead: 0" in line


class TestServiceLineIndentation:
    def test_printed_service_line_keeps_indent(self, capsys):
        scanner = NetworkScanner(network="192.168.1.10/32")
        result = ScanResult(
            ip="192.168.1.10",
            alive=True,
            open_ports=[22],
            services={22: {"name": "SSH", "version": "9.6"}},
        )
        scanner.print_results([result])
        out = capsys.readouterr().out
        assert "    22: SSH 9.6" in out

    def test_txt_export_service_line_keeps_indent(self, tmp_path):
        result = ScanResult(
            ip="192.168.1.10",
            alive=True,
            open_ports=[22],
            services={22: {"name": "SSH", "version": "9.6"}},
        )
        path = tmp_path / "results.txt"
        assert ResultsHandler().save([result], str(path), "txt") is True
        assert "  22: SSH 9.6" in path.read_text(encoding="utf-8")


class TestGuiExportOverwritePrompt:
    @pytest.mark.parametrize("typed_name", ["report", "report.json"])
    def test_bare_name_export_prompts_before_overwriting(
        self, monkeypatch, tmp_path, typed_name
    ):
        # Same Qt-availability guard as test_decision_wave's GUI test:
        # skip (never fail) where the PyQt6 stack cannot load.
        try:
            from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox

            import gui.main_window as gw
        except (ImportError, SystemExit) as e:
            pytest.skip(f"PyQt6 GUI stack unavailable in this environment: {e}")
        import os

        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = QApplication.instance() or QApplication([])

        existing = tmp_path / "report.json"
        existing.write_text("ORIGINAL", encoding="utf-8")

        asked = []
        monkeypatch.setattr(
            QMessageBox,
            "question",
            staticmethod(
                lambda *a, **k: asked.append(a) or QMessageBox.StandardButton.No
            ),
        )
        monkeypatch.setattr(
            QMessageBox, "information", staticmethod(lambda *a, **k: None)
        )
        monkeypatch.setattr(QMessageBox, "critical", staticmethod(lambda *a, **k: None))
        monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))
        # The user picks JSON in the dialog; typed_name is either the
        # bare name ("report") or the full name ("report.json").
        monkeypatch.setattr(
            QFileDialog,
            "getSaveFileName",
            staticmethod(lambda *a, **k: (str(tmp_path / typed_name), "JSON (*.json)")),
        )

        window = gw.ShibaCuddlesGUI()
        try:
            window.scan_results = [
                ScanResult(ip="192.168.1.10", alive=True, open_ports=[22])
            ]
            window.export_results()
            # The prompt must have been asked about report.json, and
            # answering No must have left the file untouched.
            assert asked, "overwrite prompt was never shown for report.json"
            assert existing.read_text(encoding="utf-8") == "ORIGINAL"
        finally:
            window.close()
            app.quit()
