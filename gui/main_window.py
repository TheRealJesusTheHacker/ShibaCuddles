"""
ShibaCuddles GUI - Main Window
PyQt6-based graphical interface for network scanning and security testing.
"""

import sys
import threading
from typing import List, Dict
from datetime import datetime

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QTableWidget, QTableWidgetItem, QPushButton, QLineEdit,
        QLabel, QComboBox, QSpinBox, QCheckBox, QProgressBar, QTextEdit,
        QFileDialog, QMessageBox, QDialog, QDialogButtonBox, QGroupBox,
        QFrame, QGridLayout
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QColor, QFont, QIcon
    from PyQt6.QtChart import QChart, QChartView, QBarSeries, QBarSet, QBarCategoryAxis, QValueAxis
except ImportError:
    print("PyQt6 not installed. Install with: pip install PyQt6 PyQt6-Charts")
    sys.exit(1)

import logging
from src.scanner import NetworkScanner
from src.results_handler import ResultsHandler

try:
    from src import __version__ as _APP_VERSION
except Exception:
    _APP_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
_ACCENT = "#3ddc84"        # mint green accent
_ACCENT_DARK = "#2bb673"
_BG = "#14161b"            # app background
_PANEL = "#1b1f27"         # sidebar / card background
_PANEL_ALT = "#20242e"     # raised elements
_BORDER = "#2c313d"
_TEXT = "#e8ebf1"
_TEXT_DIM = "#9aa3b2"
_DANGER = "#f05555"
_MONO = "'JetBrains Mono', 'Cascadia Code', Consolas, monospace"


class ScannerThread(QThread):
    """
    Worker thread for network scanning.
    """
    progress = pyqtSignal(int)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, network: str, ports: str, threads: int, timeout: float,
                 ping_sweep: bool = True, service_detection: bool = False,
                 os_detection: bool = False, aggressive: bool = False):
        super().__init__()
        self.network = network
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.ping_sweep = ping_sweep
        self.service_detection = service_detection
        self.os_detection = os_detection
        self.aggressive = aggressive
        self.logger = logging.getLogger(__name__)
        self._stop_event = threading.Event()

    def request_stop(self):
        """Request a cooperative stop of the running scan."""
        self._stop_event.set()

    def run(self):
        """Run the scan in background thread."""
        try:
            scanner = NetworkScanner(
                network=self.network,
                threads=self.threads,
                timeout=self.timeout,
                logger=self.logger,
                stop_event=self._stop_event
            )
            scanner.ping_sweep = self.ping_sweep
            if self.aggressive:
                scanner.enable_service_detection = True
                scanner.enable_os_detection = True
            else:
                scanner.enable_service_detection = self.service_detection
                scanner.enable_os_detection = self.os_detection

            results = scanner.scan(self.ports)
            self.finished.emit(results)

        except Exception as e:
            self.error.emit(str(e))


class StatCard(QFrame):
    """Small KPI card used on the Statistics tab."""

    def __init__(self, label: str, value: str = "—", accent: str = _TEXT):
        super().__init__()
        self.setObjectName("statCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(4)

        self.value_label = QLabel(value)
        self.value_label.setObjectName("statValue")
        self.value_label.setStyleSheet(f"color: {accent};")
        layout.addWidget(self.value_label)

        caption = QLabel(label.upper())
        caption.setObjectName("statLabel")
        layout.addWidget(caption)

    def set_value(self, value: str):
        self.value_label.setText(value)


class ShibaCuddlesGUI(QMainWindow):
    """
    Main GUI window for ShibaCuddles scanner.

    Features:
    - Network scanning with real-time progress
    - Results visualization and filtering
    - Multi-format export
    - Advanced scanning options
    - Service detection toggle
    - OS fingerprinting
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("ShibaCuddles - Advanced Network Scanner")
        self.setGeometry(100, 100, 1240, 820)
        self.setMinimumSize(1024, 680)

        self.scanner_thread = None
        self.scan_results = []
        self.logger = logging.getLogger(__name__)

        self._init_ui()
        self._setup_styles()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _init_ui(self):
        """Initialize user interface components."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        root = QVBoxLayout(central_widget)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header bar
        root.addWidget(self._create_header())

        # Thin accent divider
        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet(f"background-color: {_ACCENT};")
        root.addWidget(divider)

        # Body: sidebar + tabs
        body = QHBoxLayout()
        body.setContentsMargins(16, 16, 16, 16)
        body.setSpacing(16)

        sidebar = self._create_config_panel()
        sidebar_widget = QWidget()
        sidebar_widget.setLayout(sidebar)
        sidebar_widget.setObjectName("sidebar")
        sidebar_widget.setFixedWidth(300)

        tabs = self._create_tabs()

        body.addWidget(sidebar_widget)
        body.addWidget(tabs, 1)
        root.addLayout(body, 1)

        # Status bar
        self.statusBar().showMessage("Ready")

    def _create_header(self) -> QWidget:
        """Top brand bar."""
        bar = QWidget()
        bar.setObjectName("headerBar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 12, 20, 12)

        title = QLabel("ShibaCuddles")
        title.setObjectName("brandTitle")
        layout.addWidget(title)

        subtitle = QLabel("Advanced Network Scanner")
        subtitle.setObjectName("brandSubtitle")
        layout.addWidget(subtitle)

        layout.addStretch()

        version = QLabel(f"v{_APP_VERSION}")
        version.setObjectName("versionBadge")
        layout.addWidget(version)

        return bar

    def _create_config_panel(self) -> QVBoxLayout:
        """Create left configuration panel."""
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # --- Target group ---
        target = QGroupBox("Target")
        t_layout = QVBoxLayout(target)
        t_layout.setSpacing(6)

        t_layout.addWidget(QLabel("Network (CIDR)"))
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("192.168.1.0/24")
        t_layout.addWidget(self.network_input)

        t_layout.addWidget(QLabel("Ports"))
        self.port_input = QLineEdit()
        self.port_input.setText("1-1024")
        self.port_input.setPlaceholderText("e.g. 1-1024, 80,443, 22-25")
        t_layout.addWidget(self.port_input)
        layout.addWidget(target)

        # --- Performance group ---
        perf = QGroupBox("Performance")
        p_layout = QGridLayout(perf)
        p_layout.setColumnStretch(1, 1)

        p_layout.addWidget(QLabel("Threads"), 0, 0)
        self.threads_spinner = QSpinBox()
        self.threads_spinner.setMinimum(1)
        self.threads_spinner.setMaximum(64)
        self.threads_spinner.setValue(10)
        p_layout.addWidget(self.threads_spinner, 0, 1)

        p_layout.addWidget(QLabel("Timeout (s)"), 1, 0)
        self.timeout_spinner = QSpinBox()
        self.timeout_spinner.setMinimum(1)
        self.timeout_spinner.setMaximum(60)
        self.timeout_spinner.setValue(5)
        p_layout.addWidget(self.timeout_spinner, 1, 1)
        layout.addWidget(perf)

        # --- Options group ---
        opts = QGroupBox("Scan Options")
        o_layout = QVBoxLayout(opts)
        o_layout.setSpacing(8)

        self.ping_sweep_check = QCheckBox("Ping sweep")
        self.ping_sweep_check.setChecked(True)
        o_layout.addWidget(self.ping_sweep_check)

        self.service_detection_check = QCheckBox("Service detection")
        o_layout.addWidget(self.service_detection_check)

        self.os_detection_check = QCheckBox("OS fingerprinting")
        o_layout.addWidget(self.os_detection_check)

        self.aggressive_check = QCheckBox("Aggressive scan")
        self.aggressive_check.setToolTip(
            "Enables service detection and OS fingerprinting together."
        )
        o_layout.addWidget(self.aggressive_check)
        layout.addWidget(opts)

        # --- Actions ---
        layout.addSpacing(6)
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setObjectName("primaryButton")
        self.scan_button.setMinimumHeight(42)
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("secondaryButton")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        row.addWidget(self.stop_button)

        self.export_button = QPushButton("Export")
        self.export_button.setObjectName("secondaryButton")
        self.export_button.clicked.connect(self.export_results)
        row.addWidget(self.export_button)
        layout.addLayout(row)

        # --- Progress ---
        layout.addSpacing(6)
        progress_label = QLabel("Progress")
        progress_label.setObjectName("sectionLabel")
        layout.addWidget(progress_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)

        layout.addStretch()
        return layout

    def _create_tabs(self) -> QTabWidget:
        """Create tabbed interface for results."""
        tabs = QTabWidget()
        tabs.setDocumentMode(True)

        # Results table tab
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(
            ["IP Address", "Status", "Open Ports", "Services", "OS"]
        )
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, header.ResizeMode.Stretch)
        header.setSectionResizeMode(1, header.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, header.ResizeMode.Stretch)
        header.setSectionResizeMode(3, header.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, header.ResizeMode.Stretch)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(
            self.results_table.SelectionBehavior.SelectRows
        )
        self.results_table.setEditTriggers(
            self.results_table.EditTrigger.NoEditTriggers
        )
        tabs.addTab(self.results_table, "Results")

        # Statistics tab
        stats_page = QWidget()
        stats_layout = QVBoxLayout(stats_page)
        stats_layout.setContentsMargins(4, 12, 4, 4)
        stats_layout.setSpacing(12)

        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)
        self.card_hosts = StatCard("Hosts scanned")
        self.card_alive = StatCard("Hosts alive", accent=_ACCENT)
        self.card_ports = StatCard("Open ports", accent="#6cb8ff")
        self.card_avg = StatCard("Avg ports / host", accent="#c9a6ff")
        for card in (self.card_hosts, self.card_alive,
                     self.card_ports, self.card_avg):
            cards_row.addWidget(card)
        stats_layout.addLayout(cards_row)

        detail_label = QLabel("Scan Summary")
        detail_label.setObjectName("sectionLabel")
        stats_layout.addWidget(detail_label)
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setObjectName("consoleText")
        stats_layout.addWidget(self.stats_text, 1)
        tabs.addTab(stats_page, "Statistics")

        # Log tab
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setObjectName("consoleText")
        tabs.addTab(self.log_text, "Activity Log")

        return tabs

    # ------------------------------------------------------------------
    # Styling
    # ------------------------------------------------------------------
    def _setup_styles(self):
        """Setup application styles."""
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {_BG};
                color: {_TEXT};
                font-family: "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif;
                font-size: 13px;
            }}
            #headerBar {{
                background-color: {_PANEL};
            }}
            #brandTitle {{
                font-size: 20px;
                font-weight: 800;
                color: {_TEXT};
                letter-spacing: 0.5px;
            }}
            #brandSubtitle {{
                font-size: 13px;
                color: {_TEXT_DIM};
                padding-left: 8px;
            }}
            #versionBadge {{
                background-color: {_PANEL_ALT};
                border: 1px solid {_BORDER};
                border-radius: 10px;
                padding: 4px 12px;
                color: {_ACCENT};
                font-weight: 600;
            }}
            #sidebar {{
                background-color: {_PANEL};
                border: 1px solid {_BORDER};
                border-radius: 10px;
            }}
            QGroupBox {{
                font-weight: 700;
                font-size: 12px;
                letter-spacing: 1px;
                text-transform: uppercase;
                color: {_TEXT_DIM};
                border: 1px solid {_BORDER};
                border-radius: 8px;
                margin-top: 14px;
                padding-top: 10px;
                background-color: {_BG};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 12px;
                padding: 0 6px;
                background-color: {_BG};
            }}
            QLabel {{
                color: {_TEXT};
            }}
            #sectionLabel {{
                color: {_TEXT_DIM};
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 1px;
                text-transform: uppercase;
            }}
            QLineEdit, QSpinBox, QComboBox {{
                background-color: {_PANEL_ALT};
                border: 1px solid {_BORDER};
                border-radius: 6px;
                padding: 8px 10px;
                color: {_TEXT};
                selection-background-color: {_ACCENT_DARK};
            }}
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
                border: 1px solid {_ACCENT};
            }}
            QLineEdit::placeholder {{
                color: #5c6575;
            }}
            QCheckBox {{
                color: {_TEXT};
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
                border-radius: 4px;
                border: 1px solid {_BORDER};
                background-color: {_PANEL_ALT};
            }}
            QCheckBox::indicator:checked {{
                background-color: {_ACCENT};
                border: 1px solid {_ACCENT};
            }}
            QPushButton {{
                border-radius: 7px;
                padding: 10px 14px;
                font-weight: 600;
                border: 1px solid {_BORDER};
                background-color: {_PANEL_ALT};
                color: {_TEXT};
            }}
            QPushButton:hover {{
                border-color: {_ACCENT};
            }}
            QPushButton:disabled {{
                color: #5c6575;
                background-color: #1a1d24;
                border-color: #242932;
            }}
            #primaryButton {{
                background-color: {_ACCENT};
                border: none;
                color: #0c1410;
                font-size: 14px;
                font-weight: 700;
            }}
            #primaryButton:hover {{
                background-color: {_ACCENT_DARK};
            }}
            #primaryButton:disabled {{
                background-color: #243028;
                color: #5c6575;
            }}
            QProgressBar {{
                background-color: {_PANEL_ALT};
                border: 1px solid {_BORDER};
                border-radius: 6px;
                text-align: center;
                color: {_TEXT};
                height: 18px;
            }}
            QProgressBar::chunk {{
                background-color: {_ACCENT};
                border-radius: 5px;
            }}
            QTabWidget::pane {{
                border: 1px solid {_BORDER};
                border-radius: 8px;
                background-color: {_PANEL};
                top: -1px;
            }}
            QTabBar::tab {{
                background-color: transparent;
                color: {_TEXT_DIM};
                padding: 10px 22px;
                margin-right: 4px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-weight: 600;
            }}
            QTabBar::tab:selected {{
                color: {_ACCENT};
                background-color: {_PANEL};
                border: 1px solid {_BORDER};
                border-bottom: none;
            }}
            QTabBar::tab:hover:!selected {{
                color: {_TEXT};
            }}
            QTableWidget {{
                background-color: {_PANEL};
                alternate-background-color: #181c23;
                border: none;
                border-radius: 8px;
                gridline-color: {_BORDER};
                selection-background-color: #233026;
                selection-color: {_TEXT};
                outline: none;
            }}
            QHeaderView::section {{
                background-color: {_PANEL_ALT};
                color: {_TEXT_DIM};
                font-weight: 700;
                font-size: 12px;
                letter-spacing: 0.5px;
                text-transform: uppercase;
                border: none;
                border-bottom: 1px solid {_BORDER};
                padding: 10px 8px;
            }}
            #statCard {{
                background-color: {_PANEL};
                border: 1px solid {_BORDER};
                border-radius: 10px;
            }}
            #statValue {{
                font-size: 30px;
                font-weight: 800;
            }}
            #statLabel {{
                font-size: 11px;
                letter-spacing: 1.5px;
                color: {_TEXT_DIM};
                font-weight: 700;
            }}
            #consoleText {{
                background-color: #0d0f13;
                border: 1px solid {_BORDER};
                border-radius: 8px;
                font-family: {_MONO};
                font-size: 12px;
                color: #c8cdd6;
                padding: 8px;
            }}
            QStatusBar {{
                background-color: {_PANEL};
                color: {_TEXT_DIM};
                border-top: 1px solid {_BORDER};
            }}
            QMessageBox {{
                background-color: {_PANEL};
            }}
        """)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _log(self, message: str, level: str = "info"):
        """Append a timestamped, color-coded line to the activity log."""
        ts = datetime.now().strftime("%H:%M:%S")
        colors = {"info": "#9aa3b2", "ok": _ACCENT, "error": _DANGER,
                  "warn": "#f0b429"}
        color = colors.get(level, colors["info"])
        self.log_text.append(
            f'<span style="color:#5c6575;">[{ts}]</span> '
            f'<span style="color:{color};">{message}</span>'
        )

    # ------------------------------------------------------------------
    # Scan control
    # ------------------------------------------------------------------
    def start_scan(self):
        """Start network scan."""
        network = self.network_input.text().strip()
        ports = self.port_input.text().strip()
        threads = self.threads_spinner.value()
        timeout = self.timeout_spinner.value()

        if not network:
            QMessageBox.warning(self, "Missing Target",
                                "Please enter a target network in CIDR notation.")
            return

        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scanning…")
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.statusBar().showMessage(f"Scanning {network} …")
        self._log(f"Starting scan on {network} (ports {ports or 'default'})")

        self.scanner_thread = ScannerThread(
            network, ports, threads, timeout,
            ping_sweep=self.ping_sweep_check.isChecked(),
            service_detection=self.service_detection_check.isChecked(),
            os_detection=self.os_detection_check.isChecked(),
            aggressive=self.aggressive_check.isChecked(),
        )
        self.scanner_thread.finished.connect(self.on_scan_finished)
        self.scanner_thread.error.connect(self.on_scan_error)
        self.scanner_thread.start()

    def stop_scan(self):
        """Stop current scan."""
        if self.scanner_thread and self.scanner_thread.isRunning():
            # Cooperative stop: quit() alone is a no-op here because the
            # thread runs scan() directly without an event loop.
            self.scanner_thread.request_stop()
            self.scanner_thread.wait()
            self._log("Scan stopped by user", "warn")

        self.scan_button.setEnabled(True)
        self.scan_button.setText("Start Scan")
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage("Ready")

    def on_scan_finished(self, results: List):
        """Handle scan completion."""
        self.scan_results = results
        self.progress_bar.setValue(100)
        self._log(f"Scan completed — {len(results)} host(s) found", "ok")

        # Populate results table
        self.results_table.setRowCount(len(results))
        for row, result in enumerate(results):
            ip = result.ip
            alive = bool(result.alive)
            ports = ", ".join(map(str, result.open_ports[:8]))
            if len(result.open_ports) > 8:
                ports += f" (+{len(result.open_ports) - 8} more)"
            services = str(len(result.services)) if result.services else "0"
            os_name = (result.os_info.get("name", "Unknown")
                       if result.os_info else "Unknown")

            ip_item = QTableWidgetItem(ip)
            mono = QFont("Consolas", 10)
            mono.setStyleHint(QFont.StyleHint.Monospace)
            ip_item.setFont(mono)

            status_item = QTableWidgetItem("● ALIVE" if alive else "○ DOWN")
            status_item.setForeground(
                QColor(_ACCENT) if alive else QColor(_TEXT_DIM))
            font = status_item.font()
            font.setBold(True)
            status_item.setFont(font)

            self.results_table.setItem(row, 0, ip_item)
            self.results_table.setItem(row, 1, status_item)
            self.results_table.setItem(row, 2, QTableWidgetItem(ports))
            self.results_table.setItem(row, 3, QTableWidgetItem(services))
            self.results_table.setItem(row, 4, QTableWidgetItem(os_name))

        # Update statistics
        self._update_statistics(results)

        self.scan_button.setEnabled(True)
        self.scan_button.setText("Start Scan")
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(
            f"Scan completed — {sum(1 for r in results if r.alive)} host(s) alive")

    def on_scan_error(self, error: str):
        """Handle scan errors."""
        self._log(f"Scan error: {error}", "error")
        QMessageBox.critical(self, "Scan Error", f"An error occurred:\n{error}")

        self.scan_button.setEnabled(True)
        self.scan_button.setText("Start Scan")
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage("Ready")

    def _update_statistics(self, results: List):
        """Update statistics tab."""
        total_hosts = len(results)
        alive_hosts = sum(1 for r in results if r.alive)
        total_ports = sum(len(r.open_ports) for r in results)
        avg = total_ports / max(alive_hosts, 1)

        self.card_hosts.set_value(str(total_hosts))
        self.card_alive.set_value(str(alive_hosts))
        self.card_ports.set_value(str(total_ports))
        self.card_avg.set_value(f"{avg:.1f}")

        lines = [
            f"Hosts scanned:      {total_hosts}",
            f"Hosts alive:        {alive_hosts}",
            f"Hosts down:         {total_hosts - alive_hosts}",
            f"Total open ports:   {total_ports}",
            f"Avg ports / host:   {avg:.2f}",
        ]
        if alive_hosts:
            top = sorted(results, key=lambda r: len(r.open_ports),
                         reverse=True)[:5]
            lines.append("")
            lines.append("Top hosts by open ports:")
            for r in top:
                lines.append(f"  {r.ip:<18} {len(r.open_ports):>3} open")
        self.stats_text.setPlainText("\n".join(lines))

    def export_results(self):
        """Export scan results to file."""
        if not self.scan_results:
            QMessageBox.warning(self, "No Results",
                                "There are no scan results to export yet.")
            return

        file_path, file_format = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "",
            "JSON (*.json);;CSV (*.csv);;XML (*.xml);;Text (*.txt)"
        )

        if file_path:
            format_map = {
                "*.json": "json",
                "*.csv": "csv",
                "*.xml": "xml",
                "*.txt": "txt"
            }

            export_format = format_map.get(
                file_format.split("(")[1].split(")")[0] if "(" in file_format else "json",
                "json"
            )

            handler = ResultsHandler()
            if handler.save(self.scan_results, file_path, export_format):
                QMessageBox.information(
                    self,
                    "Export Successful",
                    f"Results exported to:\n{file_path}"
                )
                self._log(f"Results exported to {file_path}", "ok")
            else:
                QMessageBox.critical(self, "Export Failed",
                                     "Failed to export results.")


def main():
    """Main entry point for GUI."""
    app = QApplication(sys.argv)
    window = ShibaCuddlesGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
