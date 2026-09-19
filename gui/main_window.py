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
        QFileDialog, QMessageBox, QDialog, QDialogButtonBox
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
        self.setGeometry(100, 100, 1200, 800)
        
        self.scanner_thread = None
        self.scan_results = []
        self.logger = logging.getLogger(__name__)
        
        self._init_ui()
        self._setup_styles()
    
    def _init_ui(self):
        """Initialize user interface components."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout(central_widget)
        
        # Left panel - Configuration
        left_panel = self._create_config_panel()
        
        # Right panel - Tabs
        tabs = self._create_tabs()
        
        main_layout.addLayout(left_panel, 1)
        main_layout.addWidget(tabs, 2)
        
        # Status bar
        self.statusBar().showMessage("Ready")
    
    def _create_config_panel(self) -> QVBoxLayout:
        """Create left configuration panel."""
        layout = QVBoxLayout()
        
        # Network input
        layout.addWidget(QLabel("Target Network (CIDR):"))
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("192.168.1.0/24")
        layout.addWidget(self.network_input)
        
        # Port range
        layout.addWidget(QLabel("Ports:"))
        self.port_input = QLineEdit()
        self.port_input.setText("1-1024")
        layout.addWidget(self.port_input)
        
        # Threads
        layout.addWidget(QLabel("Threads:"))
        self.threads_spinner = QSpinBox()
        self.threads_spinner.setMinimum(1)
        self.threads_spinner.setMaximum(64)
        self.threads_spinner.setValue(10)
        layout.addWidget(self.threads_spinner)
        
        # Timeout
        layout.addWidget(QLabel("Timeout (seconds):"))
        self.timeout_spinner = QSpinBox()
        self.timeout_spinner.setMinimum(1)
        self.timeout_spinner.setMaximum(60)
        self.timeout_spinner.setValue(5)
        layout.addWidget(self.timeout_spinner)
        
        # Features
        layout.addWidget(QLabel("Features:"))
        self.ping_sweep_check = QCheckBox("Ping Sweep")
        self.ping_sweep_check.setChecked(True)
        layout.addWidget(self.ping_sweep_check)
        
        self.service_detection_check = QCheckBox("Service Detection")
        layout.addWidget(self.service_detection_check)
        
        self.os_detection_check = QCheckBox("OS Fingerprinting")
        layout.addWidget(self.os_detection_check)
        
        self.aggressive_check = QCheckBox("Aggressive Scan")
        layout.addWidget(self.aggressive_check)
        
        # Buttons
        layout.addSpacing(20)
        self.scan_button = QPushButton("🔍 START SCAN")
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("⏹ STOP")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        layout.addWidget(self.stop_button)
        
        self.export_button = QPushButton("💾 EXPORT")
        self.export_button.clicked.connect(self.export_results)
        layout.addWidget(self.export_button)
        
        # Progress
        layout.addSpacing(20)
        layout.addWidget(QLabel("Progress:"))
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        layout.addStretch()
        
        # Return the layout itself: installing it on a container widget AND
        # returning a second layout for the same container silently drops
        # every widget (Qt refuses the second setLayout), leaving a blank panel.
        return layout
    
    def _create_tabs(self) -> QTabWidget:
        """Create tabbed interface for results."""
        tabs = QTabWidget()
        
        # Results table tab
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(
            ["IP Address", "Status", "Open Ports", "Services", "OS"]
        )
        tabs.addTab(self.results_table, "Scan Results")
        
        # Statistics tab
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        tabs.addTab(self.stats_text, "Statistics")
        
        # Log tab
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        tabs.addTab(self.log_text, "Logs")
        
        return tabs
    
    def _setup_styles(self):
        """Setup application styles."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QLabel {
                font-weight: bold;
                color: #333;
            }
            QLineEdit, QSpinBox {
                padding: 5px;
                border: 1px solid #ddd;
                border-radius: 3px;
                background-color: white;
            }
            QCheckBox {
                color: #333;
            }
            QPushButton {
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
        """)
    
    def start_scan(self):
        """Start network scan."""
        network = self.network_input.text().strip()
        ports = self.port_input.text().strip()
        threads = self.threads_spinner.value()
        timeout = self.timeout_spinner.value()
        
        if not network:
            QMessageBox.warning(self, "Error", "Please enter a target network")
            return
        
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Starting scan on {network}")
        
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
            self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Scan stopped by user")
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    
    def on_scan_finished(self, results: List):
        """Handle scan completion."""
        self.scan_results = results
        self.progress_bar.setValue(100)
        self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Scan completed - Found {len(results)} hosts")
        
        # Populate results table
        self.results_table.setRowCount(len(results))
        for row, result in enumerate(results):
            ip = result.ip
            status = "ALIVE" if result.alive else "DEAD"
            ports = ", ".join(map(str, result.open_ports[:5]))  # Show first 5
            services = str(len(result.services)) if result.services else "0"
            os_name = result.os_info.get("name", "Unknown") if result.os_info else "Unknown"
            
            self.results_table.setItem(row, 0, QTableWidgetItem(ip))
            self.results_table.setItem(row, 1, QTableWidgetItem(status))
            self.results_table.setItem(row, 2, QTableWidgetItem(ports))
            self.results_table.setItem(row, 3, QTableWidgetItem(services))
            self.results_table.setItem(row, 4, QTableWidgetItem(os_name))
        
        # Update statistics
        self._update_statistics(results)
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage("Scan completed")
    
    def on_scan_error(self, error: str):
        """Handle scan errors."""
        self.log_text.append(f"[ERROR] {error}")
        QMessageBox.critical(self, "Scan Error", f"An error occurred: {error}")
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    
    def _update_statistics(self, results: List):
        """Update statistics tab."""
        total_hosts = len(results)
        alive_hosts = sum(1 for r in results if r.alive)
        total_ports = sum(len(r.open_ports) for r in results)
        
        stats_text = f"""
        ╔═══════════════════════════════════════════════════════════╗
        ║                  SCAN STATISTICS                          ║
        ╠═══════════════════════════════════════════════════════════╣
        ║ Total Hosts Scanned:     {total_hosts:<25} ║
        ║ Alive Hosts:             {alive_hosts:<25} ║
        ║ Dead Hosts:              {total_hosts - alive_hosts:<25} ║
        ║ Total Open Ports Found:  {total_ports:<25} ║
        ║ Average Ports/Host:      {total_ports / max(alive_hosts, 1):<25.2f} ║
        ╚═══════════════════════════════════════════════════════════╝
        """
        
        self.stats_text.setText(stats_text)
    
    def export_results(self):
        """Export scan results to file."""
        if not self.scan_results:
            QMessageBox.warning(self, "No Results", "No scan results to export")
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
                    f"Results exported to {file_path}"
                )
                self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Results exported to {file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to export results")


def main():
    """Main entry point for GUI."""
    app = QApplication(sys.argv)
    window = ShibaCuddlesGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
