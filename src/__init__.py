"""
ShibaCuddles package initialization.
Exposes main scanner classes and utilities.
"""

from .scanner import NetworkScanner, ScanResult
from .device import DeviceDiscovery, ARPScanner, Device
from .port_scanner import PortScanner, UDPScanner
from .service_detector import ServiceDetector, VulnerabilityScanner
from .results_handler import ResultsHandler
from .utils import (
    setup_logging,
    validate_network,
    parse_port_spec,
    format_elapsed_time,
    print_banner
)

__version__ = "0.3.0"
__author__ = "thedarkonejesus"
__description__ = "ShibaCuddles - Advanced Network Scanner"

__all__ = [
    "NetworkScanner",
    "ScanResult",
    "DeviceDiscovery",
    "ARPScanner",
    "Device",
    "PortScanner",
    "UDPScanner",
    "ServiceDetector",
    "VulnerabilityScanner",
    "ResultsHandler",
    "setup_logging",
    "validate_network",
    "parse_port_spec",
    "format_elapsed_time",
    "print_banner",
]
