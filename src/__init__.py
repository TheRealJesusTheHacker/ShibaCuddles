"""
ShibaCuddles package initialization.
Exposes main scanner classes and utilities.
"""

from .device import ARPScanner, Device, DeviceDiscovery
from .port_scanner import PortScanner, UDPScanner
from .results_handler import ResultsHandler
from .scanner import NetworkScanner, ScanResult
from .service_detector import ServiceDetector, VulnerabilityScanner
from .utils import (
    format_elapsed_time,
    parse_port_spec,
    print_banner,
    setup_logging,
    validate_network,
)

__version__ = "0.3.7"
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
