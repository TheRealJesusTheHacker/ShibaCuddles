"""
ShibaCuddles Scanner Core Module
Orchestrates network scanning operations with optimization and performance tuning.
"""

import logging
import threading
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import time
import ipaddress
from collections import defaultdict

from .device import DeviceDiscovery
from .port_scanner import PortScanner
from .service_detector import ServiceDetector
from .results_handler import ResultsHandler
from .utils import format_elapsed_time


@dataclass
class ScanResult:
    """Data class for scan results."""
    ip: str
    alive: bool
    open_ports: List[int] = None
    closed_ports: List[int] = None
    filtered_ports: List[int] = None
    services: Dict[int, Dict] = None
    os_info: Dict = None
    scan_time: float = 0.0
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.closed_ports is None:
            self.closed_ports = []
        if self.filtered_ports is None:
            self.filtered_ports = []
        if self.services is None:
            self.services = {}
        if self.os_info is None:
            self.os_info = {}


class NetworkScanner:
    """
    High-performance network scanner with multi-threading and advanced features.
    
    Features:
    - Device discovery via ICMP and ARP
    - High-performance port scanning
    - Service version detection
    - OS fingerprinting
    - Parallel processing with thread pooling
    - Configurable timeouts and rate limiting
    - Multiple output formats
    """
    
    def __init__(
        self,
        network: str,
        threads: int = 10,
        timeout: float = 5.0,
        rate_limit: float = 0.0,
        batch_size: int = 50,
        skip_broadcast: bool = False,
        logger: Optional[logging.Logger] = None,
        stop_event: Optional[threading.Event] = None
    ):
        """
        Initialize the network scanner.

        Args:
            network: Target network in CIDR notation
            threads: Number of worker threads
            timeout: Connection timeout in seconds
            rate_limit: Delay between requests in seconds
            batch_size: Size of result batches for processing
            skip_broadcast: Skip broadcast/network addresses
            logger: Logger instance
            stop_event: Optional threading.Event; when set, the scan aborts
                cooperatively at the next checkpoint and returns partial results
        """
        self.network = network
        self.threads = min(threads, 64)  # Cap at 64 threads
        self.timeout = max(1.0, timeout)  # Minimum 1 second
        self.rate_limit = max(0.0, rate_limit)
        self.batch_size = max(10, batch_size)
        self.skip_broadcast = skip_broadcast
        self.logger = logger or logging.getLogger(__name__)
        self.stop_event = stop_event or threading.Event()

        # Feature flags
        self.ping_sweep = True
        self.enable_service_detection = False
        self.enable_os_detection = False

        # Initialize components with the CLAMPED values, so the minimums
        # enforced above actually apply to the components doing the work.
        self.device_discovery = DeviceDiscovery(timeout=self.timeout, logger=self.logger)
        self.port_scanner = PortScanner(
            threads=self.threads,
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            logger=self.logger
        )
        self.service_detector = ServiceDetector(timeout=self.timeout, logger=self.logger)
        self.results_handler = ResultsHandler(logger=self.logger)
        
        # Statistics
        self.stats = {
            'total_hosts': 0,
            'alive_hosts': 0,
            'dead_hosts': 0,
            'open_ports_found': 0,
            'scan_duration': 0.0,
            'hosts_per_second': 0.0
        }
    
    def _should_stop(self) -> bool:
        """Check whether a stop was requested via the stop event."""
        return self.stop_event.is_set()

    def scan(self, port_range: str) -> List[ScanResult]:
        """
        Execute comprehensive network scan.
        
        Args:
            port_range: Port specification (e.g., "1-1024" or "22,80,443")
        
        Returns:
            List of ScanResult objects with findings
        """
        start_time = time.time()
        results = []
        
        try:
            # Step 1: Parse network and get target IPs
            self.logger.info(f"Parsing network: {self.network}")
            target_ips = self._get_target_hosts()
            self.stats['total_hosts'] = len(target_ips)
            self.logger.info(f"Target hosts: {len(target_ips)}")
            
            # Step 2: Device discovery (optional but recommended)
            if self.ping_sweep:
                self.logger.info("Starting device discovery phase...")
                alive_ips = self._discover_devices(target_ips)
                self.stats['alive_hosts'] = len(alive_ips)
                self.stats['dead_hosts'] = len(target_ips) - len(alive_ips)
                self.logger.info(f"Discovered {len(alive_ips)} alive hosts")
            else:
                alive_ips = target_ips
                self.logger.info("Skipping device discovery, scanning all hosts")
            
            # Step 3: Port scanning
            if alive_ips and not self._should_stop():
                self.logger.info("Starting port scanning phase...")
                results = self._scan_ports(alive_ips, port_range)

                # Count open ports
                for result in results:
                    self.stats['open_ports_found'] += len(result.open_ports)

                self.logger.info(
                    f"Port scan complete. Found {self.stats['open_ports_found']} open ports"
                )

            # Step 4: Service detection (optional)
            if self.enable_service_detection and results and not self._should_stop():
                self.logger.info("Starting service detection phase...")
                results = self._detect_services(results)

            # Step 5: OS detection (optional)
            if self.enable_os_detection and results and not self._should_stop():
                self.logger.info("Starting OS fingerprinting phase...")
                results = self._detect_os(results)

        finally:
            # Calculate statistics
            self.stats['scan_duration'] = time.time() - start_time
            if self.stats['scan_duration'] > 0:
                self.stats['hosts_per_second'] = (
                    self.stats['total_hosts'] / self.stats['scan_duration']
                )
            self.logger.info(self._format_statistics())
        
        return results
    
    def _get_target_hosts(self) -> List[str]:
        """Parse network and return list of target IPs."""
        try:
            network = ipaddress.ip_network(self.network, strict=False)
            hosts = list(network.hosts())
            
            if self.skip_broadcast:
                # Remove broadcast and network addresses
                hosts = [str(ip) for ip in hosts if str(ip) != str(network.broadcast_address)]
            else:
                hosts = [str(ip) for ip in hosts]
            
            return hosts
        except ValueError as e:
            self.logger.error(f"Invalid network format: {e}")
            raise
    
    def _discover_devices(self, target_ips: List[str]) -> List[str]:
        """Discover alive devices using ICMP and ARP."""
        alive_ips = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.device_discovery.is_alive, ip): ip
                for ip in target_ips
            }
            
            for future in as_completed(futures):
                if self._should_stop():
                    # Cancel anything not yet running; already-running
                    # pings finish on their own (short timeouts).
                    for f in futures:
                        f.cancel()
                    break
                ip = futures[future]
                try:
                    if future.result():
                        alive_ips.append(ip)
                except Exception as e:
                    self.logger.debug(f"Error checking {ip}: {e}")
        
        return sorted(alive_ips)
    
    def _scan_ports(self, alive_ips: List[str], port_range: str) -> List[ScanResult]:
        """Scan ports on alive hosts."""
        results = []
        
        for ip in alive_ips:
            if self._should_stop():
                self.logger.info("Scan stop requested, aborting port scan")
                break
            start_time = time.time()
            open_ports = self.port_scanner.scan(ip, port_range)
            scan_time = time.time() - start_time
            
            result = ScanResult(
                ip=ip,
                alive=True,
                open_ports=sorted(open_ports),
                scan_time=scan_time
            )
            results.append(result)
            
            if open_ports:
                self.logger.debug(f"{ip}: Found {len(open_ports)} open ports")
        
        return results
    
    def _detect_services(self, results: List[ScanResult]) -> List[ScanResult]:
        """Detect services running on open ports."""
        for result in results:
            if self._should_stop():
                break
            if result.open_ports:
                self.logger.debug(f"Detecting services on {result.ip}")
                result.services = self.service_detector.detect(
                    result.ip,
                    result.open_ports
                )
        
        return results
    
    def _detect_os(self, results: List[ScanResult]) -> List[ScanResult]:
        """Perform OS fingerprinting."""
        for result in results:
            if self._should_stop():
                break
            self.logger.debug(f"Fingerprinting OS on {result.ip}")
            result.os_info = self.service_detector.detect_os(result.ip)
        
        return results
    
    def print_results(self, results: List[ScanResult]) -> None:
        """Display results in human-readable format."""
        if not results:
            print("No results to display")
            return
        
        print("\n" + "="*80)
        print("SCAN RESULTS - ShibaCuddles Network Scanner")
        print("="*80 + "\n")
        
        for result in results:
            print(f"Host: {result.ip}")
            print(f"  Status: {'ALIVE' if result.alive else 'DEAD'}")
            
            if result.open_ports:
                print(f"  Open Ports: {', '.join(map(str, result.open_ports))}")
                
                if result.services:
                    print("  Services:")
                    for port, service_info in result.services.items():
                        service_name = service_info.get('name', 'Unknown')
                        version = service_info.get('version', '')
                        print(f"    {port}: {service_name} {version}".strip())
            else:
                print("  Open Ports: None found")
            
            if result.os_info:
                os_name = result.os_info.get('name', 'Unknown')
                confidence = result.os_info.get('confidence', 0)
                print(f"  OS: {os_name} (Confidence: {confidence}%)")
            
            print(f"  Scan Time: {result.scan_time:.2f}s\n")
        
        print("="*80)
        print(f"Statistics: {self._format_statistics()}")
        print("="*80 + "\n")
    
    def save_results(self, results: List[ScanResult], filepath: str, format: str = "json") -> None:
        """Save results to file."""
        self.results_handler.save(results, filepath, format)
    
    def _format_statistics(self) -> str:
        """Format scan statistics."""
        return (
            f"Total: {self.stats['total_hosts']} | "
            f"Alive: {self.stats['alive_hosts']} | "
            f"Dead: {self.stats['dead_hosts']} | "
            f"Open Ports: {self.stats['open_ports_found']} | "
            f"Duration: {format_elapsed_time(self.stats['scan_duration'])} | "
            f"Rate: {self.stats['hosts_per_second']:.2f} hosts/sec"
        )
