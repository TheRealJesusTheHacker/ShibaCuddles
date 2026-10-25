"""
ShibaCuddles Scanner Core Module
Orchestrates network scanning operations with optimization and performance tuning.
"""

import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .device import DeviceDiscovery
from .port_scanner import PortScanner, UDPScanner
from .results_handler import ResultsHandler
from .service_detector import ServiceDetector, VulnerabilityScanner
from .utils import clamp_threads, format_elapsed_time, parse_port_spec


def _ip_sort_key(ip: str):
    """Numeric sort key for an IP string: (address version, integer value).

    Version-first ordering keeps IPv4 and IPv6 blocks separate without
    raising on mixed input. Parses the address once -- the previous
    inline key parsed it twice per host, which cost seconds on
    /16-scale discovery result sets.
    """
    addr = ipaddress.ip_address(ip)
    return (addr.version, int(addr))


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
    udp_open_ports: List[int] = None
    vulnerabilities: Dict = None

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
        if self.udp_open_ports is None:
            self.udp_open_ports = []
        if self.vulnerabilities is None:
            self.vulnerabilities = {}


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
        stop_event: Optional[threading.Event] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
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
        # Floor of 1 as well as the cap: ThreadPoolExecutor raises
        # ValueError for max_workers < 1, so an unclamped threads=0
        # (e.g. CLI --threads 0) crashed scan() instead of scanning.
        # The clamp logic is shared (utils.clamp_threads); the cap of
        # 64 here vs 100 in PortScanner/UDPScanner is per-class.
        self.threads = clamp_threads(threads, 64)
        self.timeout = max(0.2, timeout)  # Minimum 0.2 seconds (sub-second allowed)
        self.rate_limit = max(0.0, rate_limit)
        self.batch_size = max(10, batch_size)
        self.skip_broadcast = skip_broadcast
        self.logger = logger or logging.getLogger(__name__)
        self.stop_event = stop_event or threading.Event()
        self.progress_callback = progress_callback

        # Feature flags
        self.ping_sweep = True
        self.enable_service_detection = False
        self.enable_os_detection = False
        self.enable_udp_scan = False
        self.enable_vuln_scan = False

        # Initialize components with the CLAMPED values, so the minimums
        # enforced above actually apply to the components doing the work.
        self.device_discovery = DeviceDiscovery(
            timeout=self.timeout, logger=self.logger
        )
        self.port_scanner = PortScanner(
            threads=self.threads,
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            logger=self.logger,
            stop_event=self.stop_event,
        )
        self.service_detector = ServiceDetector(
            timeout=self.timeout, logger=self.logger
        )
        self.udp_scanner = UDPScanner(
            timeout=self.timeout,
            threads=self.threads,
            logger=self.logger,
            stop_event=self.stop_event,
        )
        self.vulnerability_scanner = VulnerabilityScanner(logger=self.logger)
        self.results_handler = ResultsHandler(logger=self.logger)

        # Statistics
        self.stats = {
            "total_hosts": 0,
            "alive_hosts": 0,
            "dead_hosts": 0,
            "open_ports_found": 0,
            "udp_open_ports_found": 0,
            "vulnerabilities_found": 0,
            "scan_duration": 0.0,
            "hosts_per_second": 0.0,
        }

    def _should_stop(self) -> bool:
        """Check whether a stop was requested via the stop event."""
        return self.stop_event.is_set()

    def _report_progress(self, done: int, total: int) -> None:
        """Invoke the progress callback, never letting it break the scan."""
        cb = self.progress_callback
        if cb is None:
            return
        try:
            cb(done, total)
        except Exception:
            self.logger.debug("progress callback raised", exc_info=True)

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

        # Reset per-run statistics so repeated scan() calls on one instance
        # don't accumulate hosts/ports from earlier runs.
        self.stats = {
            "total_hosts": 0,
            "alive_hosts": 0,
            "dead_hosts": 0,
            "open_ports_found": 0,
            "udp_open_ports_found": 0,
            "vulnerabilities_found": 0,
            "scan_duration": 0.0,
            "hosts_per_second": 0.0,
        }

        try:
            # Step 1: Parse network and get target IPs
            self.logger.info(f"Parsing network: {self.network}")
            target_ips = self._get_target_hosts()
            self.stats["total_hosts"] = len(target_ips)
            self.logger.info(f"Target hosts: {len(target_ips)}")

            # Step 2: Device discovery (optional but recommended)
            if self.ping_sweep:
                self.logger.info("Starting device discovery phase...")
                alive_ips = self._discover_devices(target_ips)
                self.stats["alive_hosts"] = len(alive_ips)
                self.stats["dead_hosts"] = len(target_ips) - len(alive_ips)
                self.logger.info(f"Discovered {len(alive_ips)} alive hosts")
            else:
                alive_ips = target_ips
                # No discovery ran, so every target is treated as alive
                # for scanning; the statistics must say so. Leaving the
                # counters at 0 reported "Alive: 0 | Dead: 0" for a
                # --no-ping scan that found alive hosts, and broke the
                # total = alive + dead invariant the ping path keeps.
                self.stats["alive_hosts"] = len(alive_ips)
                self.stats["dead_hosts"] = 0
                self.logger.info("Skipping device discovery, scanning all hosts")

            # Step 3: Port scanning
            if alive_ips and not self._should_stop():
                self.logger.info("Starting port scanning phase...")
                results = self._scan_ports(alive_ips, port_range)

                # Count open ports
                for result in results:
                    self.stats["open_ports_found"] += len(result.open_ports)

                self.logger.info(
                    f"Port scan complete. "
                    f"Found {self.stats['open_ports_found']} open ports"
                )

            # Step 3b: UDP port scanning (optional, --udp)
            if self.enable_udp_scan and results and not self._should_stop():
                self.logger.info("Starting UDP port scanning phase...")
                results = self._scan_udp_ports(results, port_range)
                for result in results:
                    self.stats["udp_open_ports_found"] += len(result.udp_open_ports)
                self.logger.info(
                    f"UDP scan complete. "
                    f"Found {self.stats['udp_open_ports_found']} open UDP ports"
                )

            # Step 4: Service detection (optional). Vulnerability
            # scanning matches against detected services, so enabling
            # it implies this phase runs even when service detection
            # itself was not requested.
            if (
                (self.enable_service_detection or self.enable_vuln_scan)
                and results
                and not self._should_stop()
            ):
                self.logger.info("Starting service detection phase...")
                results = self._detect_services(results)

            # Step 5: OS detection (optional)
            if self.enable_os_detection and results and not self._should_stop():
                self.logger.info("Starting OS fingerprinting phase...")
                results = self._detect_os(results)

            # Step 6: Vulnerability scan (optional, --vuln-scan). Matches
            # the services detected above against VulnerabilityScanner's
            # bundled table — DEMO DATA (four sample entries, not a
            # vulnerability feed); see that class's docstring.
            if self.enable_vuln_scan and results and not self._should_stop():
                self.logger.info("Starting vulnerability scan phase...")
                results = self._detect_vulnerabilities(results)
                for result in results:
                    self.stats["vulnerabilities_found"] += len(result.vulnerabilities)

        finally:
            # Calculate statistics
            self.stats["scan_duration"] = time.time() - start_time
            if self.stats["scan_duration"] > 0:
                self.stats["hosts_per_second"] = (
                    self.stats["total_hosts"] / self.stats["scan_duration"]
                )
            self.logger.info(self._format_statistics())

        return results

    def _get_target_hosts(self) -> List[str]:
        """Parse network and return list of target IPs."""
        try:
            network = ipaddress.ip_network(self.network, strict=False)
            if network.num_addresses > 65536:
                raise ValueError(
                    f"Target {self.network} contains "
                    f"{network.num_addresses:,} addresses, "
                    "exceeding the 65,536-address limit. Narrow the target range."
                )
            hosts = list(network.hosts())

            # Broadcast is an IPv4 concept and only exists as a distinct
            # address on networks with 2+ addresses. Applying the filter
            # unconditionally silently erased legitimate targets: a /32
            # single-host scan returned ZERO hosts (its only address IS
            # the "broadcast" address), and an IPv6 range lost its final
            # host (IPv6 has no broadcast at all).
            if (
                self.skip_broadcast
                and network.version == 4
                and network.num_addresses > 1
            ):
                # Remove broadcast and network addresses
                hosts = [
                    str(ip) for ip in hosts if str(ip) != str(network.broadcast_address)
                ]
            else:
                hosts = [str(ip) for ip in hosts]

            return hosts
        except ValueError as e:
            self.logger.error(f"Invalid network format: {e}")
            raise

    def _discover_devices(self, target_ips: List[str]) -> List[str]:
        """Discover alive devices using ICMP and ARP."""
        alive_ips = []
        total = len(target_ips)
        completed = 0

        # Submit in chunks so a /16 doesn't queue 65k futures (and ping
        # subprocesses) up front.
        chunk_size = 1024
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for chunk_start in range(0, len(target_ips), chunk_size):
                if self._should_stop():
                    # A stop inside the inner future loop only breaks out of
                    # that loop; without this check the outer loop would keep
                    # submitting every remaining chunk. Abort them all.
                    break
                chunk = target_ips[chunk_start : chunk_start + chunk_size]
                futures = {
                    executor.submit(self.device_discovery.is_alive, ip): ip
                    for ip in chunk
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
                    completed += 1
                    self._report_progress(completed, total)

        # Numeric sort (not lexicographic): without this, "192.168.1.10"
        # sorts before "192.168.1.2".
        return sorted(alive_ips, key=_ip_sort_key)

    def _scan_ports(self, hosts: List[str], port_range: str) -> List[ScanResult]:
        """Scan ports on each alive host and build ScanResults.

        Hosts are scanned one at a time; PortScanner parallelizes the ports
        within each host. (A host-level pool nested inside the port-level
        pool would multiply thread counts: threads^2.) Progress is reported
        per completed host via the progress callback.
        """
        try:
            ports = parse_port_spec(port_range)
        except ValueError as e:
            self.logger.error(f"Invalid port specification: {e}")
            return []
        if not ports:
            return []

        total = len(hosts)
        results: List[ScanResult] = []
        for idx, host in enumerate(hosts, 1):
            if self._should_stop():
                self.logger.info("Port scan aborted by stop request")
                break
            t0 = time.time()
            try:
                open_ports = self.port_scanner.scan(host, port_range)
            except Exception as e:
                self.logger.debug(f"Port scan failed for {host}: {e}")
                open_ports = []
            results.append(
                ScanResult(
                    ip=host,
                    alive=True,
                    open_ports=open_ports,
                    scan_time=time.time() - t0,
                )
            )
            self._report_progress(idx, total)
        return results

    def _scan_udp_ports(
        self, results: List[ScanResult], port_range: str
    ) -> List[ScanResult]:
        """Probe UDP ports on each scanned host (serial across hosts).

        UDPScanner parallelizes the ports within a host, mirroring how
        _scan_ports uses PortScanner; nesting a host pool around it
        would multiply thread counts the same way.
        """
        try:
            ports = parse_port_spec(port_range)
        except ValueError as e:
            self.logger.error(f"Invalid port specification: {e}")
            return results
        if not ports:
            return results

        for result in results:
            if self._should_stop():
                self.logger.info("UDP scan aborted by stop request")
                break
            try:
                result.udp_open_ports = self.udp_scanner.scan(result.ip, ports)
            except Exception as e:
                self.logger.debug(f"UDP scan failed for {result.ip}: {e}")
                result.udp_open_ports = []
        return results

    def _detect_vulnerabilities(self, results: List[ScanResult]) -> List[ScanResult]:
        """Match each host's detected services against the vuln table.

        Hosts are handled serially: VulnerabilityScanner.scan is a
        pure table lookup (no I/O), so a thread pool would add
        overhead without shortening anything.
        """
        for result in results:
            if self._should_stop():
                break
            if result.services:
                try:
                    result.vulnerabilities = self.vulnerability_scanner.scan(
                        result.services
                    )
                except Exception as e:
                    self.logger.debug(f"Vulnerability scan failed on {result.ip}: {e}")
                    result.vulnerabilities = {}
            else:
                result.vulnerabilities = {}
        return results

    def _map_parallel(self, func, results: List[ScanResult]) -> List[ScanResult]:
        """Apply func to each result in a thread pool, preserving order."""
        ordered: List[Optional[ScanResult]] = [None] * len(results)
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(func, result): idx for idx, result in enumerate(results)
            }
            for future in as_completed(futures):
                if self._should_stop():
                    for f in futures:
                        f.cancel()
                    break
                idx = futures[future]
                try:
                    ordered[idx] = future.result()
                except Exception as e:
                    self.logger.debug(f"Parallel task failed: {e}")
                    ordered[idx] = results[idx]
        for idx, res in enumerate(ordered):
            if res is None:
                ordered[idx] = results[idx]
        return ordered

    def _detect_services(self, results: List[ScanResult]) -> List[ScanResult]:
        """Detect services running on open ports (parallel across hosts).

        Ports within a host are probed serially on purpose: this runs
        inside the per-host thread pool above, so calling
        ServiceDetector.detect() here would nest its per-port pool inside
        it and multiply thread counts (threads^2). detect_service is
        thread-safe, so per-host serial probing is safe.
        """

        def _detect_one(result: ScanResult) -> ScanResult:
            if result.open_ports:
                self.logger.debug(f"Detecting services on {result.ip}")
                services = {}
                for port in result.open_ports:
                    try:
                        info = self.service_detector.detect_service(result.ip, port)
                    except Exception as e:
                        self.logger.debug(
                            f"Service detection failed on " f"{result.ip}:{port}: {e}"
                        )
                        continue
                    if info:
                        services[port] = info
                result.services = services
            return result

        return self._map_parallel(_detect_one, results)

    def _detect_os(self, results: List[ScanResult]) -> List[ScanResult]:
        """Perform OS fingerprinting (parallel across hosts)."""

        def _fingerprint_one(result: ScanResult) -> ScanResult:
            self.logger.debug(f"Fingerprinting OS on {result.ip}")
            result.os_info = self.service_detector.detect_os(result.ip)
            return result

        return self._map_parallel(_fingerprint_one, results)

    def print_results(self, results: List[ScanResult]) -> None:
        """Display results in human-readable format."""
        if not results:
            print("No results to display")
            return

        print("\n" + "=" * 80)
        print("SCAN RESULTS - ShibaCuddles Network Scanner")
        print("=" * 80 + "\n")

        for result in results:
            print(f"Host: {result.ip}")
            print(f"  Status: {'ALIVE' if result.alive else 'DEAD'}")

            if result.open_ports:
                print(f"  Open Ports: {', '.join(map(str, result.open_ports))}")

                if result.services:
                    print("  Services:")
                    for port, service_info in result.services.items():
                        service_name = service_info.get("name", "Unknown")
                        version = service_info.get("version", "")
                        print(f"    {port}: {service_name} {version}".rstrip())
            else:
                print("  Open Ports: None found")

            if result.udp_open_ports:
                print(
                    "  UDP Open Ports: " f"{', '.join(map(str, result.udp_open_ports))}"
                )

            if result.vulnerabilities:
                print(
                    "  Vulnerabilities (bundled demo table — sample data "
                    "only, not a vulnerability feed):"
                )
                for key, vuln in result.vulnerabilities.items():
                    print(f"    {key}: {vuln}")

            if result.os_info:
                os_name = result.os_info.get("name", "Unknown")
                confidence = result.os_info.get("confidence", 0)
                print(f"  OS: {os_name} (Confidence: {confidence}%)")

            print(f"  Scan Time: {result.scan_time:.2f}s\n")

        print("=" * 80)
        print(f"Statistics: {self._format_statistics()}")
        print("=" * 80 + "\n")

    def save_results(
        self,
        results: List[ScanResult],
        filepath: str,
        format: str = "json",
        force: bool = False,
    ) -> bool:
        """Save results to file. Returns True if the file was written."""
        return self.results_handler.save(results, filepath, format, force)

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
