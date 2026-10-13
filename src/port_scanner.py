"""
High-performance port scanner module.
Implements TCP connection scanning with threading and optimization.
"""

import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from .utils import clamp_threads, create_socket, parse_port_spec

# Maximum number of probe futures in flight at once. Submitting an
# entire port spec up front (65,535 futures for a full-range scan) held
# ~116 MB of futures + as_completed waiters in memory before the first
# result arrived; a bounded window keeps results identical with a flat
# memory profile. Matches the chunk size NetworkScanner discovery uses.
_SUBMIT_WINDOW = 1024


class PortScanner:
    """
    High-performance TCP port scanner with multi-threading support.

    Features:
    - Multi-threaded scanning for speed
    - Connection pooling
    - Timeout handling
    - Rate limiting
    - Service banner grabbing
    """

    def __init__(
        self,
        threads: int = 10,
        timeout: float = 5.0,
        rate_limit: float = 0.0,
        logger: logging.Logger = None,
        stop_event: Optional[threading.Event] = None,
    ):
        """
        Initialize port scanner.

        Args:
            threads: Number of worker threads
            timeout: Socket timeout in seconds
            rate_limit: Delay between scans in seconds
            logger: Logger instance
            stop_event: Optional threading.Event; when set, an in-progress
                scan aborts cooperatively at the next checkpoint
        """
        self.threads = clamp_threads(threads, 100)
        self.timeout = max(0.1, timeout)
        self.rate_limit = max(0.0, rate_limit)
        self.logger = logger or logging.getLogger(__name__)
        self.stop_event = stop_event or threading.Event()

    def _should_stop(self) -> bool:
        """Check whether a stop was requested via the stop event."""
        return self.stop_event.is_set()

    def scan(self, host: str, port_spec: str) -> List[int]:
        """
        Scan ports on target host.

        Args:
            host: Target IP address
            port_spec: Port specification (e.g., "1-1024" or "22,80,443")

        Returns:
            List of open ports
        """
        try:
            ports = parse_port_spec(port_spec)
        except ValueError as e:
            self.logger.error(f"Invalid port specification: {e}")
            return []

        open_ports = []
        futures = {}

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            try:
                # Submit in bounded windows (see _SUBMIT_WINDOW) rather
                # than queueing the whole spec up front.
                for chunk_start in range(0, len(ports), _SUBMIT_WINDOW):
                    if self._should_stop():
                        break
                    chunk = ports[chunk_start : chunk_start + _SUBMIT_WINDOW]
                    futures = {
                        executor.submit(self._check_port, host, port): port
                        for port in chunk
                    }

                    for future in as_completed(futures):
                        if self._should_stop():
                            for f in futures:
                                f.cancel()
                            break
                        port = futures[future]
                        try:
                            if future.result():
                                open_ports.append(port)
                                self.logger.debug(f"{host}:{port} is OPEN")
                        except Exception as e:
                            self.logger.debug(f"Error scanning {host}:{port}: {e}")
            except KeyboardInterrupt:
                # Abort promptly: drop everything still queued so the pool
                # teardown doesn't first run thousands of pending probes.
                # Running probes finish on their own (socket timeout bounds
                # them); every socket is still closed in _check_port.
                for f in futures:
                    f.cancel()
                raise

        return sorted(open_ports)

    def _check_port(self, host: str, port: int) -> bool:
        """
        Check if a single port is open.

        Args:
            host: Target IP address
            port: Port number

        Returns:
            True if port is open, False otherwise
        """
        sock = None
        try:
            # Rate limiting
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)

            # Create socket with timeout
            sock = create_socket(host, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Attempt connection
            result = sock.connect_ex((host, port))

            return result == 0

        except (socket.timeout, socket.error):
            return False
        except Exception as e:
            self.logger.debug(f"Unexpected error scanning {host}:{port}: {e}")
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def grab_banner(self, host: str, port: int) -> str:
        """
        Attempt to grab service banner from open port.

        Args:
            host: Target IP address
            port: Port number

        Returns:
            Banner string or empty string if failed
        """
        sock = None
        try:
            sock = create_socket(host, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            # Receive banner (max 1024 bytes)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()

            return banner

        except (socket.timeout, socket.error, Exception):
            return ""
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


class UDPScanner:
    """
    UDP port scanner for service discovery.
    """

    def __init__(
        self,
        timeout: float = 3.0,
        threads: int = 20,
        logger: logging.Logger = None,
        stop_event: Optional[threading.Event] = None,
    ):
        """
        Initialize UDP scanner.

        Args:
            timeout: Socket timeout in seconds
            threads: Number of worker threads
            logger: Logger instance
            stop_event: Optional threading.Event for cooperative stop
        """
        self.timeout = max(0.1, timeout)
        self.threads = clamp_threads(threads, 100)
        self.logger = logger or logging.getLogger(__name__)
        self.stop_event = stop_event or threading.Event()

    def _check_udp_port(self, host: str, port: int) -> bool:
        """
        Probe a single UDP port.

        Args:
            host: Target IP address
            port: Port number

        Returns:
            True if a response was received, False otherwise
        """
        sock = None
        try:
            sock = create_socket(host, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Send empty UDP packet
            sock.sendto(b"", (host, port))

            # Try to receive response
            try:
                sock.recvfrom(1024)
                return True
            except socket.timeout:
                # No response could mean open or filtered
                return False

        except (socket.error, Exception) as e:
            self.logger.debug(f"UDP scan error on {host}:{port}: {e}")
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def scan(self, host: str, ports: List[int]) -> List[int]:
        """
        Scan UDP ports (ICMP-based detection), in parallel.

        Args:
            host: Target IP address
            ports: List of port numbers to scan

        Returns:
            List of ports with responses
        """
        open_ports = []
        futures = {}

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            try:
                # Bounded submission windows, same as the TCP scan above.
                for chunk_start in range(0, len(ports), _SUBMIT_WINDOW):
                    if self.stop_event.is_set():
                        break
                    chunk = ports[chunk_start : chunk_start + _SUBMIT_WINDOW]
                    futures = {
                        executor.submit(self._check_udp_port, host, port): port
                        for port in chunk
                    }

                    for future in as_completed(futures):
                        if self.stop_event.is_set():
                            for f in futures:
                                f.cancel()
                            break
                        port = futures[future]
                        try:
                            if future.result():
                                open_ports.append(port)
                        except Exception as e:
                            self.logger.debug(f"UDP scan error on {host}:{port}: {e}")
            except KeyboardInterrupt:
                # Same as TCP scan above: drop the queued probes so abort
                # is prompt; running probes are timeout-bounded and close
                # their sockets in _check_udp_port's finally block.
                for f in futures:
                    f.cancel()
                raise

        return sorted(open_ports)
