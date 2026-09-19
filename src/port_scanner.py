"""
High-performance port scanner module.
Implements TCP connection scanning with threading and optimization.
"""

import socket
import threading
import logging
import time
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue


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
        logger: logging.Logger = None
    ):
        """
        Initialize port scanner.
        
        Args:
            threads: Number of worker threads
            timeout: Socket timeout in seconds
            rate_limit: Delay between scans in seconds
            logger: Logger instance
        """
        self.threads = max(1, min(threads, 100))
        self.timeout = max(0.1, timeout)
        self.rate_limit = max(0.0, rate_limit)
        self.logger = logger or logging.getLogger(__name__)
        self.lock = threading.Lock()
    
    def scan(self, host: str, port_spec: str) -> List[int]:
        """
        Scan ports on target host.
        
        Args:
            host: Target IP address
            port_spec: Port specification (e.g., "1-1024" or "22,80,443")
        
        Returns:
            List of open ports
        """
        from .utils import parse_port_spec
        
        try:
            ports = parse_port_spec(port_spec)
        except ValueError as e:
            self.logger.error(f"Invalid port specification: {e}")
            return []
        
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_port, host, port): port
                for port in ports
            }
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        self.logger.debug(f"{host}:{port} is OPEN")
                except Exception as e:
                    self.logger.debug(f"Error scanning {host}:{port}: {e}")
        
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    
    def scan_batch(self, hosts: List[str], port_spec: str) -> Dict[str, List[int]]:
        """
        Scan multiple hosts in parallel.
        
        Args:
            hosts: List of target IP addresses
            port_spec: Port specification
        
        Returns:
            Dictionary mapping host to list of open ports
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.scan, host, port_spec): host
                for host in hosts
            }
            
            for future in as_completed(futures):
                host = futures[future]
                try:
                    results[host] = future.result()
                except Exception as e:
                    self.logger.error(f"Error scanning {host}: {e}")
                    results[host] = []
        
        return results
    
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    
    def __init__(self, timeout: float = 3.0, logger: logging.Logger = None):
        """
        Initialize UDP scanner.
        
        Args:
            timeout: Socket timeout in seconds
            logger: Logger instance
        """
        self.timeout = max(0.1, timeout)
        self.logger = logger or logging.getLogger(__name__)
    
    def scan(self, host: str, ports: List[int]) -> List[int]:
        """
        Scan UDP ports (ICMP-based detection).
        
        Args:
            host: Target IP address
            ports: List of port numbers to scan
        
        Returns:
            List of ports with responses
        """
        open_ports = []
        
        for port in ports:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)

                # Send empty UDP packet
                sock.sendto(b"", (host, port))

                # Try to receive response
                try:
                    sock.recvfrom(1024)
                    open_ports.append(port)
                except socket.timeout:
                    # No response could mean open or filtered
                    pass

            except (socket.error, Exception) as e:
                self.logger.debug(f"UDP scan error on {host}:{port}: {e}")
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass

        return sorted(open_ports)
