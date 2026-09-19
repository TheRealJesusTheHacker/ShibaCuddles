"""
Device discovery module for network scanning.
Implements ICMP and ARP-based host discovery.
"""

import subprocess
import platform
import logging
import socket
import re
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class Device:
    """Represents a discovered device."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    is_alive: bool = True


class DeviceDiscovery:
    """
    Device discovery using ICMP ping and optional ARP scanning.
    
    Features:
    - ICMP-based ping sweep
    - ARP scanning (optional)
    - Hostname resolution
    - MAC address resolution
    """
    
    def __init__(self, timeout: float = 5.0, logger: logging.Logger = None):
        """
        Initialize device discovery.
        
        Args:
            timeout: Ping timeout in seconds
            logger: Logger instance
        """
        self.timeout = max(1, int(timeout))
        self.logger = logger or logging.getLogger(__name__)
        self.system = platform.system().lower()
    
    def is_alive(self, ip: str) -> bool:
        """
        Check if host is alive using ICMP ping.
        
        Args:
            ip: Target IP address
        
        Returns:
            True if host responds to ping, False otherwise
        """
        try:
            # Platform-specific ping command
            if self.system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), ip]
            else:  # Linux, macOS, etc.
                cmd = ["ping", "-c", "1", "-W", str(self.timeout), ip]
            
            # Execute ping
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 2
            )
            
            return result.returncode == 0
        
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.debug(f"Ping to {ip} failed: {e}")
            return False
    
    def resolve_hostname(self, ip: str) -> Optional[str]:
        """
        Resolve IP to hostname.
        
        Args:
            ip: Target IP address
        
        Returns:
            Hostname or None if resolution fails
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.error):
            return None
    
    def get_mac_address(self, ip: str) -> Optional[str]:
        """
        Get MAC address for IP address (requires ARP).
        
        Args:
            ip: Target IP address
        
        Returns:
            MAC address or None if not found
        """
        # Matches MACs with ':' or '-' separators on any platform, e.g.
        # Linux:   "192.168.1.1  ether  00:11:22:33:44:55  C  eth0"
        # Windows: "  192.168.1.1           00-11-22-33-44-55     dynamic"
        mac_pattern = r"\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b"

        try:
            # Try ARP lookup
            if self.system == "windows":
                result = subprocess.run(
                    ["arp", "-a", ip],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            else:
                result = subprocess.run(
                    ["arp", "-n", ip],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

            match = re.search(mac_pattern, result.stdout)
            if match:
                # Normalize to colon-separated lowercase
                return match.group(1).replace("-", ":").lower()
        
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"ARP lookup for {ip} failed: {e}")
        
        return None
    
    def discover(self, ips: List[str], resolve_hostname: bool = True, 
                resolve_mac: bool = False) -> List[Device]:
        """
        Discover devices on given IPs.
        
        Args:
            ips: List of IP addresses to check
            resolve_hostname: Whether to resolve hostnames
            resolve_mac: Whether to resolve MAC addresses
        
        Returns:
            List of discovered Device objects
        """
        devices = []
        
        for ip in ips:
            if self.is_alive(ip):
                device = Device(ip=ip)
                
                if resolve_hostname:
                    device.hostname = self.resolve_hostname(ip)
                
                if resolve_mac:
                    device.mac = self.get_mac_address(ip)
                
                devices.append(device)
                self.logger.debug(f"Discovered device: {ip} ({device.hostname})")
        
        return devices
    
    def discover_subnet(self, subnet: str, resolve_hostname: bool = True,
                       resolve_mac: bool = False) -> List[Device]:
        """
        Discover all devices on a subnet.
        
        Args:
            subnet: Network in CIDR notation
            resolve_hostname: Whether to resolve hostnames
            resolve_mac: Whether to resolve MAC addresses
        
        Returns:
            List of discovered Device objects
        """
        import ipaddress
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            return self.discover(ips, resolve_hostname, resolve_mac)
        
        except ValueError as e:
            self.logger.error(f"Invalid subnet: {e}")
            return []


class ARPScanner:
    """
    ARP-based network scanner for faster device discovery.
    """
    
    def __init__(self, logger: logging.Logger = None):
        """
        Initialize ARP scanner.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
    
    def scan_network(self, network: str) -> List[Device]:
        """
        Scan network using ARP.
        
        Args:
            network: Network in CIDR notation
        
        Returns:
            List of discovered Device objects
        """
        try:
            from scapy.all import ARP, Ether, srp
        except ImportError:
            self.logger.warning("Scapy not installed, falling back to ping sweep")
            return []
        
        try:
            devices = []
            
            # Create ARP request
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
            
            # Send requests and get responses
            answered, _ = srp(arp_request, timeout=2, verbose=False)
            
            # Process responses
            for _, response in answered:
                device = Device(
                    ip=response.psrc,
                    mac=response.hwsrc
                )
                devices.append(device)
                self.logger.debug(f"ARP discovered: {device.ip} ({device.mac})")
            
            return devices
        
        except Exception as e:
            self.logger.warning(f"ARP scan failed: {e}")
            return []
