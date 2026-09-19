"""
Service detection and OS fingerprinting module.
Identifies services and their versions on discovered hosts.
"""

import logging
import socket
import re
from typing import Dict, Optional, List


class ServiceDetector:
    """
    Detects services and their versions on open ports.
    """
    
    # Common service signatures
    SERVICE_SIGNATURES = {
        22: {"name": "SSH", "protocol": "tcp"},
        23: {"name": "Telnet", "protocol": "tcp"},
        25: {"name": "SMTP", "protocol": "tcp"},
        53: {"name": "DNS", "protocol": "udp"},
        80: {"name": "HTTP", "protocol": "tcp"},
        110: {"name": "POP3", "protocol": "tcp"},
        143: {"name": "IMAP", "protocol": "tcp"},
        389: {"name": "LDAP", "protocol": "tcp"},
        443: {"name": "HTTPS", "protocol": "tcp"},
        445: {"name": "SMB", "protocol": "tcp"},
        3306: {"name": "MySQL", "protocol": "tcp"},
        3389: {"name": "RDP", "protocol": "tcp"},
        5432: {"name": "PostgreSQL", "protocol": "tcp"},
        5900: {"name": "VNC", "protocol": "tcp"},
        6379: {"name": "Redis", "protocol": "tcp"},
        8080: {"name": "HTTP-Alt", "protocol": "tcp"},
        8443: {"name": "HTTPS-Alt", "protocol": "tcp"},
        27017: {"name": "MongoDB", "protocol": "tcp"},
    }
    
    # Version pattern detection
    VERSION_PATTERNS = {
        "SSH": re.compile(r"OpenSSH[_\s]+([0-9.]+)", re.IGNORECASE),
        "HTTP": re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE),
        "Apache": re.compile(r"Apache[/\s]+([0-9.]+)", re.IGNORECASE),
        "Nginx": re.compile(r"nginx[/\s]+([0-9.]+)", re.IGNORECASE),
    }
    
    def __init__(self, timeout: float = 5.0, logger: logging.Logger = None):
        """
        Initialize service detector.
        
        Args:
            timeout: Connection timeout in seconds
            logger: Logger instance
        """
        self.timeout = max(0.5, timeout)
        self.logger = logger or logging.getLogger(__name__)
    
    def detect(self, host: str, ports: List[int]) -> Dict[int, Dict]:
        """
        Detect services on open ports.
        
        Args:
            host: Target IP address
            ports: List of open port numbers
        
        Returns:
            Dictionary mapping port to service information
        """
        services = {}
        
        for port in ports:
            service_info = self.detect_service(host, port)
            if service_info:
                services[port] = service_info
        
        return services
    
    def detect_service(self, host: str, port: int) -> Optional[Dict]:
        """
        Detect service on a single port.
        
        Args:
            host: Target IP address
            port: Port number
        
        Returns:
            Dictionary with service information or None
        """
        try:
            # Try banner grabbing
            banner = self._grab_banner(host, port)
            
            if banner:
                # Parse banner
                service_info = self._parse_banner(banner, port)
                self.logger.debug(f"{host}:{port} -> {service_info.get('name', 'Unknown')}")
                return service_info
            
            # Fallback to port-based detection
            if port in self.SERVICE_SIGNATURES:
                return self.SERVICE_SIGNATURES[port].copy()
            
            return None
        
        except Exception as e:
            self.logger.debug(f"Service detection on {host}:{port} failed: {e}")
            return None
    
    def _grab_banner(self, host: str, port: int, max_len: int = 1024) -> Optional[str]:
        """
        Grab service banner from port.
        
        Args:
            host: Target IP address
            port: Port number
            max_len: Maximum banner length to retrieve
        
        Returns:
            Banner string or None
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            # Some services send banners immediately
            try:
                banner = sock.recv(max_len).decode("utf-8", errors="ignore")
                if banner.strip():
                    return banner.strip()
            except socket.timeout:
                pass

            # For plaintext HTTP ports, send a HEAD request to elicit a banner.
            # Never send plaintext HTTP to TLS ports (443/8443): the server
            # just answers with a TLS alert/reset and no usable banner.
            if port in (80, 8080):
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(max_len).decode("utf-8", errors="ignore")
                if banner.strip():
                    return banner.strip()

            return None

        except Exception as e:
            self.logger.debug(f"Banner grab failed for {host}:{port}: {e}")
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _parse_banner(self, banner: str, port: int) -> Dict:
        """
        Parse banner to extract service information.
        
        Args:
            banner: Service banner string
            port: Port number
        
        Returns:
            Dictionary with parsed service info
        """
        service_info = {"banner": banner[:100]}  # Store first 100 chars
        
        # Get service name from port
        if port in self.SERVICE_SIGNATURES:
            service_info.update(self.SERVICE_SIGNATURES[port])
        else:
            service_info["name"] = "Unknown"
            service_info["protocol"] = "tcp"
        
        # Try to extract version
        for service_name, pattern in self.VERSION_PATTERNS.items():
            match = pattern.search(banner)
            if match:
                service_info["version"] = match.group(1)
                service_info["name"] = service_name
                break
        
        return service_info
    
    def detect_os(self, host: str) -> Dict:
        """
        Perform basic OS fingerprinting.
        
        Args:
            host: Target IP address
        
        Returns:
            Dictionary with OS information
        """
        try:
            # Try to determine OS based on TTL
            ttl = self._get_ttl(host)
            os_info = self._guess_os_from_ttl(ttl)
            return os_info
        
        except Exception as e:
            self.logger.debug(f"OS detection failed for {host}: {e}")
            return {
                "name": "Unknown",
                "confidence": 0,
                "method": "failed"
            }
    
    def _get_ttl(self, host: str) -> Optional[int]:
        """
        Get TTL value from ICMP echo reply.
        
        Args:
            host: Target IP address
        
        Returns:
            TTL value or None
        """
        try:
            from scapy.all import IP, ICMP, sr1
            
            packet = IP(dst=host) / ICMP()
            reply = sr1(packet, timeout=2, verbose=False)
            
            if reply:
                return reply.ttl
        
        except ImportError:
            self.logger.debug("Scapy not available for TTL detection")
        except Exception as e:
            self.logger.debug(f"TTL detection failed: {e}")
        
        return None
    
    def _guess_os_from_ttl(self, ttl: Optional[int]) -> Dict:
        """
        Guess OS based on TTL value.
        
        Args:
            ttl: TTL value from ICMP reply
        
        Returns:
            Dictionary with OS guess
        """
        if ttl is None:
            return {"name": "Unknown", "confidence": 0, "method": "ttl"}
        
        os_guesses = {
            128: ("Windows", 90),
            64: ("Linux/Unix", 85),
            255: ("Cisco/Network Device", 80),
            32: ("Windows/Old", 70),
        }
        
        closest = min(os_guesses.keys(), key=lambda x: abs(x - ttl))
        os_name, confidence = os_guesses[closest]
        
        if ttl == closest:
            confidence = 95
        elif abs(ttl - closest) <= 10:
            confidence = 75
        else:
            confidence = 50
        
        return {
            "name": os_name,
            "ttl": ttl,
            "confidence": confidence,
            "method": "ttl"
        }


class VulnerabilityScanner:
    """
    Basic vulnerability scanning based on service versions.
    """
    
    VULNERABILITIES = {
        "OpenSSH": {
            "5.0": "CVE-2007-3477 - Privilege escalation",
            "7.0": "CVE-2016-3113 - Information disclosure",
        },
        "Apache": {
            "2.4.17": "CVE-2015-3185 - Denial of service",
            "2.4.49": "CVE-2021-41773 - Remote code execution",
        },
    }
    
    def __init__(self, logger: logging.Logger = None):
        """Initialize vulnerability scanner."""
        self.logger = logger or logging.getLogger(__name__)
    
    def scan(self, services: Dict[int, Dict]) -> Dict:
        """
        Scan services for known vulnerabilities.
        
        Args:
            services: Dictionary of detected services
        
        Returns:
            Dictionary with vulnerability findings
        """
        vulnerabilities = {}
        
        for port, service_info in services.items():
            service_name = service_info.get("name", "")
            version = service_info.get("version", "")

            known_versions = self.VULNERABILITIES.get(service_name, {})
            for known_version, vuln in known_versions.items():
                # Tolerant match: detected "7.0p1" matches known "7.0".
                if version and (version == known_version
                                or version.startswith(known_version)):
                    vulnerabilities[f"{service_name}-{version}"] = vuln
                    break

        return vulnerabilities
