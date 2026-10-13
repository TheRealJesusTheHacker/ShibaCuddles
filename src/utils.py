"""
Utility functions for ShibaCuddles scanner.
Provides helpers for IP handling, logging, and output formatting.
"""

import ipaddress
import logging
import socket
import sys
from datetime import timedelta
from functools import lru_cache
from typing import List


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Configure logging with formatted output.

    Args:
        level: Logging level

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("shibacuddles")
    logger.setLevel(level)

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    # Formatter
    formatter = logging.Formatter(
        fmt="[%(asctime)s] %(levelname)-8s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def validate_network(network: str) -> bool:
    """
    Validate CIDR network notation.

    Args:
        network: Network string in CIDR format

    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except (ValueError, TypeError):
        return False


def parse_port_spec(port_spec: str) -> List[int]:
    """
    Parse port specification into list of ports.

    Supports:
    - Range: "1-1024"
    - List: "22,80,443"
    - Mixed: "22,80,443,8000-8100"

    Args:
        port_spec: Port specification string

    Returns:
        Sorted list of unique port numbers

    Raises:
        ValueError: If port spec is invalid
    """
    # Non-string input is an invalid spec, not a crash: callers such as
    # PortScanner.scan() catch ValueError (the documented contract) and
    # treat the scan as empty, but the parser itself would raise
    # AttributeError (no .split) or TypeError (unhashable, from the
    # cache) and escape straight through them.
    if not isinstance(port_spec, str):
        raise ValueError(
            f"Port specification must be a string, "
            f"got {type(port_spec).__name__}"
        )

    # Memoized: PortScanner.scan() re-parses the spec for every host, and
    # a full-range parse ("1-65535") costs ~20 ms -- across a /24 that was
    # ~5 s of pure re-parsing per scan. The cached value is an immutable
    # tuple; each caller gets a fresh list copy it may freely mutate.
    return list(_parse_port_spec_cached(port_spec))


@lru_cache(maxsize=128)
def _parse_port_spec_cached(port_spec: str) -> tuple:
    """Worker for parse_port_spec; returns the ports as a sorted tuple."""
    ports = set()

    for segment in port_spec.split(","):
        segment = segment.strip()

        if "-" in segment:
            # Range format
            try:
                start, end = segment.split("-")
                start, end = int(start.strip()), int(end.strip())

                if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                    raise ValueError(f"Port out of range: {segment}")

                if start > end:
                    raise ValueError(f"Invalid port range (start > end): {segment}")

                ports.update(range(start, end + 1))
            except ValueError as e:
                raise ValueError(f"Invalid port range: {segment}") from e
        else:
            # Single port
            try:
                port = int(segment)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port out of range: {port}")
                ports.add(port)
            except ValueError as e:
                raise ValueError(f"Invalid port: {segment}") from e

    return tuple(sorted(ports))


def clamp_threads(threads: int, maximum: int) -> int:
    """
    Clamp a worker-thread count to [1, maximum].

    ThreadPoolExecutor raises ValueError for max_workers < 1, so every
    scanner class floors its count at 1; each class keeps its own cap.
    The clamp lived inline in three classes -- it is spelled out once
    here so the floor/cap logic cannot drift between them again.

    Args:
        threads: Requested thread count
        maximum: Per-class cap

    Returns:
        The clamped thread count
    """
    return max(1, min(threads, maximum))


def format_elapsed_time(seconds: float) -> str:
    """
    Format seconds into human-readable duration.

    Args:
        seconds: Number of seconds

    Returns:
        Formatted duration string
    """
    td = timedelta(seconds=seconds)
    hours, remainder = divmod(int(td.total_seconds()), 3600)
    minutes, secs = divmod(remainder, 60)

    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)


def print_banner():
    """Print ShibaCuddles banner."""
    banner = r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                   🐕 ShibaCuddles 🐕                          ║
    ║              Advanced Network Scanner v0.3.2                  ║
    ║          High-Performance Parallel Scanning                   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    try:
        print(banner)
    except UnicodeEncodeError:
        # Legacy Windows consoles (cp437/cp1252 codepages) cannot render
        # the box-drawing glyphs or the emoji: fall back to plain ASCII
        # so startup never crashes on a codepage-limited console.
        print("ShibaCuddles - Advanced Network Scanner v0.3.2")


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes into human-readable format.

    Args:
        bytes_value: Number of bytes

    Returns:
        Formatted bytes string
    """
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} TB"


def is_ip(value: str) -> bool:
    """Check if value is valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_ipv4(value: str) -> bool:
    """Check if value is valid IPv4 address."""
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4
    except ValueError:
        return False


def is_ipv6(value: str) -> bool:
    """Check if value is valid IPv6 address."""
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 6
    except ValueError:
        return False


def cidr_to_range(cidr: str) -> tuple:
    """
    Convert CIDR notation to IP range (first, last).

    Args:
        cidr: CIDR notation string

    Returns:
        Tuple of (first_ip, last_ip)

    Raises:
        ValueError: If CIDR is invalid
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        first = str(network.network_address)
        last = str(network.broadcast_address)
        return (first, last)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {cidr}") from e


def get_host_count(cidr: str) -> int:
    """
    Get number of hosts in CIDR network.

    Args:
        cidr: CIDR notation string

    Returns:
        Number of usable hosts
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return (
            network.num_addresses - 2
            if network.num_addresses > 2
            else network.num_addresses
        )
    except ValueError:
        return 0


@lru_cache(maxsize=1024)
def _resolve_family(host: str, sock_type: int) -> int:
    """Address family for ``host``, cached.

    getaddrinfo can hit DNS for hostnames; without caching, every port
    probe pays for a fresh resolution. lru_cache is thread-safe.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=sock_type)
        return infos[0][0] if infos else socket.AF_INET
    except socket.gaierror:
        return socket.AF_INET


def create_socket(host: str, sock_type: int) -> socket.socket:
    """
    Create a socket with the address family matching ``host``.

    Uses getaddrinfo so IPv6 targets get AF_INET6 instead of silently
    failing on an AF_INET socket (which reports every port closed).
    The family lookup is cached per (host, type).

    Args:
        host: Target hostname or IP address
        sock_type: socket.SOCK_STREAM or socket.SOCK_DGRAM

    Returns:
        An unconnected socket of the right family
    """
    return socket.socket(_resolve_family(host, sock_type), sock_type)
