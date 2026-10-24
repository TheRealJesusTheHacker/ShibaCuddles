#!/usr/bin/env python3
"""
ShibaCuddles - Advanced Network Scanner
A comprehensive, high-performance network scanning tool written in Python.
It supports device discovery, port scanning, service detection, and
vulnerability assessment.
"""

import argparse
import logging
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent))

from src.scanner import NetworkScanner
from src.utils import parse_port_spec, print_banner, setup_logging, validate_network


def parse_arguments():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="ShibaCuddles - Advanced Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic network scan
  python main.py 192.168.1.0/24

  # Scan with custom ports
  python main.py 192.168.1.0/24 --ports 22,80,443,8080

  # Aggressive scan with service detection
  python main.py 192.168.1.0/24 --aggressive --service-detection

  # UDP scan plus vulnerability matching on detected services
  python main.py 192.168.1.0/24 --udp --vuln-scan

  # Save results to file
  python main.py 192.168.1.0/24 --output results.json --format json

  # Parallel scanning with 20 threads
  python main.py 192.168.1.0/24 --threads 20 --timeout 3
        """,
    )

    # Required arguments
    parser.add_argument(
        "network", help="Target network in CIDR notation (e.g., 192.168.1.0/24)"
    )

    # Scanning options
    parser.add_argument(
        "--ports",
        "-p",
        type=str,
        default="1-1024",
        help="Ports to scan: range (1-1024) or list (22,80,443) [default: 1-1024]",
    )
    parser.add_argument(
        "--threads",
        "-t",
        type=int,
        default=10,
        help="Number of threads for parallel scanning [default: 10]",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds [default: 5.0]",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        help="Delay between scans in seconds (0 for no limit) [default: 0.0]",
    )

    # Feature flags
    parser.add_argument(
        "--ping-sweep",
        "-ps",
        action="store_true",
        help=(
            "Enable ICMP ping sweep for device discovery "
            "(on by default; this flag is accepted for explicitness)"
        ),
    )
    parser.add_argument(
        "--service-detection",
        "-sd",
        action="store_true",
        help="Enable service version detection",
    )
    parser.add_argument(
        "--os-detection", "-os", action="store_true", help="Enable OS fingerprinting"
    )
    parser.add_argument(
        "--aggressive",
        "-A",
        action="store_true",
        help="Enable aggressive scanning (service + OS detection)",
    )
    parser.add_argument(
        "--no-ping", action="store_true", help="Skip ping sweep, scan all hosts"
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Also scan for open UDP ports (same port spec as the TCP scan)",
    )
    parser.add_argument(
        "--vuln-scan",
        action="store_true",
        help="Match detected services against the bundled vulnerability "
        "table (demo data: four sample entries, not a vulnerability "
        "feed — a clean result does not mean a host is safe)",
    )

    # Output options
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Output file path (auto-detects format from extension)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "csv", "xml", "txt"],
        default="json",
        help="Output format [default: json]",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Verbose output (use -vv for extra verbosity)",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress all output except results"
    )

    # Performance options
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Batch size for processing results [default: 50]",
    )
    parser.add_argument(
        "--skip-broadcast",
        action="store_true",
        help="Skip broadcast and network addresses",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the authorization confirmation prompt for non-private "
        "targets (only use on networks you own or are authorized to test)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists",
    )

    return parser.parse_args()


def _is_private_target(network: str) -> bool:
    """Return True if the target network is private (RFC1918) address space."""
    import ipaddress

    try:
        net = ipaddress.ip_network(network, strict=False)
        # Explicit CGNAT check: 100.64.0.0/10 (RFC 6598) is shared
        # carrier-grade NAT space that some ipaddress versions do not
        # report as private -- treat it as private here. The target
        # must lie WHOLLY inside the CGNAT range (subnet_of), not
        # merely overlap it: the old overlaps() check classified
        # e.g. 100.0.0.0/8 -- mostly public space that happens to
        # contain the /10 -- as private, skipping the authorization
        # warning for a largely public target.
        if net.is_private:
            return True
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        return net.version == 4 and net.subnet_of(cgnat)
    except ValueError:
        return False


def main():
    """Main entry point."""
    print_banner()
    args = parse_arguments()

    # Setup logging
    log_level = logging.WARNING
    if args.quiet:
        log_level = logging.ERROR
    elif args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG

    logger = setup_logging(log_level)

    # Validate network input
    if not validate_network(args.network):
        logger.error(f"Invalid network: {args.network}")
        sys.exit(1)

    # Validate the port spec here too: the engine only logs a bad spec
    # and returns no results, so without this check a typo'd --ports
    # looked exactly like a completed scan that found nothing (exit 0).
    # The GUI validates the same way before starting a scan.
    try:
        parse_port_spec(args.ports)
    except ValueError as e:
        logger.error(f"Invalid port specification: {e}")
        sys.exit(1)

    # Scope guardrail: warn loudly when the target is not private address
    # space, and require explicit confirmation unless --yes was passed.
    if not _is_private_target(args.network):
        print(f"WARNING: {args.network} is NOT private (RFC1918) address space.")
        print("Scanning a network you do not own or are not authorized to test")
        print("may be illegal. Continue only if you are authorized.")
        if not args.yes:
            try:
                confirm = input(
                    "Type YES to confirm you are authorized to scan "
                    "(Ctrl+C to abort): "
                )
            except (KeyboardInterrupt, EOFError):
                print("\nAborted.")
                return 130
            if confirm.strip() != "YES":
                print("Aborted.")
                return 130

    # Create scanner instance
    scanner = NetworkScanner(
        network=args.network,
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        batch_size=args.batch_size,
        skip_broadcast=args.skip_broadcast,
        logger=logger,
    )

    # Configure scanner features
    if args.aggressive:
        scanner.enable_service_detection = True
        scanner.enable_os_detection = True
    else:
        scanner.enable_service_detection = args.service_detection
        scanner.enable_os_detection = args.os_detection
    scanner.enable_udp_scan = args.udp
    scanner.enable_vuln_scan = args.vuln_scan

    # Ping sweep is ON by default; --no-ping disables it.
    # (--ping-sweep is accepted for explicitness but is a no-op.)
    scanner.ping_sweep = not args.no_ping

    try:
        # Run scan
        logger.info(f"Starting scan on {args.network}")
        results = scanner.scan(args.ports)

        # Display results
        if not args.quiet:
            scanner.print_results(results)

        # Save results if output file specified. ResultsHandler.save
        # reports failure via its return value (and its own error log);
        # don't claim success here when the write actually failed.
        if args.output:
            if scanner.save_results(results, args.output, args.format, args.force):
                logger.info(f"Results saved to {args.output}")
            else:
                logger.error(f"Results were NOT saved to {args.output}")

        return 0

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.verbose >= 2:
            logger.exception("Full traceback:")
        return 1


if __name__ == "__main__":
    sys.exit(main())
