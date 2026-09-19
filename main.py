#!/usr/bin/env python3
"""
ShibaCuddles - Advanced Network Scanner
A comprehensive, high-performance network scanning tool written in Python.
Supports device discovery, port scanning, service detection, and vulnerability assessment.
"""

import argparse
import sys
import logging
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent))

from src.scanner import NetworkScanner
from src.utils import setup_logging, validate_network, print_banner

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

  # Save results to file
  python main.py 192.168.1.0/24 --output results.json --format json

  # Parallel scanning with 20 threads
  python main.py 192.168.1.0/24 --threads 20 --timeout 3
        """
    )
    
    # Required arguments
    parser.add_argument("network", help="Target network in CIDR notation (e.g., 192.168.1.0/24)")
    
    # Scanning options
    parser.add_argument(
        "--ports", "-p",
        type=str,
        default="1-1024",
        help="Ports to scan: range (1-1024) or list (22,80,443) [default: 1-1024]"
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=10,
        help="Number of threads for parallel scanning [default: 10]"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds [default: 5.0]"
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        help="Delay between scans in seconds (0 for no limit) [default: 0.0]"
    )
    
    # Feature flags
    parser.add_argument(
        "--ping-sweep", "-ps",
        action="store_true",
        help="Enable ICMP ping sweep for device discovery (on by default; this flag is accepted for explicitness)"
    )
    parser.add_argument(
        "--service-detection", "-sd",
        action="store_true",
        help="Enable service version detection"
    )
    parser.add_argument(
        "--os-detection", "-os",
        action="store_true",
        help="Enable OS fingerprinting"
    )
    parser.add_argument(
        "--aggressive", "-A",
        action="store_true",
        help="Enable aggressive scanning (service + OS detection)"
    )
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Skip ping sweep, scan all hosts"
    )
    
    # Output options
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path (auto-detects format from extension)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "xml", "txt"],
        default="json",
        help="Output format [default: json]"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Verbose output (use -vv for extra verbosity)"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all output except results"
    )
    
    # Performance options
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Batch size for processing results [default: 50]"
    )
    parser.add_argument(
        "--skip-broadcast",
        action="store_true",
        help="Skip broadcast and network addresses"
    )
    
    return parser.parse_args()


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
    
    # Create scanner instance
    scanner = NetworkScanner(
        network=args.network,
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        batch_size=args.batch_size,
        skip_broadcast=args.skip_broadcast,
        logger=logger
    )
    
    # Configure scanner features
    if args.aggressive:
        scanner.enable_service_detection = True
        scanner.enable_os_detection = True
    else:
        scanner.enable_service_detection = args.service_detection
        scanner.enable_os_detection = args.os_detection
    
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
        
        # Save results if output file specified
        if args.output:
            scanner.save_results(results, args.output, args.format)
            logger.info(f"Results saved to {args.output}")
        
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
