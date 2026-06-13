import argparse
import ipaddress
import json
import logging
import re
import sys
import yaml

from modules.scanner import NetworkScanner
from modules.enumerator import ServiceEnumerator
from modules.exploiter import Exploiter
from modules.reporter import Reporter
from modules.intelligence import IntelligentAnalyzer
# modules/__init__ configures logging (RotatingFileHandler) on import — no setup needed here

try:
    with open("config.yaml", "r") as file:
        config = yaml.safe_load(file)
    if not isinstance(config, dict) or 'default' not in config:
        raise ValueError("Missing 'default' section")
except FileNotFoundError:
    print("Error: config.yaml not found.")
    sys.exit(1)
except (yaml.YAMLError, ValueError) as e:
    print(f"Error loading config.yaml: {e}")
    sys.exit(1)


def _validate_target(target: str) -> bool:
    """Return True if target is a valid IP address or CIDR range."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    return False


def _validate_bucket_name(name: str) -> bool:
    """Return True if name meets S3 bucket naming rules."""
    return bool(re.match(r'^[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]$', name))


def main():
    parser = argparse.ArgumentParser(description="Anansi - Basic Penetration Testing Framework")
    parser.add_argument('--target', help='Target IP address or range')
    parser.add_argument('--threads', type=int, default=config['default']['max_threads'],
                        help='Number of threads to use (1-100)')
    parser.add_argument('--ai', action='store_true',
                        help='Enable AI-powered analysis (requires OPENAI_API_KEY)')
    parser.add_argument('--web', action='store_true', help='Launch the Web Dashboard')
    parser.add_argument('--s3', help='Scan an AWS S3 bucket for public access')
    parser.add_argument('--pdf', action='store_true', help='Generate a PDF report')
    args = parser.parse_args()

    if not 1 <= args.threads <= 100:
        print("Error: --threads must be between 1 and 100")
        sys.exit(1)

    if args.web:
        from web.app import start_server
        print("Starting Anansi Web Dashboard on http://127.0.0.1:8000")
        start_server()
        return

    if args.s3:
        if not _validate_bucket_name(args.s3):
            print(f"Error: '{args.s3}' is not a valid S3 bucket name.")
            sys.exit(1)
        from modules.cloud import CloudScanner
        print(f"Scanning S3 Bucket: {args.s3}")
        cloud_scanner = CloudScanner()
        results = cloud_scanner.scan_bucket(args.s3)
        print(json.dumps(results, indent=2))
        return

    if not args.target:
        print("Error: --target is required for network scanning.")
        sys.exit(1)

    if not _validate_target(args.target):
        print(f"Error: '{args.target}' is not a valid IP address or CIDR range.")
        sys.exit(1)

    exclude_ports = config['default'].get('exclude_ports', [])
    scanner = NetworkScanner(args.target, args.threads, exclude_ports=exclude_ports)
    scan_results = scanner.scan()

    enumerator = ServiceEnumerator(scan_results)
    services = enumerator.enumerate()

    exploiter = Exploiter(services)
    final_results = exploiter.exploit()

    if args.ai:
        print("\nRunning AI Analysis...")
        analyzer = IntelligentAnalyzer(config['default'])
        ai_report = analyzer.analyze(scan_results)
        print("\n--- AI Analysis Report ---")
        print(ai_report)
        print("--------------------------\n")

    reporter = Reporter(final_results)
    reporter.generate_report()

    if args.pdf:
        from modules.reporting_pdf import PDFReporter
        pdf_reporter = PDFReporter({'target': args.target}, final_results)
        pdf_reporter.generate(f"report_{args.target}.pdf")

    logging.info("Penetration testing completed for target: %s", args.target)


if __name__ == "__main__":
    main()
