import argparse
import json
import logging
import os
import re
import sys
from dataclasses import asdict

from domain.findings import Finding
from modules.app_logging import configure_logging
from modules.config import ConfigError, load_config
from modules.scanner import NetworkScanner
from modules.enumerator import ServiceEnumerator
from modules.exploiter import Exploiter
from modules.reporter import Reporter, check_report_format
from modules.intelligence import IntelligentAnalyzer
from modules.targets import MAX_TARGET_ADDRESSES, validate_target


def _validate_bucket_name(name: str) -> bool:
    """Return True if name meets S3 bucket naming rules."""
    return bool(re.match(r'^[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]$', name))


def main() -> None:
    configure_logging()
    try:
        config = load_config()
    except ConfigError as e:
        print(f"Error loading config: {e}")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Anansi - Basic Penetration Testing Framework")
    parser.add_argument('--target', help='Target IP address or range')
    parser.add_argument('--threads', type=int, default=config['default']['max_threads'],
                        help='Number of threads to use (1-100)')
    parser.add_argument('--ai', action='store_true',
                        help='Enable AI-powered analysis (see the ai_* settings in config.yaml)')
    parser.add_argument('--cve', action='store_true',
                        help='Look up CVEs for discovered services via NVD API')
    parser.add_argument('--web', action='store_true', help='Launch the Web Dashboard')
    parser.add_argument('--s3', help='Scan an AWS S3 bucket for public access')
    parser.add_argument('--pdf', action='store_true', help='Generate a PDF report')
    parser.add_argument('--exploit', action='store_true',
                        help='Run exploitation checks against discovered services (opt-in; '
                             'none are implemented yet)')
    parser.add_argument('--dns', metavar='DOMAIN',
                        help='Run DNS enumeration on DOMAIN (records, subdomains, zone transfer)')
    parser.add_argument('--compliance', nargs='*', metavar='FRAMEWORK',
                        help='Map findings to compliance frameworks (PCI-DSS, HIPAA, NIST). '
                             'Omit values to check all three.')
    args = parser.parse_args()

    if not 1 <= args.threads <= 100:
        print("Error: --threads must be between 1 and 100")
        sys.exit(1)

    if args.dns:
        from modules.dns_enum import DNSEnumerator
        print(f"\nRunning DNS enumeration for: {args.dns}")
        dns_results = DNSEnumerator(args.dns).enumerate()
        print(json.dumps(dns_results, indent=2))
        return

    if args.web:
        from web.app import start_server
        start_server()
        return

    if args.s3:
        if not _validate_bucket_name(args.s3):
            print(f"Error: '{args.s3}' is not a valid S3 bucket name.")
            sys.exit(1)
        from modules.cloud import CloudScanner
        print(f"Scanning S3 Bucket: {args.s3}")
        report = CloudScanner().scan_bucket(args.s3)
        print(json.dumps(asdict(report), indent=2))
        if report.errors:
            sys.exit(1)
        return

    if not args.target:
        print("Error: --target is required for network scanning.")
        sys.exit(1)

    if not validate_target(args.target):
        print(f"Error: '{args.target}' must be an IP address or a CIDR range "
              f"of at most {MAX_TARGET_ADDRESSES:,} addresses.")
        sys.exit(1)

    report_format = config['default']['report_format']
    try:
        check_report_format(report_format)
    except ValueError as e:
        print(f"Error in config.yaml: {e}")
        sys.exit(1)

    analyzer = None
    if args.ai:
        try:
            analyzer = IntelligentAnalyzer(config['default'])
        except ValueError as e:
            print(f"Error in config.yaml: {e}")
            sys.exit(1)

    exclude_ports = config['default'].get('exclude_ports', [])
    scanner = NetworkScanner(args.target, args.threads, exclude_ports=exclude_ports)
    scan_results = scanner.scan()

    findings: list[Finding] = ServiceEnumerator(scan_results).enumerate()

    if args.cve:
        from modules.vuln_lookup import VulnLookup
        print("\nLooking up CVEs via NVD (this may take a moment)...")
        lookup = VulnLookup(api_key=os.getenv('NVD_API_KEY'))
        findings = lookup.enrich(findings)

    if args.exploit:
        findings = Exploiter(findings).exploit()

    if analyzer:
        print("\nRunning AI Analysis...")
        ai_report = analyzer.analyze(findings)
        print("\n--- AI Analysis Report ---")
        print(ai_report)
        print("--------------------------\n")

    reporter = Reporter(findings, report_format)
    reporter.generate_report()

    compliance_findings: dict[str, list[dict[str, str]]] = {}
    if args.compliance is not None:
        from modules.compliance import ComplianceMapper
        frameworks = args.compliance or None
        compliance_findings = ComplianceMapper(findings).map(frameworks=frameworks)
        print("\n--- Compliance Mapping ---")
        print(json.dumps(compliance_findings, indent=2))
        print("--------------------------\n")

    if args.pdf:
        from modules.reporting_pdf import PDFReporter, report_filename
        PDFReporter({'target': args.target}, findings).generate(
            report_filename(args.target), compliance_findings)

    logging.info("Penetration testing completed for target: %s", args.target)


if __name__ == "__main__":
    main()
