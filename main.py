import argparse
import json
import logging
import os
import re
import sys
from dataclasses import asdict
from typing import NoReturn

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


def _fail(message: str) -> NoReturn:
    print(message)
    sys.exit(1)


def _parse_args(settings: dict) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Anansi - Basic Penetration Testing Framework")
    parser.add_argument('--target', help='Target IP address or range')
    parser.add_argument('--threads', type=int, default=settings['max_threads'],
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
        _fail("Error: --threads must be between 1 and 100")
    return args


def _enumerate_dns(domain: str) -> None:
    from modules.dns_enum import DNSEnumerator
    print(f"\nRunning DNS enumeration for: {domain}")
    dns_results = DNSEnumerator(domain).enumerate()
    print(json.dumps(dns_results, indent=2))


def _scan_bucket(bucket: str) -> None:
    if not _validate_bucket_name(bucket):
        _fail(f"Error: '{bucket}' is not a valid S3 bucket name.")
    from modules.cloud import CloudScanner
    print(f"Scanning S3 Bucket: {bucket}")
    report = CloudScanner().scan_bucket(bucket)
    print(json.dumps(asdict(report), indent=2))
    if report.errors:
        sys.exit(1)


def _prepare_network_scan(args: argparse.Namespace, settings: dict) -> IntelligentAnalyzer | None:
    """Check everything the scan needs before it starts; return the AI analyzer if --ai."""
    if not args.target:
        _fail("Error: --target is required for network scanning.")
    if not validate_target(args.target):
        _fail(f"Error: '{args.target}' must be an IP address or a CIDR range "
              f"of at most {MAX_TARGET_ADDRESSES:,} addresses.")
    try:
        check_report_format(settings['report_format'])
    except ValueError as e:
        _fail(f"Error in config.yaml: {e}")
    if not args.ai:
        return None
    try:
        return IntelligentAnalyzer(settings)
    except ValueError as e:
        _fail(f"Error in config.yaml: {e}")


def _find_services(args: argparse.Namespace, settings: dict) -> list[Finding]:
    scanner = NetworkScanner(args.target, args.threads, exclude_ports=settings.get('exclude_ports', []))
    findings: list[Finding] = ServiceEnumerator(scanner.scan()).enumerate()
    if args.cve:
        from modules.vuln_lookup import VulnLookup
        print("\nLooking up CVEs via NVD (this may take a moment)...")
        findings = VulnLookup(api_key=os.getenv('NVD_API_KEY')).enrich(findings)
    if args.exploit:
        findings = Exploiter(findings).exploit()
    return findings


def _print_ai_analysis(analyzer: IntelligentAnalyzer, findings: list[Finding]) -> None:
    print("\nRunning AI Analysis...")
    ai_report = analyzer.analyze(findings)
    print("\n--- AI Analysis Report ---")
    print(ai_report)
    print("--------------------------\n")


def _map_compliance(findings: list[Finding], frameworks: list[str]) -> dict[str, list[dict[str, str]]]:
    from modules.compliance import ComplianceMapper
    compliance_findings = ComplianceMapper(findings).map(frameworks=frameworks or None)
    print("\n--- Compliance Mapping ---")
    print(json.dumps(compliance_findings, indent=2))
    print("--------------------------\n")
    return compliance_findings


def _scan_network(args: argparse.Namespace, settings: dict) -> None:
    analyzer = _prepare_network_scan(args, settings)
    findings = _find_services(args, settings)
    if analyzer:
        _print_ai_analysis(analyzer, findings)

    Reporter(findings, settings['report_format']).generate_report()

    compliance_findings: dict[str, list[dict[str, str]]] = {}
    if args.compliance is not None:
        compliance_findings = _map_compliance(findings, args.compliance)

    if args.pdf:
        from modules.reporting_pdf import PDFReporter, report_filename
        PDFReporter({'target': args.target}, findings).generate(
            report_filename(args.target), compliance_findings)

    logging.info("Penetration testing completed for target: %s", args.target)


def main() -> None:
    configure_logging()
    try:
        settings = load_config()['default']
    except ConfigError as e:
        _fail(f"Error loading config: {e}")

    args = _parse_args(settings)
    if args.dns:
        _enumerate_dns(args.dns)
    elif args.web:
        from web.app import start_server
        start_server()
    elif args.s3:
        _scan_bucket(args.s3)
    else:
        _scan_network(args, settings)


if __name__ == "__main__":
    main()
