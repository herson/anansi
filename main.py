import argparse
from modules.scanner import NetworkScanner
from modules.enumerator import ServiceEnumerator
from modules.exploiter import Exploiter
from modules.reporter import Reporter
import logging
import yaml
import os

# Initialize logger
logging.basicConfig(filename="logs/anansi.log", level=logging.INFO)

# Load configuration
with open("config.yaml", "r") as file:
    config = yaml.safe_load(file)

def main():
    # Argument parser
    parser = argparse.ArgumentParser(description="Anansi - Basic Penetration Testing Framework")
    parser.add_argument('--target', required=True, help='Target IP address or range')
    parser.add_argument('--threads', type=int, default=config['default']['max_threads'], help='Number of threads to use')
    args = parser.parse_args()

    # Initialize scanning, enumeration, exploitation, and reporting
    scanner = NetworkScanner(args.target, args.threads)
    services = scanner.scan()

    enumerator = ServiceEnumerator(services)
    vulnerabilities = enumerator.enumerate()

    exploiter = Exploiter(vulnerabilities)
    results = exploiter.exploit()

    reporter = Reporter(results)
    reporter.generate_report()

    logging.info("Penetration testing completed for target: %s", args.target)

if __name__ == "__main__":
    main()