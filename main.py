import argparse
from modules.scanner import NetworkScanner
from modules.enumerator import ServiceEnumerator
from modules.exploiter import Exploiter
from modules.reporter import Reporter
from modules.intelligence import IntelligentAnalyzer
import logging
import yaml
import os

# Initialize logger
# Ensure logs directory exists
log_dir = os.path.join(os.getcwd(), "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(filename=os.path.join(log_dir, "anansi.log"), level=logging.INFO)

# Load configuration
with open("config.yaml", "r") as file:
    config = yaml.safe_load(file)

def main():
    # Argument parser
    parser = argparse.ArgumentParser(description="Anansi - Basic Penetration Testing Framework")
    parser.add_argument('--target', required=True, help='Target IP address or range')
    parser.add_argument('--threads', type=int, default=config['default']['max_threads'], help='Number of threads to use')
    parser.add_argument('--ai', action='store_true', help='Enable AI-powered analysis of scan results (Requires OPENAI_API_KEY)')
    args = parser.parse_args()

    # Initialize scanning, enumeration, exploitation, and reporting
    scanner = NetworkScanner(args.target, args.threads)
    scan_results = scanner.scan()

    enumerator = ServiceEnumerator(scan_results)
    services = enumerator.enumerate()

    exploiter = Exploiter(services)
    # The Exploiter modifies services/results in place or returns them? 
    # Exploiter implementation: return self.vulnerabilities (which is passed as argument 'services')
    # But wait, scanner.scan() returns 'scan_result' (a dict from python-nmap).
    # enumerator.enumerate() takes scan_result (scan_data) and returns 'services' dict.
    # exploiter.exploit() takes 'services' dict (vulnerabilities) and returns it after trying exploit.
    
    final_results = exploiter.exploit()

    # AI Analysis
    if args.ai:
        print("\n🧠 Running AI Analysis...")
        analyzer = IntelligentAnalyzer(config['default'])
        ai_report = analyzer.analyze(scan_results) # Pass the raw scan data for better context
        print("\n--- AI Analysis Report ---")
        print(ai_report)
        print("--------------------------\n")
        # Optionally attach AI report to final_results if reporter supports it, 
        # but for now just printing it is a good first step.

    reporter = Reporter(final_results)
    reporter.generate_report()

    logging.info("Penetration testing completed for target: %s", args.target)

if __name__ == "__main__":
    main()