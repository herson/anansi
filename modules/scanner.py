import nmap
import os


class NetworkScanner:
    def __init__(self, target, threads, exclude_ports=None):
        """
        Args:
            target: IP address or CIDR range to scan.
            threads: Hint for concurrent operations (nmap manages its own parallelism).
            exclude_ports: List of port numbers to skip during the scan.
        """
        self.target = target
        self.threads = threads
        self.exclude_ports = exclude_ports or []
        self.nm = nmap.PortScanner()

    def scan(self):
        """Run an nmap scan against the target and return raw results."""
        if os.geteuid() == 0:
            scan_args = "-sS"
            scan_type = "Stealth Scan (-sS)"
        else:
            scan_args = "-sT"
            scan_type = "Connect Scan (-sT)"

        if self.exclude_ports:
            ports_str = ','.join(str(p) for p in self.exclude_ports)
            scan_args += f" --exclude-ports {ports_str}"

        print(f"Scanning {self.target} for open ports using {scan_type}...")
        scan_result = self.nm.scan(self.target, arguments=scan_args)
        print("Scan completed.")
        return scan_result
