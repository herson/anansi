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

    @property
    def arguments(self) -> str:
        """The nmap arguments scan() passes. They decide what a scan can find (ADR-0013)."""
        privileged = os.geteuid() == 0
        # Service/version detection: CVE lookup and compliance need real product versions.
        args = ("-sS" if privileged else "-sT") + " -sV"
        excluded = sorted(set(self.exclude_ports))
        if excluded:
            # Unprivileged host discovery probes the target with TCP connects
            # (including port 80); --exclude-ports suppresses those probes too,
            # so every host looks down. Skip discovery and scan the ports directly.
            if not privileged:
                args += " -Pn"
            args += " --exclude-ports " + ",".join(str(p) for p in excluded)
        return args

    def scan(self):
        """Run an nmap scan against the target and return raw results."""
        scan_args = self.arguments
        scan_type = "Stealth Scan (-sS)" if scan_args.startswith("-sS") else "Connect Scan (-sT)"

        print(f"Scanning {self.target} for open ports using {scan_type}...")
        scan_result = self.nm.scan(self.target, arguments=scan_args)
        print("Scan completed.")
        return scan_result
