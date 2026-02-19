import nmap
import os
from concurrent.futures import ThreadPoolExecutor

class NetworkScanner:
    def __init__(self, target, threads):
        self.target = target
        self.threads = threads
        self.nm = nmap.PortScanner()

    def scan(self):
        # Check for root privileges
        if os.geteuid() == 0:
            scan_args = "-sS" # Stealth scan (requires root)
            scan_type = "Stealth Scan (-sS)"
        else:
            scan_args = "-sT" # Connect scan (no root required)
            scan_type = "Connect Scan (-sT)"

        print(f"Scanning {self.target} for open ports using {scan_type}...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Note: nmap.scan arguments should include ports if needed, but defaults are fine for now
            future = executor.submit(self.nm.scan, self.target, arguments=scan_args)
            scan_result = future.result()
        print("Scan completed.")
        return scan_result