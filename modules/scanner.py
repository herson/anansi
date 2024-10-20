import nmap
from concurrent.futures import ThreadPoolExecutor

class NetworkScanner:
    def __init__(self, target, threads):
        self.target = target
        self.threads = threads
        self.nm = nmap.PortScanner()

    def scan(self):
        print(f"Scanning {self.target} for open ports...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future = executor.submit(self.nm.scan, self.target, arguments="-sS")
            scan_result = future.result()
        print("Scan completed.")
        return scan_result