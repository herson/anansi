class ServiceEnumerator:
    def __init__(self, scan_data):
        """
        Args:
            scan_data: Raw dict returned by NetworkScanner.scan().
        """
        self.scan_data = scan_data

    def enumerate(self):
        """Parse scan data and return a dict of {port: {service, version}}."""
        services = {}
        print("Enumerating services...")
        if not self.scan_data or 'scan' not in self.scan_data:
            return services

        for host in self.scan_data['scan']:
            for protocol in self.scan_data['scan'][host]:
                if protocol not in ['tcp', 'udp']:
                    continue
                if not isinstance(self.scan_data['scan'][host][protocol], dict):
                    continue
                for port in self.scan_data['scan'][host][protocol].keys():
                    service = self.scan_data['scan'][host][protocol][port]['name']
                    version = self.scan_data['scan'][host][protocol][port]['version']
                    services[port] = {'service': service, 'version': version}
        return services
