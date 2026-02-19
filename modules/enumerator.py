class ServiceEnumerator:
    def __init__(self, scan_data):
        self.scan_data = scan_data

    def enumerate(self):
        services = {}
        print("Enumerating services...")
        # Ensure scan data is valid
        if not self.scan_data or 'scan' not in self.scan_data:
            return services
            
        for host in self.scan_data['scan']:
            for protocol in self.scan_data['scan'][host]:
                if protocol not in ['tcp', 'udp']:
                    continue
                
                # Double check it is a dict before accessing keys
                if not isinstance(self.scan_data['scan'][host][protocol], dict):
                    continue

                for port in self.scan_data['scan'][host][protocol].keys():
                    service = self.scan_data['scan'][host][protocol][port]['name']
                    version = self.scan_data['scan'][host][protocol][port]['version']
                    services[port] = {'service': service, 'version': version}
        return services