class ServiceEnumerator:
    def __init__(self, scan_data):
        self.scan_data = scan_data

    def enumerate(self):
        services = {}
        print("Enumerating services...")
        for host in self.scan_data['scan']:
            for protocol in self.scan_data['scan'][host].keys():
                for port in self.scan_data['scan'][host][protocol].keys():
                    service = self.scan_data['scan'][host][protocol][port]['name']
                    version = self.scan_data['scan'][host][protocol][port]['version']
                    services[port] = {'service': service, 'version': version}
        return services