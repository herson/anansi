# Scanner Module

The **Scanner** module is responsible for network discovery and identifying open ports. It uses `nmap` for efficient network scanning.

## Key Functions

- **scan_network(target: str) -> dict**: This function performs a SYN scan on the target and returns a dictionary of open ports and services.

### Example Usage

```python
from modules.scanner import scan_network

scan_result = scan_network("192.168.1.1/24")
print(scan_result)
```

## Dependencies

- Requires `nmap` to be installed on the system.