# Enumerator Module

The **Enumerator** module analyzes the services running on open ports identified by the **Scanner** module.

## Key Functions

- **enumerate_services(scan_result: dict) -> dict**: This function takes the scan result from `scan_network` and enumerates details about each service.

### Example Usage

```python
from modules.enumerator import enumerate_services

services = enumerate_services(scan_result)
print(services)
```