# API Reference

This section provides detailed documentation on the internal API of the **Anansi** framework, including its core modules, functions, and usage.

## Core Functions

### Scanner
- `scan_network(target: str) -> dict`
  - Scans the network for open ports and services.

### Enumerator
- `enumerate_services(scan_result: dict) -> dict`
  - Enumerates the services running on the open ports found during the scan.

### Exploiter
- `Exploiter(services: dict).exploit() -> dict`
  - Opt-in exploitation checks (CLI `--exploit`). None are implemented yet, so findings are returned unchanged.
  
More detailed API documentation can be auto-generated using [Sphinx](https://www.sphinx-doc.org) or similar tools.