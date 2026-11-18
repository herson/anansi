# Enumerator

`ServiceEnumerator` turns nmap's raw results into one `Finding` per host, port and protocol ([ADR-0003](../adr/0003-model-scan-results-as-typed-finding-records.md)).

```python
from modules.enumerator import ServiceEnumerator
from modules.scanner import NetworkScanner

findings = ServiceEnumerator(NetworkScanner("192.168.1.10", threads=10).scan()).enumerate()
for f in findings:
    print(f.host, f.port, f.protocol, f.service, f.product, f.version)
```

A `Finding` (`domain/findings.py`) is a frozen record:

| Field | Example |
|---|---|
| `host` | `192.168.1.10` |
| `port` | `80` |
| `protocol` | `tcp` or `udp` |
| `service` | `http` |
| `product` | `Apache httpd` |
| `version` | `2.4.49` |
| `cves` | `Cve` records, empty until `--cve` adds them |

`findings_to_json` gives the plain form used by reports, scan history and the API.
