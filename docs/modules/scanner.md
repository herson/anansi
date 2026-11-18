# Scanner

`NetworkScanner` runs `nmap` against a target and returns nmap's raw results.

```python
from modules.scanner import NetworkScanner

scan_data = NetworkScanner("192.168.1.10", threads=10, exclude_ports=[9100]).scan()
```

- **`target`**: an IP address or CIDR range.
- **`threads`**: accepted for the CLI's `--threads`; nmap manages its own parallelism.
- **`exclude_ports`**: ports to skip. When it is set and Anansi is not root, host discovery is skipped (`-Pn`), because unprivileged discovery probes the excluded ports too.

As root it runs a SYN scan (`-sS`); otherwise a TCP connect scan (`-sT`). Both add service and version detection (`-sV`), which CVE lookup and compliance mapping need.

Requires `nmap` on the `PATH`.
