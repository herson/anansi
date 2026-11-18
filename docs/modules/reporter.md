# Reporter

`Reporter` writes findings to `reports/report.json` or `reports/report.csv`, readable only by the user who ran the scan.

```python
from modules.reporter import Reporter

Reporter(findings, report_format="csv").generate_report()
```

`report_format` comes from `default.report_format` in `config.yaml` and must be `json` or `csv`; any other value raises `ValueError`, and the CLI rejects it before scanning.

- **JSON**: the list of findings, each with its CVEs.
- **CSV**: one row per finding, with columns `Host`, `Port`, `Protocol`, `Service`, `Product`, `Version`, `CVE Count`, `Top CVSS` and `Top Severity`.

`--pdf` writes a separate PDF report with `modules/reporting_pdf.py`.
