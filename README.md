<p align="center">
  <img src="anansi.png" alt="Anansi" width="480" />
</p>

# Anansi - Advanced Penetration Testing Framework

[![CI](https://github.com/herson/anansi/actions/workflows/ci.yml/badge.svg)](https://github.com/herson/anansi/actions/workflows/ci.yml)
[![GitHub License](https://img.shields.io/github/license/herson/anansi)](https://github.com/herson/anansi/blob/main/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/herson/anansi?style=social)](https://github.com/herson/anansi/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/herson/anansi?style=social)](https://github.com/herson/anansi/network/forks)
[![GitHub issues](https://img.shields.io/github/issues/herson/anansi)](https://github.com/herson/anansi/issues)
[![Last commit](https://img.shields.io/github/last-commit/herson/anansi)](https://github.com/herson/anansi/commits/main)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

Anansi is a modular, Python-based penetration testing framework that unifies network scanning, service enumeration, CVE lookup, DNS enumeration, compliance mapping, exploitation checks, cloud security, and AI-powered analysis — with an optional real-time web dashboard.

> **For authorized security testing only.** Always obtain written permission before scanning systems you do not own.

---

## Quick Demo

```
$ python3 main.py --target 10.0.0.1 --cve --compliance

[*] Scanning for open ports...
[*] Enumerating services...
[*] Looking up CVEs via NVD...

PORT    SERVICE    VERSION              CVEs
------  ---------  -------------------  ----
22/tcp  ssh        OpenSSH 8.2p1        0
80/tcp  http       Apache httpd 2.4.49  2   ← CVE-2021-41773 (CRITICAL 9.8)
443/tcp https      Apache httpd 2.4.49  2
3306/tcp mysql     MySQL 5.7.36         1

--- Compliance Mapping ---
PCI-DSS:
  • PCI-DSS 6.3.3 – Install applicable security patches
    Evidence: CVE-2021-41773 (CVSS 9.8) on port 80

NIST:
  • NIST SP 800-53 SI-2 – Flaw Remediation (Critical severity)
  • NIST SP 800-53 SC-8 – Transmission Confidentiality
    Evidence: Port 80 runs http, an unencrypted protocol
```

```
$ python3 main.py --dns example.com

{
  "domain": "example.com",
  "records": {
    "A": ["93.184.216.34"],
    "MX": ["0 ."],
    "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
    "TXT": ["v=spf1 -all"]
  },
  "subdomains": ["www.example.com", "mail.example.com"],
  "zone_transfer": {"a.iana-servers.net": []}
}
```

---

## Features

| Feature | Flag | Description |
|---------|------|-------------|
| Network Scanning | `--target` | Discover open ports and services via nmap |
| CVE Lookup | `--cve` | Query NIST NVD API v2 for known vulnerabilities |
| DNS Enumeration | `--dns DOMAIN` | Record lookup, subdomain brute-force, zone transfer |
| Compliance Mapping | `--compliance` | Map findings to PCI-DSS, HIPAA, NIST SP 800-53 |
| Exploitation Checks | _(auto)_ | Safe Metasploit integration |
| AI Analysis | `--ai` | OpenAI-powered remediation suggestions |
| Cloud Security | `--s3` | Scan AWS S3 buckets for public access |
| PDF Reports | `--pdf` | Professional PDF with CVE details + compliance |
| Web Dashboard | `--web` | FastAPI dashboard with SSE progress + history |
| Docker | — | One-command deploy with `docker compose up` |

---

## Installation

### Prerequisites

- Python 3.10+
- `nmap` on PATH (`apt install nmap` / `brew install nmap`)
- Metasploit (`msfconsole`) — optional, for exploitation checks

```bash
git clone https://github.com/herson/anansi.git
cd anansi
pip install -r requirements.txt
cp .env.example .env   # add your API keys
```

### Docker (recommended)

```bash
docker compose up --build
# Dashboard → http://localhost:8000
```

Runs with `NET_RAW`/`NET_ADMIN` capabilities for nmap stealth scans.

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANANSI_API_KEY` | Protect all API endpoints and `/docs` |
| `NVD_API_KEY` | Higher NVD rate limits (10 req/s vs 5 req/min) |
| `OPENAI_API_KEY` | Required for `--ai` |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Required for `--s3` |

---

## Usage

```bash
# Network scan + CVE lookup + compliance report + PDF
python3 main.py --target 192.168.1.0/24 --cve --compliance --pdf

# DNS enumeration
python3 main.py --dns example.com

# Compliance check against specific frameworks
python3 main.py --target 10.0.0.1 --cve --compliance PCI-DSS HIPAA

# AI-assisted analysis
OPENAI_API_KEY=sk-... python3 main.py --target 10.0.0.1 --ai

# Cloud security
python3 main.py --s3 my-bucket-name

# Web dashboard
python3 main.py --web

# Multithreaded scan
python3 main.py --target 10.0.0.0/24 --threads 20
```

---

## Web Dashboard & API

Start with `python3 main.py --web` or `docker compose up`.

All endpoints require `X-API-Key` header when `ANANSI_API_KEY` is set. The `/docs` (Swagger UI) and `/openapi.json` are also protected.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Live dashboard |
| `POST` | `/scan?target=IP[&cve=true]` | Start a background scan |
| `GET` | `/api/status` | Scan state |
| `GET` | `/api/progress` | SSE stream with real-time progress |
| `GET` | `/api/history` | Recent scan list |
| `GET` | `/api/scan/{id}` | Full results for a past scan |
| `POST` | `/api/schedule?target=IP&cron=EXPR` | Schedule a recurring scan |
| `GET` | `/api/schedule` | List scheduled scans |
| `DELETE` | `/api/schedule/{job_id}` | Remove a schedule |

```bash
# Schedule a nightly scan at 02:00
curl -X POST -H "X-API-Key: $ANANSI_API_KEY" \
  "http://localhost:8000/api/schedule?target=10.0.0.0/24&cron=0+2+*+*+*&cve=true"
```

---

## Configuration

`config.yaml`:

```yaml
default:
  scan_type: "full"
  max_threads: 10
  report_format: "json"
  exclude_ports: [22, 80]
  metasploit_enabled: false
```

---

## Running Tests

```bash
PYTHONPATH=. python -m unittest discover -s tests/modules
# 87 tests across 10 modules — no system dependencies required
```

---

## CI / Security

Every push and PR runs:

1. **flake8** — syntax and undefined name checks
2. **bandit** — static security analysis (medium+ severity)
3. **pip-audit** — dependency CVE audit
4. **unittest** — full test suite on Python 3.10, 3.11, and 3.12

---

## Contributing

Contributions are welcome!

👉 **[Contributing Guidelines](.github/CONTRIBUTING.md)** · **[Code of Conduct](.github/CODE_OF_CONDUCT.md)**

---

## License

[MIT License](LICENSE) — **Herson Cruz** · [@hersoncruz](https://twitter.com/hersoncruz)  
[https://github.com/herson/anansi](https://github.com/herson/anansi)
