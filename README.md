# Anansi - Advanced Penetration Testing Framework

[![CI](https://github.com/herson/anansi/actions/workflows/ci.yml/badge.svg)](https://github.com/herson/anansi/actions/workflows/ci.yml)
[![GitHub License](https://img.shields.io/github/license/herson/anansi)](https://github.com/herson/anansi/blob/main/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)

Anansi is a modular penetration testing framework that unifies network scanning, service enumeration, CVE lookup, DNS enumeration, compliance mapping, exploitation checks, cloud security, and AI-powered analysis into a single command-line tool with an optional web dashboard.

---

## Support the Project

[<img src="https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86" width="150" />](https://github.com/sponsors/herson)

---

## Features

| Feature | Description |
|---------|-------------|
| Network Scanning | Discover open ports and services using `nmap` |
| Service Enumeration | Identify service names and versions |
| CVE Lookup | Query NIST NVD API v2 for known vulnerabilities |
| DNS Enumeration | Record lookup, subdomain brute-force, zone transfer attempts |
| Compliance Mapping | Map findings to PCI-DSS, HIPAA, and NIST SP 800-53 controls |
| Exploitation Checks | Safe Metasploit integration with command-injection protection |
| Cloud Security | Scan AWS S3 buckets for public access risks |
| AI Analysis | OpenAI-powered remediation suggestions |
| Web Dashboard | FastAPI dashboard with real-time SSE progress, scan history, and scheduled scans |
| PDF Reports | Professional PDF output with CVE details and compliance section |
| Structured Reports | JSON and CSV output |

---

## Installation

### Prerequisites

- Python 3.10+
- `nmap` installed and on PATH (`apt install nmap` / `brew install nmap`)
- Metasploit (`msfconsole`) — optional, for exploitation checks
- Docker — optional, for containerised runs

### Standard Install

```bash
git clone https://github.com/herson/anansi.git
cd anansi
pip install -r requirements.txt
cp .env.example .env          # edit to set API keys
```

### Docker

```bash
docker compose up --build
```

The web dashboard is then available at `http://localhost:8000`.

The container runs with `NET_RAW` and `NET_ADMIN` capabilities so that nmap stealth scans work correctly.

---

## Environment Variables

Copy `.env.example` and set values as needed:

| Variable | Purpose |
|----------|---------|
| `ANANSI_API_KEY` | Protect all API endpoints and `/docs` with an API key |
| `NVD_API_KEY` | NVD API key for higher rate limits (optional) |
| `OPENAI_API_KEY` | Required for `--ai` analysis |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Required for `--s3` cloud scanning |

---

## Command-Line Usage

### Basic Network Scan

```bash
python3 main.py --target 192.168.1.1
python3 main.py --target 10.0.0.0/24 --threads 20
```

### CVE Lookup

Enrich scan results with known CVEs from the NIST NVD API:

```bash
python3 main.py --target 192.168.1.1 --cve
NVD_API_KEY=your_key python3 main.py --target 192.168.1.1 --cve
```

### DNS Enumeration

Run full DNS enumeration on a domain (A/AAAA/MX/NS/TXT/CNAME/SOA records, subdomain brute-force, zone transfer attempt):

```bash
python3 main.py --dns example.com
```

### Compliance Mapping

Map findings to compliance frameworks. Omit framework names to check all three (PCI-DSS, HIPAA, NIST):

```bash
python3 main.py --target 192.168.1.1 --compliance
python3 main.py --target 192.168.1.1 --cve --compliance PCI-DSS HIPAA
```

### PDF Report

Generate a PDF report, optionally including a compliance section:

```bash
python3 main.py --target 192.168.1.1 --pdf
python3 main.py --target 192.168.1.1 --cve --compliance --pdf
```

### AI Analysis

```bash
OPENAI_API_KEY=sk-... python3 main.py --target 192.168.1.1 --ai
```

### Cloud Security

```bash
python3 main.py --s3 my-bucket-name
```

### Web Dashboard

```bash
python3 main.py --web
# Open http://localhost:8000
```

---

## Web Dashboard & API

Start the dashboard with `python3 main.py --web` or `docker compose up`.

### API Authentication

Set `ANANSI_API_KEY` in your environment. Pass the key in the `X-API-Key` header for all API requests. The `/docs`, `/redoc`, and `/openapi.json` endpoints are also protected when an API key is configured.

```bash
curl -H "X-API-Key: your_key" http://localhost:8000/api/status
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | HTML dashboard |
| `POST` | `/scan?target=IP[&cve=true]` | Start a background scan |
| `GET` | `/api/status` | Scan status (`is_scanning`, `results_available`) |
| `GET` | `/api/progress` | Server-Sent Events stream with real-time progress |
| `GET` | `/api/history[?limit=N]` | List recent scans (metadata only) |
| `GET` | `/api/scan/{id}` | Full results for a past scan |
| `POST` | `/api/schedule?target=IP&cron=EXPR[&cve=true]` | Schedule a recurring scan |
| `GET` | `/api/schedule` | List scheduled scans |
| `DELETE` | `/api/schedule/{job_id}` | Remove a scheduled scan |

#### Schedule example

```bash
# Scan nightly at 02:00
curl -X POST -H "X-API-Key: your_key" \
  "http://localhost:8000/api/schedule?target=10.0.0.1&cron=0+2+*+*+*"
```

---

## Configuration

`config.yaml` controls default scan behaviour:

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
```

The test suite covers all modules (68+ tests). It uses in-memory SQLite and mocked C-extension packages (`nmap`, `fpdf`, `dnspython`) so no system dependencies are required to run tests.

---

## CI / Security

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push and pull request:

1. **flake8** — syntax and style checks
2. **bandit** — static security analysis (medium+ severity)
3. **pip-audit** — known vulnerability audit of all dependencies
4. **unittest** — full test suite on Python 3.10, 3.11, and 3.12

---

## Contributing

Contributions are welcome!

👉 **[Read the Contributing Guidelines](.github/CONTRIBUTING.md)**

Please also review our [Code of Conduct](.github/CODE_OF_CONDUCT.md) before participating.

---

## License

[MIT License](LICENSE)

---

**Herson Cruz** — [@hersoncruz](https://twitter.com/hersoncruz)  
Project: [https://github.com/herson/anansi](https://github.com/herson/anansi)
