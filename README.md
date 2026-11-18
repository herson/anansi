<p align="center">
  <img src="anansi.png" alt="Anansi" width="480" />
</p>

# Anansi - Advanced Penetration Testing Framework

[![CI](https://github.com/herson/anansi/actions/workflows/ci.yml/badge.svg)](https://github.com/herson/anansi/actions/workflows/ci.yml)
[![GitHub License](https://img.shields.io/github/license/herson/anansi)](https://github.com/herson/anansi/blob/main/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/herson/anansi?style=social)](https://github.com/herson/anansi/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/herson/anansi?style=social)](https://github.com/herson/anansi/network/forks)
[![GitHub issues](https://img.shields.io/github/issues/herson/anansi)](https://github.com/herson/anansi/issues)
[![Last commit](https://img.shields.io/github/last-commit/herson/anansi)](https://github.com/herson/anansi/commits/main)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

Anansi is a modular, Python-based penetration testing framework that unifies network scanning, service enumeration, CVE lookup, DNS enumeration, compliance mapping, cloud security, and AI-powered analysis — with an optional real-time web dashboard.

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
| Network Scanning | `--target` | Discover open ports, services and product versions via nmap (`-sV`) |
| CVE Lookup | `--cve` | Query NIST NVD API v2 by detected product and version; services without a detected version are skipped |
| DNS Enumeration | `--dns DOMAIN` | Record lookup, subdomain brute-force, zone transfer |
| Compliance Mapping | `--compliance` | Map findings to PCI-DSS, HIPAA, NIST SP 800-53 |
| Exploitation Checks | `--exploit` | Opt-in only, never run by the web dashboard. No checks are implemented yet |
| AI Analysis | `--ai` | Remediation suggestions from OpenAI, OpenRouter or a local model such as Ollama |
| Cloud Security | `--s3` | Scan AWS S3 buckets for public access |
| PDF Reports | `--pdf` | Professional PDF with CVE details + compliance |
| Web Dashboard | `--web` | FastAPI dashboard with SSE progress + history |
| Docker | — | One-command deploy with `docker compose up` |

---

## Installation

### Prerequisites

- Python 3.11+
- `nmap` on PATH (`apt install nmap` / `brew install nmap`)

```bash
git clone https://github.com/herson/anansi.git
cd anansi
pip install -r requirements.txt
cp .env.example .env   # add your API keys
```

### Docker (recommended)

```bash
echo "ANANSI_API_KEY=$(openssl rand -hex 32)" >> .env   # required for Docker
docker compose up --build
# Dashboard → http://localhost:8000
```

The container runs as an unprivileged user, so nmap uses TCP connect scans (`-sT`); SYN "stealth" scans (`-sS`) need a root run outside Docker. The port is published on `127.0.0.1` only, and scan history and logs are kept in the `anansi-data` and `anansi-logs` named volumes. The server will not listen on a non-loopback address unless `ANANSI_API_KEY` is set.

`./scripts/docker-smoke.sh` builds the image and checks that it contains no secret values from `.env`, refuses to run without an API key, runs as a non-root user, and answers through the published port.

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANANSI_API_KEY` | Dashboard and API key, at least 16 characters. Generated per run if unset on localhost; required when `ANANSI_HOST` is not a loopback address |
| `ANANSI_HOST` | Dashboard bind address (default `127.0.0.1`; `0.0.0.0` in Docker) |
| `ANANSI_DB_PATH` | SQLite scan-history file (default `anansi.db`; `/app/data/anansi.db` in Docker) |
| `NVD_API_KEY` | Higher NVD rate limit: 50 instead of 5 requests per rolling 30 seconds, so CVE lookups wait 0.6 s instead of 6 s between services |
| `OPENAI_API_KEY` | Required for `--ai` with the default OpenAI endpoint. Never sent to another `ai_base_url` |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Required for `--s3` |

The `--s3` credentials need these read-only IAM actions on the bucket:
`s3:GetBucketPublicAccessBlock`, `s3:GetBucketAcl` and `s3:GetBucketPolicyStatus`.
A check the credentials can't run is listed under `errors`, and the command exits with status 1.

---

## Usage

```bash
# Network scan + CVE lookup + compliance report + PDF
python3 main.py --target 192.168.1.0/24 --cve --compliance --pdf

# DNS enumeration
python3 main.py --dns example.com

# Compliance check against specific frameworks
python3 main.py --target 10.0.0.1 --cve --compliance PCI-DSS HIPAA

# AI-assisted analysis of the verified CVEs
OPENAI_API_KEY=sk-... python3 main.py --target 10.0.0.1 --cve --ai

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

Every route except `/login` needs a credential ([ADR-0001](docs/adr/0001-require-a-session-backed-api-key-for-every-dashboard-and-api-route.md)):

- **Browsers** sign in once at `/login` with the key and get an `HttpOnly`, `SameSite=Strict` session cookie that lasts 12 hours or until the server restarts.
- **Scripts** send the key in the `X-API-Key` header on every request.

The key is `ANANSI_API_KEY` (at least 16 characters). If it is unset and the server only listens on localhost, a random key is generated at startup and printed in the terminal. On a network, put the dashboard behind TLS: the key and cookie are otherwise sent in clear text.

The dashboard loads no third-party code and every response carries a strict Content-Security-Policy ([ADR-0002](docs/adr/0002-serve-dashboard-styles-and-scripts-from-the-app-with-a-strict-csp.md)). There is no Swagger UI page for the same reason; load `/openapi.json` (with `X-API-Key`) into any OpenAPI viewer instead.

| Method | Path | Description |
|--------|------|-------------|
| `GET`/`POST` | `/login` | Sign-in page (public) |
| `POST` | `/logout` | End the browser session |
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

Schedules are saved in the scan database (`ANANSI_DB_PATH`) and survive restarts. Only one scan runs at a time: a scheduled scan that comes due while another scan is running is skipped and logged. Runs missed while the dashboard is stopped are not made up.

---

## Configuration

`config.yaml`:

```yaml
default:
  max_threads: 10
  report_format: "json"      # json or csv
  exclude_ports: []          # ports to skip, e.g. [9100]
  ai_model: "gpt-6-luna"     # model for --ai, as the endpoint names it
```

### AI analysis endpoint

`--ai` sends each service's host, port, product, version and CVEs to a Chat Completions API. By default that is OpenAI, with the key in `OPENAI_API_KEY`. Scan data leaves your machine, so check that the engagement allows it ([ADR-0005](docs/adr/0005-send-ai-analysis-to-a-configurable-openai-compatible-endpoint.md)).

| Setting | Default | Meaning |
|---|---|---|
| `ai_base_url` | not set (OpenAI) | Any OpenAI-compatible API, e.g. `http://localhost:11434/v1` (Ollama) or `https://openrouter.ai/api/v1` |
| `ai_model` | `gpt-6-luna` | Model name as that endpoint expects it, e.g. `qwen3.5` or `openai/gpt-6-luna` |
| `ai_api_key_env` | `OPENAI_API_KEY` without `ai_base_url`; none with it | Environment variable holding the key. With `ai_base_url` set, no key is sent unless you name one here ([ADR-0006](docs/adr/0006-send-an-api-key-to-a-custom-ai-endpoint-only-when-one-is-named.md)) |
| `ai_token_parameter` | `max_completion_tokens` | `max_tokens` for endpoints that reject `max_completion_tokens`, which includes most OpenRouter models |

Keep scan data on your machine with a local model:

```yaml
default:
  ai_base_url: "http://localhost:11434/v1"
  ai_model: "qwen3.5"
```

Use OpenRouter:

```yaml
default:
  ai_base_url: "https://openrouter.ai/api/v1"
  ai_model: "openai/gpt-6-luna"
  ai_api_key_env: "OPENROUTER_API_KEY"
  ai_token_parameter: "max_tokens"
```

- **Run `--ai` with `--cve`.** The model then explains CVEs looked up in the NVD instead of recalling them from memory. Small local models without `--cve` miss well-known vulnerabilities and can invent CVE numbers.
- **OpenRouter** may route requests to providers that keep prompts. Set your data policy in your OpenRouter account before sending client data.
- **A key is never sent over plain HTTP:** a named key with an `http://` URL is a configuration error, and `--ai` stops before the scan starts.
- **Docker:** the container receives only `OPENAI_API_KEY`. For another key variable, add it to `environment:` in `docker-compose.yml`. With Docker Desktop, a server on your machine is `http://host.docker.internal:11434/v1` from inside the container.

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
4. **unittest** — full test suite on Python 3.11 and 3.12

---

## Contributing

Contributions are welcome!

👉 **[Contributing Guidelines](.github/CONTRIBUTING.md)** · **[Code of Conduct](.github/CODE_OF_CONDUCT.md)**

---

## License

[MIT License](LICENSE) — **Herson Cruz** · [@hersoncruz](https://twitter.com/hersoncruz)  
[https://github.com/herson/anansi](https://github.com/herson/anansi)
