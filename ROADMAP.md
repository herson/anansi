# 🕷️ Anansi Strategic Roadmap 2026

To keep Anansi relevant and attract sponsors, we need to move beyond basic network scanning into modern, high-value security domains.

## 🔧 Audit Remediation (2026-11-17)

A full audit found that the Docker deployment doesn't start, the web API is open by default, and several modules return wrong results. These items come before any new features. Every bug fix ships with a failing test first.

### Phase 1 — Make Docker work safely
- [x] **D1** Declare `python-nmap` in `requirements.txt` (the image crashes on `import nmap`); add a contract test that every third-party import is declared, and stop CI installing it separately
- [x] **D2** Make the dashboard reachable from outside the container (uvicorn is hard-bound to `127.0.0.1`), without exposing an unauthenticated API
- [x] **D3** Add a `.dockerignore` so `.env`, `.venv`, `.git`, `logs/` and the database are not copied into the image
- [x] **D4** Fix the `./anansi.db` bind mount (Docker creates a directory when the file is missing)
- [x] **D5** CI: build the Docker image and smoke-test it: imports load, the dashboard answers through the port mapping, and no planted secret ends up in the image

### Phase 2 — Web API security
- [x] **S1** Require `ANANSI_API_KEY` when the server is reachable beyond localhost; cover `/`, `/api/progress` and history too
- [x] **S2** The dashboard sends `X-API-Key` (today it gets a 403 once a key is set)
- [x] **S3** Stop cross-site requests from starting scans (`/scan` is a plain POST with query parameters)
- [x] **S4** Cap the target size (`0.0.0.0/0` is currently accepted); share one `_validate_target` between the CLI and the web app
- [x] **S5** Self-host Tailwind or pin it with Subresource Integrity (SRI); stop loading the Play CDN script
- [x] **S6** Run the container as a non-root user (decided: nmap uses connect scans `-sT` in Docker rather than `setcap`)
- [x] **S7** Treat service banners as untrusted data in the OpenAI prompt, with a test that injects one

### Phase 3 — Exploitation module
- [x] **E1** Off by default; require an explicit `--exploit` opt-in (CLI only; the web dashboard never runs exploitation)
- [x] **E2** Remove the broken `multi/handler` + `set payload <service>` call (it started a listener, not an exploit); real checks need an ADR first
- [x] **E3** Fix the README's "Safe Metasploit integration" claim

### Phase 4 — Correctness
- [x] **C1** `ServiceEnumerator` keys results by port only, so multi-host scans overwrite each other (ADR-0003: typed `Finding` records, checked by mypy)
- [x] **C2** Keep nmap's `product` field so CVE lookups search for `Apache httpd 2.4.49`, not `http 2.4.49`; the scanner also needed `-sV` (without it nmap reported no product or version at all), and versionless services are no longer looked up
- [x] **C3** The PDF compliance section is added after the file is written, so it never appears
- [x] **C4** `--pdf` crashes on CIDR targets (`report_10.0.0.0/24.pdf`)
- [x] **C5** Replace `fpdf==1.7.2` (unmaintained, Latin-1 only) with `fpdf2`
- [x] **C6** The default `exclude_ports: [22, 80]` hides the most common ports; remove the unused `scan_type` / `logging_level` settings or wire them up
- [x] **C7** S3 scan: report failed checks as errors, not as a clean bucket; check all four public-access-block flags and the bucket policy status
- [x] **C8** Scheduled scans conflict with manual scans (they share `IS_SCANNING`, results and progress); schedules are lost on restart
- [x] **C9** Fix the NVD rate limits in the README (50 vs 5 requests per 30 seconds)
- [x] **C10** Update the default AI model from `gpt-3.5-turbo`
- [x] **C11** Excluding port 80 breaks unprivileged host discovery: nmap probes port 80 to decide a host is up, so with the default `exclude_ports: [22, 80]` every non-root scan (all Docker scans since S6) reports the host down and finds nothing

### Phase 5 — Code health and architecture
- [ ] **H1** Write ADRs (`docs/adr/`) for the existing decisions: Metasploit, OpenAI, SQLite, APScheduler, FastAPI, the dashboard UI approach
- [ ] **H2** Move config loading and I/O behind ports; stop `Exploiter`/`Reporter` re-reading `config.yaml` from the working directory; remove the import-time logging and `logs/` side effects in `modules/__init__.py`
- [ ] **H3** Delete the dead `modules/utils.py` (fake retry built on `random.choice`) and its test
- [ ] **H4** Pin dependencies with a lockfile; move mkdocs into a separate docs requirements file
- [ ] **H5** CI: make flake8 blocking, pin actions to commit SHAs, add a `permissions:` block
- [ ] **H6** Remove the stale `reports/report.csv` from git; replace the deprecated `@app.on_event` hooks with a lifespan handler
- [ ] **H7** Bring the mkdocs site (`docs/`) in line with the code: it documents functions and flags that don't exist (e.g. `--enumerate`, `scan_network()`)

### Phase 6 — AI analysis
- [ ] **A1** Analyse the `Finding` records instead of raw nmap output: today the prompt drops the product (the model sees `http 2.4.49`, not `Apache httpd 2.4.49`) and never includes the CVEs that `--cve` found, so the model has to recall vulnerabilities from memory
- [ ] **A2** Send AI analysis to a configurable OpenAI-compatible endpoint (OpenAI, OpenRouter, Ollama), once ADR-0005 is accepted

## 🚀 Top Strategic Proposals

### 1. AI-Powered Analysis (High Sponsorship Potential)
**Concept**: Integrate an LLM (OpenAI/Anthropic/Ollama) to analyze raw scan data.
**Value**: Instead of just listing "Port 22 Open", Anansi explains *why* it matters in the specific context and suggests tailored hardening steps.
- **Feature**: `modules/analysis.py` - Smart summarization of risks.
- **Sponsor Hook**: "Sponsor to unlock advanced GPT-4 analysis tokens" (or similar model).

### 2. Web Dashboard (High "Cool Factor")
**Concept**: A modern, dark-mode React/Next.js dashboard to visualize findings.
**Value**: CLI tools are great for pros, but dashboards sell tools. Visualizing network topology and risk heatmaps looks impressive on GitHub Readme.
- **Feature**: `web/` - Simple FastAPI backend + React frontend.

### 3. Cloud & Container Security (High Relevance)
**Concept**: Modules for AWS S3 bucket scanning and Docker secure configuration checks.
**Value**: Modern infrastructure is cloud-native. A legacy network scanner is less relevant than a cloud security tool.
- **Feature**: `modules/cloud.py` - AWS/Azure checks.

### 4. Automated PDF Reporting
**Concept**: Generate professional "Consultant-Ready" PDF reports.
**Value**: Professionals (who sponsor tools) need to deliver reports to clients.
- **Feature**: `modules/reporting.py` - Upgrade from JSON/CSV to PDF with graphs.

### 5. Persistent Storage & History (The "Memory")
**Concept**: Store scan results in a local SQLite database to track changes over time.
**Value**: Allows users to see "New Ports Opened" since last week. Essential for continuous monitoring.
- **Feature**: `modules/storage.py` - Database models and history API.

### 6. Vulnerability Intelligence (The "Venom") 
**Concept**: Match discovered service versions against a local or API-based CVE database.
**Value**: Moves from "Port 80 is open" to "Apache 2.4.49 is vulnerable to Path Traversal (CVE-2021-41773)".
- **Feature**: `modules/vuln_scanner.py` - CVE lookup integration.

### 7. Subdomain & Directory Recon (The "Web Weaver")
**Concept**: Enumerate subdomains and hidden web directories (gobuster style).
**Value**: Expands the attack surface discovery beyond just IP scanning.
- **Feature**: `modules/recon_web.py` - Wordlist-based enumeration.

## Recommended Next Step
Work through the **Audit Remediation** phases in order. Proposals #1–#6 have shipped in basic form, #7 covers subdomains but not directories yet, and building further on them waits until the remediation is done.
