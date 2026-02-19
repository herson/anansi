# 🕷️ Anansi Strategic Roadmap 2026

To keep Anansi relevant and attract sponsors, we need to move beyond basic network scanning into modern, high-value security domains.

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
Start with **#5 (Persistent Storage)** as it builds the foundation for tracking history and feeding better data into the dashboard.
