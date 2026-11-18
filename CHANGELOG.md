# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (breaking)
- **Python 3.11 or later is required** ([ADR-0011](docs/adr/0011-require-python-3-11-or-later.md)). Python 3.10 is end of life, and the fixed releases of pillow and dnspython no longer support it, so 3.10 installs got versions with known vulnerabilities. The Docker image, on 3.12, is unaffected.
- **Scan results are a list of findings** ([ADR-0003](docs/adr/0003-model-scan-results-as-typed-finding-records.md)). `reports/report.json`, stored scan history and `GET /api/scan/{id}` now return a list of objects with `host`, `port`, `protocol`, `service`, `product`, `version` and `cves`, instead of an object keyed by port. Multi-host scans no longer overwrite each other. The CSV report gains `Host`, `Protocol` and `Product` columns. History saved before this change keeps its old shape.

### Added
- **AI analysis with any OpenAI-compatible endpoint** ([ADR-0005](docs/adr/0005-send-ai-analysis-to-a-configurable-openai-compatible-endpoint.md), [ADR-0006](docs/adr/0006-send-an-api-key-to-a-custom-ai-endpoint-only-when-one-is-named.md)): new `ai_base_url`, `ai_api_key_env` and `ai_token_parameter` settings send `--ai` to OpenRouter or a local model such as Ollama, so scan data can stay on your machine. OpenAI remains the default, and its key is never sent to another endpoint. Invalid AI settings stop `--ai` before the scan starts.
- **Community Health**: Added `CODE_OF_CONDUCT.md`, `SECURITY.md`, and `FUNDING.yml`.
- **Automation**: Added GitHub Action for CI (`.github/workflows/ci.yml`) to run tests and linting on every push.
- **Templates**: Added Issue templates for Bug Reports and Feature Requests, and a Pull Request template.
- **Documentation**: Enhanced `CONTRIBUTING.md` with detailed setup and testing instructions.

### Changed
- **Dependencies are locked with hashes** ([ADR-0010](docs/adr/0010-pin-dependencies-with-a-hashed-universal-lockfile-compiled-by-uv.md)): `requirements.txt` is now generated from `requirements.in` by `scripts/lock-requirements.sh` and pins every package with hashes for every supported Python version. CI tools are locked in `requirements-dev.txt`, and mkdocs moved out of the runtime image to `requirements-docs.txt`. Edit the `.in` files, then re-lock.
- **CI fails on lint findings**: flake8 now blocks the build, with its settings in `.flake8` so local runs match CI. Actions are pinned to commit SHAs, and the workflow token can only read the repository.
- Refactored `CONTRIBUTING.md` to `.github/CONTRIBUTING.md` for better GitHub integration.
- Updated `README.md` with build status badges and sponsorship information.

### Fixed
- **The mkdocs pages describe the real code**: they documented functions and flags that never existed (`scan_network()`, `--enumerate`). Pages that repeated the README are gone, the module pages show the actual classes and `Finding` records, and a test checks that every flag, import and link in `docs/` exists.
- **The dashboard starts from any working directory**: it found its templates relative to the directory it was started from, and importing `web/app.py` opened `anansi.db` there. The database now opens when the app starts, and the scheduler starts and stops with it through a lifespan handler instead of the deprecated `on_event` hooks.
- **PDF reports render any text**: `fpdf` 1.7.2 is replaced by `fpdf2` with an embedded DejaVu Sans font, so CVE descriptions, service banners and compliance controls outside Latin-1 no longer crash `--pdf`.
- **`--pdf --compliance` includes the compliance mapping**: it was added after the file was saved, so it never appeared.
- **`--pdf` works on CIDR targets**: the report for `10.0.0.0/24` is now `report_10.0.0.0_24.pdf` instead of a crash on the `/`.
- **`--s3` no longer reports a bucket as clean when a check fails**: failed checks are listed under `errors` and the command exits with status 1. It now checks all four public access block settings, grants to any AWS account, and whether the bucket policy is public, which needs the `s3:GetBucketPolicyStatus` permission.
- **Scheduled and manual scans no longer run at the same time**: a scheduled scan that fires while another scan runs is skipped with a warning in the log, instead of overwriting the running scan's progress and results and letting a third scan start.
- **Scheduled scans survive restarts** ([ADR-0004](docs/adr/0004-persist-scan-schedules-in-the-scan-database.md)): schedules are saved in the scan database and restored when the dashboard starts. Before, every restart or image update silently dropped them.
- **`--ai` works again with the default config**: OpenAI shut down `gpt-3.5-turbo` on 2026-10-23. The default is now `gpt-6-luna`, and requests cap output with `max_completion_tokens`, which current reasoning models require instead of `max_tokens`. A custom `ai_model` in `config.yaml` must accept that parameter.
- **`--ai` analyses what the scan verified**: the model now receives each service's product name and, with `--cve`, the CVEs found in the NVD. Before, it saw only `http 2.4.49` and had to recall vulnerabilities from memory, so it could miss them or cite wrong ones.
- **An unknown `report_format` is an error**: a value other than `json` or `csv` in `config.yaml` used to skip the report without a word. The CLI now says so and exits before the scan starts.
