# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (breaking)
- **Scan results are a list of findings** ([ADR-0003](docs/adr/0003-model-scan-results-as-typed-finding-records.md)). `reports/report.json`, stored scan history and `GET /api/scan/{id}` now return a list of objects with `host`, `port`, `protocol`, `service`, `product`, `version` and `cves`, instead of an object keyed by port. Multi-host scans no longer overwrite each other. The CSV report gains `Host`, `Protocol` and `Product` columns. History saved before this change keeps its old shape.

### Added
- **Community Health**: Added `CODE_OF_CONDUCT.md`, `SECURITY.md`, and `FUNDING.yml`.
- **Automation**: Added GitHub Action for CI (`.github/workflows/ci.yml`) to run tests and linting on every push.
- **Templates**: Added Issue templates for Bug Reports and Feature Requests, and a Pull Request template.
- **Documentation**: Enhanced `CONTRIBUTING.md` with detailed setup and testing instructions.

### Changed
- Refactored `CONTRIBUTING.md` to `.github/CONTRIBUTING.md` for better GitHub integration.
- Updated `README.md` with build status badges and sponsorship information.

### Fixed
- **PDF reports render any text**: `fpdf` 1.7.2 is replaced by `fpdf2` with an embedded DejaVu Sans font, so CVE descriptions, service banners and compliance controls outside Latin-1 no longer crash `--pdf`.
- **`--pdf --compliance` includes the compliance mapping**: it was added after the file was saved, so it never appeared.
- **`--pdf` works on CIDR targets**: the report for `10.0.0.0/24` is now `report_10.0.0.0_24.pdf` instead of a crash on the `/`.
- **`--s3` no longer reports a bucket as clean when a check fails**: failed checks are listed under `errors` and the command exits with status 1. It now checks all four public access block settings, grants to any AWS account, and whether the bucket policy is public, which needs the `s3:GetBucketPolicyStatus` permission.
- **Scheduled and manual scans no longer run at the same time**: a scheduled scan that fires while another scan runs is skipped with a warning in the log, instead of overwriting the running scan's progress and results and letting a third scan start.
- **Scheduled scans survive restarts** ([ADR-0004](docs/adr/0004-persist-scan-schedules-in-the-scan-database.md)): schedules are saved in the scan database and restored when the dashboard starts. Before, every restart or image update silently dropped them.
- **`--ai` works again with the default config**: OpenAI shut down `gpt-3.5-turbo` on 2026-10-23. The default is now `gpt-6-luna`, and requests cap output with `max_completion_tokens`, which current reasoning models require instead of `max_tokens`. A custom `ai_model` in `config.yaml` must accept that parameter.
