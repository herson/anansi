# ADR-0008: Store scan history in SQLite

## Status

Accepted

## Date

2026-11-17

## Context

This records a decision already in the code (roadmap item H1). Scan history was added on 2026-06-13 with Python's built-in `sqlite3`, and its reasons were not written down. The context and options below are reconstructed from the code.

`ScanDatabase` (`modules/database.py`) stores two tables:

- `scans`: one row per scan, with its target, start and end times, status, and results as JSON text (the `Finding` records of [ADR-0003](0003-model-scan-results-as-typed-finding-records.md));
- `schedules`: saved cron schedules ([ADR-0004](0004-persist-scan-schedules-in-the-scan-database.md)).

The dashboard is a single process ([ADR-0007](0007-serve-the-dashboard-and-api-with-fastapi.md)) that runs one scan at a time. The scan's background thread writes while request handlers read. `ScanDatabase` keeps one connection, opened with `check_same_thread=False`, and serialises every call with a lock. The file path comes from `ANANSI_DB_PATH`. In Docker it is on the `anansi-data` volume. Tests use `ScanDatabase(':memory:')`.

## Decision Drivers

- Works the moment Anansi is installed, with no server to run.
- Survives restarts and image updates.
- Data volume is small: one row per scan.
- Tests need no external service.

## Options Considered

### Option 1: JSON files in a directory

- **Good:** No database at all, and easy to read by hand.
- **Bad:** Listing history means reading every file. Concurrent writes need our own locking and atomic renames. There's no query language for later features such as comparing scans.

### Option 2: PostgreSQL

- **Good:** Many concurrent writers, and it suits multi-instance deployments.
- **Bad:** Another service for every user to run and secure, and a driver dependency. Tests need a running server. None of its strengths apply to a single process that runs one scan at a time.

### Option 3: SQLite through the standard library

- **Good:**
  - Part of Python, so no dependency and no server.
  - One file, easy to back up and to put on a Docker volume.
  - Transactions, and SQL for later queries.
  - In-memory databases for tests.
- **Bad:**
  - One writer at a time, and a shared file is unsafe across hosts.
  - We write the schema and queries by hand, with no migration tool.

## Decision

We keep **Option 3**, SQLite through `sqlite3`, with the single locked connection in `ScanDatabase`. It fits a single-process tool, and every alternative adds a dependency or a service without solving a problem the app has.

Results stay as JSON text in one column. They are written once and read back whole, so normalised tables would add schema without adding a query anyone needs.

## Consequences

### Positive

- No setup: the file is created on first use.
- The database moves with the `anansi-data` volume, which the Docker smoke test checks.

### Negative / Trade-offs

- Schema changes are hand-written. `CREATE TABLE IF NOT EXISTS` doesn't alter an existing table, so the first change to an existing column needs a migration step.
- Results stored before ADR-0003 keep their old JSON shape.

### Risks

- A database file on a network share, or shared by several instances, can corrupt or run every schedule twice. The single-instance rule in ADR-0007 covers this.
- The file holds scan results, which map a network's weak points. It must stay on a private volume and be treated as sensitive data.

## Links

- [ADR-0003](0003-model-scan-results-as-typed-finding-records.md), [ADR-0004](0004-persist-scan-schedules-in-the-scan-database.md), [ADR-0007](0007-serve-the-dashboard-and-api-with-fastapi.md)
- Roadmap item H1 (`ROADMAP.md`, Audit Remediation, Phase 5)
