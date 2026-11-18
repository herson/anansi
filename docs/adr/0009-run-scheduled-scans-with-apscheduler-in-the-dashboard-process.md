# ADR-0009: Run scheduled scans with APScheduler in the dashboard process

## Status

Accepted

## Date

2026-11-17

## Context

This records a decision already in the code (roadmap item H1). Scheduled scans were added on 2026-06-13 with APScheduler, and its reasons were not written down. The context and options below are reconstructed from the code.

`POST /api/schedule` accepts a target and a 5-field cron expression. `web/app.py` adds a job to a `BackgroundScheduler`, which runs jobs on its own threads inside the dashboard process. A job calls `_run_scheduled_scan`, which claims the same single scan slot as a manual scan and is skipped if a scan is already running. Schedules are stored in the scan database and re-added at start-up ([ADR-0004](0004-persist-scan-schedules-in-the-scan-database.md)). APScheduler is pinned to `>=3.10,<4`.

## Decision Drivers

- Users schedule scans from the dashboard, with no access to the host's crontab.
- Scheduled and manual scans must share the one scan slot and the progress stream.
- Works the same on macOS, Linux and in the Docker image, which has no cron daemon.
- No extra service to run.

## Options Considered

### Option 1: The host's cron or systemd timers calling `main.py`

- **Good:** No scheduling code in the app. Runs even when the dashboard is down.
- **Bad:** The dashboard can't create or list schedules. A cron run is a separate process, so it can't share the scan slot or the progress stream, and it can start a scan alongside a dashboard scan. The Docker image would need a cron daemon.

### Option 2: A task queue with a beat scheduler (Celery, RQ)

- **Good:** Scales to many workers, with retries and monitoring.
- **Bad:** Needs a broker such as Redis and separate worker processes. That is far more to run than one scan at a time needs.

### Option 3: APScheduler's `BackgroundScheduler` inside the dashboard

- **Good:**
  - Cron syntax through `CronTrigger.from_crontab`, which also validates user input.
  - Jobs run in-process, so they share the scan slot, results and progress stream.
  - No daemon or broker, and identical on every platform.
- **Bad:**
  - Schedules run only while the dashboard runs, and runs missed while it is down are not made up.
  - Version 4 is a rewrite with a different API, hence the `<4` pin.

## Decision

We keep **Option 3**, APScheduler 3's `BackgroundScheduler` in the dashboard process. Only an in-process scheduler can share the single scan slot, which is what keeps scheduled and manual scans from overwriting each other. Persistence is our own table, not APScheduler's job store (ADR-0004), so a move to version 4 or another scheduler doesn't touch stored data.

## Consequences

### Positive

- Schedules are managed from the dashboard and API, and validated with the same parser that runs them.
- Scheduled scans show in the progress stream and history like manual ones.

### Negative / Trade-offs

- Scheduled scans need the dashboard running.
- Staying on version 3 means a move to version 4 or a replacement will eventually be needed. The scheduler is used on about a dozen lines of `web/app.py`, so the move is small.

### Risks

- A second dashboard process, such as a second uvicorn worker or replica, starts its own scheduler, and every schedule runs once per process. The single-process rule in [ADR-0007](0007-serve-the-dashboard-and-api-with-fastapi.md) prevents this.

## Links

- [ADR-0004](0004-persist-scan-schedules-in-the-scan-database.md), [ADR-0007](0007-serve-the-dashboard-and-api-with-fastapi.md)
- Roadmap items C8 and H1 (`ROADMAP.md`, Audit Remediation)
- [APScheduler 3.x user guide](https://apscheduler.readthedocs.io/en/3.x/userguide.html)
