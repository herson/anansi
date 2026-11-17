# ADR-0007: Serve the dashboard and API with FastAPI

## Status

Accepted

## Date

2026-11-17

## Context

This records a decision already in the code (roadmap item H1). The web dashboard was added on 2026-02-18 with FastAPI and uvicorn, and its reasons were not written down. The context and options below are reconstructed from what the code relies on.

`main.py --web` starts `web/app.py` with `uvicorn.run(app)`. The app serves:

- two server-rendered pages (`/` and `/login`) from Jinja2 templates, with static CSS and JS ([ADR-0002](0002-serve-dashboard-styles-and-scripts-from-the-app-with-a-strict-csp.md));
- a JSON API to start scans, read history and manage schedules;
- `/api/progress`, a Server-Sent Events (SSE) stream of scan progress.

Scans run for minutes, so `POST /scan` returns at once and the scan runs in a background task. Authentication is middleware in front of every route ([ADR-0001](0001-require-a-session-backed-api-key-for-every-dashboard-and-api-route.md)). Tests drive the app in-process with Starlette's `TestClient`.

The app keeps its state in module globals: the scan slot, the latest results, the progress events and the scheduler. It is designed to run as a single process.

## Decision Drivers

- Long-lived streaming responses (SSE) without tying up a worker thread per client.
- Run a scan in the background after the request returns.
- Test routes in-process, without a running server.
- Python only, with no frontend build step (ADR-0002).
- Few dependencies for a small app.

## Options Considered

### Option 1: Flask

- **Good:** Mature and minimal. Jinja2 templates built in.
- **Bad:** WSGI, so each open SSE stream holds a worker thread. Background work needs a thread or a task queue of our own. Request validation and OpenAPI need extensions.

### Option 2: Django

- **Good:** Batteries included: ORM, sessions, auth, admin.
- **Bad:** Far more framework than two pages and a few JSON routes need. Its ORM and auth would replace `ScanDatabase` and the API-key sessions rather than fit beside them.

### Option 3: FastAPI on uvicorn

- **Good:**
  - ASGI, so SSE is a `StreamingResponse` over an async generator.
  - `BackgroundTasks` runs the scan after the response is sent.
  - Query and body validation from type hints, and an OpenAPI schema for the API.
  - Starlette's `TestClient` makes route tests fast and in-process.
- **Bad:**
  - Pulls in Starlette and Pydantic, and Starlette's major versions have changed APIs, such as `TestClient`'s `httpx` requirement.
  - `@app.on_event` start-up hooks are deprecated in favour of a lifespan handler (roadmap H6).

## Decision

We keep **Option 3**, FastAPI on uvicorn. It is the only option here where SSE, background scans and in-process tests all come from the framework. Its cost is a few transitive dependencies, which a pinned lockfile (roadmap H4) keeps under control.

The app must run as **one uvicorn process with one worker**. Its state lives in module globals, so a second worker would run its own scheduler and its own scan slot. `start_server()` already starts a single process.

## Consequences

### Positive

- Progress streams cost no thread per client.
- Route, authentication and CSP behaviour is tested without a network.

### Negative / Trade-offs

- Starlette upgrades need checking, because they have changed test and middleware APIs before.
- The single-process rule limits the dashboard to one host. That suits a tool that runs one scan at a time.

### Risks

- Someone adds `--workers` or runs several replicas. Schedules would then run once per process. This rule is the reason to keep start-up inside `start_server()` rather than documenting a bare `uvicorn` command.

## Links

- [ADR-0001](0001-require-a-session-backed-api-key-for-every-dashboard-and-api-route.md), [ADR-0002](0002-serve-dashboard-styles-and-scripts-from-the-app-with-a-strict-csp.md), [ADR-0004](0004-persist-scan-schedules-in-the-scan-database.md)
- Roadmap items H1, H4 and H6 (`ROADMAP.md`, Audit Remediation, Phase 5)
