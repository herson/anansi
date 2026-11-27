import asyncio
import json
import logging
import ipaddress
import os
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable
from urllib.parse import parse_qs

from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from domain.changes import ScanOptions
from domain.findings import Finding, findings_from_json, findings_to_json
from modules.scanner import NetworkScanner
from modules.enumerator import ServiceEnumerator
from modules.app_logging import configure_logging
from modules.config import load_config
from modules.database import ScanDatabase, Schedule
from modules.scan_changes import changes_since_previous_scan, status_over_time
from modules.targets import MAX_TARGET_ADDRESSES, validate_target
from web.charts import status_charts
from web.sessions import SessionStore

TEMPLATES_DIR = Path(__file__).parent / "templates"

db: ScanDatabase = None  # type: ignore[assignment]  # opened by _lifespan when the app starts
sessions = SessionStore()
scheduler = BackgroundScheduler(daemon=True)

SCAN_RESULTS: list[Finding] = []
IS_SCANNING: bool = False
_state_lock = threading.Lock()

PROGRESS_EVENTS: list = []
_progress_lock = threading.Lock()

_INVALID_TARGET = (
    "Invalid target: must be an IP address or a CIDR range "
    f"of at most {MAX_TARGET_ADDRESSES:,} addresses"
)

SESSION_COOKIE = "anansi_session"
MIN_API_KEY_LENGTH = 16
_MAX_LOGIN_BODY = 4096
_PUBLIC_PATHS = {"/login"}
_Next = Callable[[Request], Awaitable[Response]]
CONTENT_SECURITY_POLICY = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    global db
    db = ScanDatabase()
    _restore_schedules()
    scheduler.start()
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)
app.mount("/static", StaticFiles(directory=TEMPLATES_DIR / "static"), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)
app.state.api_key = None  # set by start_server(); every request is rejected until then


def _key_matches(supplied: str, expected: str | None) -> bool:
    if not expected:
        return False
    return secrets.compare_digest(supplied.encode(), expected.encode())


def _is_authenticated(request: Request) -> bool:
    """A request is authenticated by an X-API-Key header or a browser session cookie (ADR-0001)."""
    supplied = request.headers.get("X-API-Key")
    if supplied is not None:
        return _key_matches(supplied, request.app.state.api_key)
    return bool(request.app.state.api_key) and sessions.is_valid(request.cookies.get(SESSION_COOKIE))


@app.middleware("http")
async def _require_credentials(request: Request, call_next: _Next) -> Response:
    path = request.url.path
    if path in _PUBLIC_PATHS or path.startswith("/static/") or _is_authenticated(request):
        return await call_next(request)
    if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
        return RedirectResponse("/login", status_code=303)
    return JSONResponse({"detail": "Not authenticated"}, status_code=401)


# Registered after _require_credentials so it wraps it and also covers 401s and redirects.
@app.middleware("http")
async def _content_security_policy(request: Request, call_next: _Next) -> Response:
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    return response


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
async def login(request: Request) -> Response:
    """Exchange the API key for an HttpOnly, SameSite=Strict session cookie."""
    body = await request.body()
    if len(body) > _MAX_LOGIN_BODY:
        raise HTTPException(status_code=413, detail="Request too large")
    supplied = parse_qs(body.decode("utf-8", "replace")).get("api_key", [""])[0]
    if not _key_matches(supplied, request.app.state.api_key):
        return templates.TemplateResponse(
            request, "login.html", {"error": "That key is not valid."}, status_code=401,
        )
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, sessions.create(),
        httponly=True, samesite="strict", path="/",
        secure=request.url.scheme == "https",
    )
    return response


@app.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    sessions.revoke(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/openapi.json", include_in_schema=False)
async def openapi_schema() -> JSONResponse:
    return JSONResponse(app.openapi())


def _emit(message: str, pct: int = 0) -> None:
    """Append a progress event (thread-safe)."""
    with _progress_lock:
        PROGRESS_EVENTS.append({'message': message, 'pct': pct})


def run_scan_background(target: str, threads: int, exclude_ports: list[int], cve: bool = False) -> None:
    """Full scan pipeline — runs in a background thread."""
    global SCAN_RESULTS, IS_SCANNING, PROGRESS_EVENTS

    with _progress_lock:
        PROGRESS_EVENTS = []

    scan_id = db.create_scan(target)
    try:
        _emit("Scanning for open ports...", 10)
        scanner = NetworkScanner(target, threads, exclude_ports=exclude_ports)
        scan_data = scanner.scan()

        _emit("Enumerating services...", 40)
        findings = ServiceEnumerator(scan_data).enumerate()

        cve_lookup_complete = False
        if cve:
            _emit("Looking up CVEs via NVD...", 55)
            from modules.vuln_lookup import VulnLookup
            lookup = VulnLookup(api_key=os.getenv('NVD_API_KEY'))
            findings = lookup.enrich(findings)
            cve_lookup_complete = lookup.failed_lookups == 0

        _emit("Saving results...", 95)
        options = ScanOptions(scanner.arguments, cve, cve_lookup_complete)
        db.complete_scan(scan_id, findings_to_json(findings), options)

        with _state_lock:
            SCAN_RESULTS = findings

    except Exception as e:
        logging.error("Background scan failed: %s", e)
        db.fail_scan(scan_id, e)
    finally:
        with _state_lock:
            IS_SCANNING = False


def _scan_settings() -> tuple[int, list[int]]:
    """Thread count and excluded ports from config.yaml."""
    default = load_config()['default']
    return default['max_threads'], default.get('exclude_ports', [])


def _claim_scan_slot() -> bool:
    """Mark a scan as running; False if one already is. Only one scan runs at a time."""
    global IS_SCANNING
    with _state_lock:
        if IS_SCANNING:
            return False
        IS_SCANNING = True
        return True


def _run_scheduled_scan(target: str, cve: bool = False) -> None:
    """APScheduler entry point — loads config and runs the scan pipeline."""
    threads, exclude_ports = _scan_settings()
    if not _claim_scan_slot():
        logging.warning("Skipped the scheduled scan of %s: another scan is running", target)
        return
    run_scan_background(target, threads, exclude_ports, cve)


# ── HTML dashboard ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request) -> HTMLResponse:
    with _state_lock:
        is_scanning = IS_SCANNING
        results = list(SCAN_RESULTS)
    history = db.list_scans(limit=10)
    latest = next((scan['id'] for scan in history if scan['status'] == 'completed'), None)
    changes = changes_since_previous_scan(db, latest) if latest is not None else None
    series = status_over_time(db, latest) if latest is not None else None
    return templates.TemplateResponse(request, "index.html", {
        "is_scanning": is_scanning,
        "results": results,
        "changes": changes if changes and changes['comparable'] else None,
        "trend": status_charts(series) if series else None,
        "history": history,
    })


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_page(request: Request, scan_id: int) -> HTMLResponse:
    """One stored scan: how it ran, its findings, changes since the scan before it, and the trend up to it."""
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    stored = json.loads(scan['results']) if scan['results'] else None
    failed = scan['status'] == 'failed'
    findings = findings_from_json(stored) if isinstance(stored, list) else None
    series = status_over_time(db, scan_id)
    return templates.TemplateResponse(request, "scan.html", {
        "scan": scan,
        "options": json.loads(scan['options']) if scan['options'] else None,
        "error": stored.get('error') if failed and isinstance(stored, dict) else None,
        "findings": findings,
        "legacy_results": not failed and stored is not None and findings is None,
        "changes": changes_since_previous_scan(db, scan_id),
        "trend": status_charts(series) if series else None,
    })


# ── Scan control ─────────────────────────────────────────────────────────────

@app.post("/scan")
async def start_scan(target: str, background_tasks: BackgroundTasks, cve: bool = False) -> dict[str, Any]:
    """Start a background scan against a valid IP or CIDR range."""
    if not validate_target(target):
        raise HTTPException(status_code=400, detail=_INVALID_TARGET)
    threads, exclude_ports = _scan_settings()
    if not _claim_scan_slot():
        return {"status": "error", "message": "Scan already in progress"}

    background_tasks.add_task(run_scan_background, target, threads, exclude_ports, cve)
    return {"status": "success", "message": f"Scan started for {target}"}


@app.get("/api/status")
async def get_status() -> dict[str, Any]:
    with _state_lock:
        return {"is_scanning": IS_SCANNING, "results_available": bool(SCAN_RESULTS)}


@app.get("/api/progress")
async def stream_progress() -> StreamingResponse:
    """Server-Sent Events stream emitting scan progress messages."""
    async def _stream() -> AsyncIterator[str]:
        sent = 0
        while True:
            with _progress_lock:
                snapshot = list(PROGRESS_EVENTS)
            if len(snapshot) > sent:
                for ev in snapshot[sent:]:
                    yield f"data: {json.dumps(ev)}\n\n"
                sent = len(snapshot)
            with _state_lock:
                scanning = IS_SCANNING
            if not scanning:
                yield f"data: {json.dumps({'message': 'Scan complete', 'pct': 100, 'done': True})}\n\n"
                break
            await asyncio.sleep(0.3)
    return StreamingResponse(_stream(), media_type="text/event-stream")


# ── Scan history ──────────────────────────────────────────────────────────────

@app.get("/api/history")
async def get_history(limit: int = 20) -> dict[str, Any]:
    """Return a list of recent scans (metadata only, no results payload)."""
    return {"scans": db.list_scans(limit=limit)}


@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: int) -> dict[str, Any]:
    """Return full details for a single past scan."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    for column in ('results', 'options'):
        if scan.get(column):
            scan[column] = json.loads(scan[column])
    return scan


@app.get("/api/scan/{scan_id}/changes")
async def get_scan_changes(scan_id: int) -> dict[str, Any]:
    """What changed since the previous scan of the same target that ran the same way (ADR-0013)."""
    changes = changes_since_previous_scan(db, scan_id)
    if changes is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return changes


# ── Scheduled scans ───────────────────────────────────────────────────────────

@app.post("/api/schedule")
async def create_schedule(target: str, cron: str, cve: bool = False) -> dict[str, Any]:
    """Schedule a recurring scan using a standard 5-field cron expression."""
    if not validate_target(target):
        raise HTTPException(status_code=400, detail=_INVALID_TARGET)
    try:
        trigger = CronTrigger.from_crontab(cron)
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid cron expression: {e}")
    schedule = Schedule(f"scan-{target}-{cron}".replace(' ', '_'), target, cron, cve)
    db.save_schedule(schedule)
    _add_job(schedule, trigger)
    return {"status": "scheduled", "job_id": schedule.id, "target": target, "cron": cron}


def _add_job(schedule: Schedule, trigger: CronTrigger) -> None:
    scheduler.add_job(_run_scheduled_scan, trigger=trigger, args=[schedule.target, schedule.cve],
                      id=schedule.id, replace_existing=True)


def _restore_schedules() -> None:
    """Schedule every saved scan, checking each row as if it came from the API.

    A row that fails the checks is skipped and left in the database for a person to inspect.
    """
    for schedule in db.list_schedules():
        if not validate_target(schedule.target):
            logging.warning("Not restoring schedule %r: invalid target %r", schedule.id, schedule.target)
            continue
        try:
            trigger = CronTrigger.from_crontab(schedule.cron)
        except (ValueError, KeyError):
            logging.warning("Not restoring schedule %r: invalid cron %r", schedule.id, schedule.cron)
            continue
        _add_job(schedule, trigger)


@app.get("/api/schedule")
async def list_schedules() -> dict[str, Any]:
    """List all active scheduled scans."""
    return {
        "schedules": [
            {"id": j.id, "next_run": str(getattr(j, 'next_run_time', None))}
            for j in scheduler.get_jobs()
        ]
    }


@app.delete("/api/schedule/{job_id}")
async def delete_schedule(job_id: str) -> dict[str, Any]:
    """Remove a scheduled scan by job ID."""
    scheduled = scheduler.get_job(job_id) is not None
    if scheduled:
        scheduler.remove_job(job_id)
    if not db.delete_schedule(job_id) and not scheduled:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "removed", "job_id": job_id}


_LOOPBACK_NAMES = {"localhost"}


def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _resolve_api_key(host: str) -> str:
    configured = os.getenv("ANANSI_API_KEY")
    if configured:
        if len(configured) < MIN_API_KEY_LENGTH:
            raise SystemExit(f"ANANSI_API_KEY must be at least {MIN_API_KEY_LENGTH} characters long.")
        return configured
    if not _is_loopback(host):
        raise SystemExit(
            f"Refusing to listen on {host} without ANANSI_API_KEY set: "
            "the API would let anyone on the network start scans."
        )
    generated = secrets.token_urlsafe(32)
    print(f"No ANANSI_API_KEY set. Dashboard key for this run: {generated}")
    return generated


def start_server() -> None:
    host = os.getenv("ANANSI_HOST", "127.0.0.1")
    app.state.api_key = _resolve_api_key(host)
    print(f"Starting Anansi Web Dashboard on http://{host}:8000")
    uvicorn.run(app, host=host, port=8000, log_config=None)


if __name__ == "__main__":
    configure_logging()
    start_server()
