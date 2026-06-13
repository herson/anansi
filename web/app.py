import asyncio
import json
import logging
import ipaddress
import os
import secrets
import threading

from fastapi import FastAPI, Request, BackgroundTasks, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security.api_key import APIKeyHeader
import uvicorn
import yaml

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from modules.scanner import NetworkScanner
from modules.enumerator import ServiceEnumerator
from modules.exploiter import Exploiter
from modules.database import ScanDatabase

app = FastAPI()
app.mount("/static", StaticFiles(directory="web/templates/static"), name="static")
templates = Jinja2Templates(directory="web/templates")

db = ScanDatabase()
scheduler = BackgroundScheduler(daemon=True)

SCAN_RESULTS: dict = {}
IS_SCANNING: bool = False
_state_lock = threading.Lock()

PROGRESS_EVENTS: list = []
_progress_lock = threading.Lock()

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


@app.on_event("startup")
async def _startup():
    if not scheduler.running:
        scheduler.start()


@app.on_event("shutdown")
async def _shutdown():
    if scheduler.running:
        scheduler.shutdown(wait=False)


def _require_api_key(api_key: str = Depends(_API_KEY_HEADER)):
    """Verify X-API-Key header when ANANSI_API_KEY env var is set."""
    expected = os.getenv("ANANSI_API_KEY")
    if expected and not secrets.compare_digest(api_key or "", expected):
        raise HTTPException(status_code=403, detail="Invalid API key")


def _validate_target(target: str) -> bool:
    """Return True if target is a valid IP address or CIDR range."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    return False


def load_config() -> dict:
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)


def _emit(message: str, pct: int = 0):
    """Append a progress event (thread-safe)."""
    with _progress_lock:
        PROGRESS_EVENTS.append({'message': message, 'pct': pct})


def run_scan_background(target: str, threads: int, exclude_ports: list, cve: bool = False):
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
        services = ServiceEnumerator(scan_data).enumerate()

        if cve:
            _emit("Looking up CVEs via NVD...", 55)
            from modules.vuln_lookup import VulnLookup
            services = VulnLookup(api_key=os.getenv('NVD_API_KEY')).enrich(services)

        _emit("Running exploitation checks...", 75)
        final_results = Exploiter(services).exploit()

        _emit("Saving results...", 95)
        db.complete_scan(scan_id, final_results)

        with _state_lock:
            SCAN_RESULTS = final_results

    except Exception as e:
        logging.error("Background scan failed: %s", e)
        db.fail_scan(scan_id, e)
    finally:
        with _state_lock:
            IS_SCANNING = False


def _run_scheduled_scan(target: str, cve: bool = False):
    """APScheduler entry point — loads config and runs the scan pipeline."""
    config = load_config()
    run_scan_background(
        target,
        config['default']['max_threads'],
        config['default'].get('exclude_ports', []),
        cve,
    )


# ── HTML dashboard ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    with _state_lock:
        is_scanning = IS_SCANNING
        results = dict(SCAN_RESULTS)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "is_scanning": is_scanning,
        "results": results,
        "history": db.list_scans(limit=10),
    })


# ── Scan control ─────────────────────────────────────────────────────────────

@app.post("/scan", dependencies=[Depends(_require_api_key)])
async def start_scan(target: str, background_tasks: BackgroundTasks, cve: bool = False):
    """Start a background scan against a valid IP or CIDR range."""
    if not _validate_target(target):
        raise HTTPException(status_code=400,
                            detail="Invalid target: must be a valid IP or CIDR range")
    with _state_lock:
        global IS_SCANNING
        if IS_SCANNING:
            return {"status": "error", "message": "Scan already in progress"}
        IS_SCANNING = True

    config = load_config()
    background_tasks.add_task(
        run_scan_background, target,
        config['default']['max_threads'],
        config['default'].get('exclude_ports', []),
        cve,
    )
    return {"status": "success", "message": f"Scan started for {target}"}


@app.get("/api/status", dependencies=[Depends(_require_api_key)])
async def get_status():
    with _state_lock:
        return {"is_scanning": IS_SCANNING, "results_available": bool(SCAN_RESULTS)}


@app.get("/api/progress")
async def stream_progress():
    """Server-Sent Events stream emitting scan progress messages."""
    async def _stream():
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

@app.get("/api/history", dependencies=[Depends(_require_api_key)])
async def get_history(limit: int = 20):
    """Return a list of recent scans (metadata only, no results payload)."""
    return {"scans": db.list_scans(limit=limit)}


@app.get("/api/scan/{scan_id}", dependencies=[Depends(_require_api_key)])
async def get_scan_result(scan_id: int):
    """Return full details for a single past scan."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get('results'):
        scan['results'] = json.loads(scan['results'])
    return scan


# ── Scheduled scans ───────────────────────────────────────────────────────────

@app.post("/api/schedule", dependencies=[Depends(_require_api_key)])
async def create_schedule(target: str, cron: str, cve: bool = False):
    """Schedule a recurring scan using a standard 5-field cron expression."""
    if not _validate_target(target):
        raise HTTPException(status_code=400, detail="Invalid target")
    try:
        trigger = CronTrigger.from_crontab(cron)
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid cron expression: {e}")
    job_id = f"scan-{target}-{cron}".replace(' ', '_')
    scheduler.add_job(_run_scheduled_scan, trigger=trigger, args=[target, cve],
                      id=job_id, replace_existing=True)
    return {"status": "scheduled", "job_id": job_id, "target": target, "cron": cron}


@app.get("/api/schedule", dependencies=[Depends(_require_api_key)])
async def list_schedules():
    """List all active scheduled scans."""
    return {
        "schedules": [
            {"id": j.id, "next_run": str(getattr(j, 'next_run_time', None))}
            for j in scheduler.get_jobs()
        ]
    }


@app.delete("/api/schedule/{job_id}", dependencies=[Depends(_require_api_key)])
async def delete_schedule(job_id: str):
    """Remove a scheduled scan by job ID."""
    if not scheduler.get_job(job_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    scheduler.remove_job(job_id)
    return {"status": "removed", "job_id": job_id}


def start_server():
    uvicorn.run(app, host="127.0.0.1", port=8000, log_config=None)


if __name__ == "__main__":
    start_server()
