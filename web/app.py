import logging
import ipaddress
import os
import secrets
import threading

from fastapi import FastAPI, Request, BackgroundTasks, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security.api_key import APIKeyHeader
import uvicorn
import yaml

from modules.scanner import NetworkScanner
from modules.enumerator import ServiceEnumerator
from modules.exploiter import Exploiter

app = FastAPI()

app.mount("/static", StaticFiles(directory="web/templates/static"), name="static")
templates = Jinja2Templates(directory="web/templates")

SCAN_RESULTS = {}
IS_SCANNING = False
_state_lock = threading.Lock()

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


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


def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)


def run_scan_background(target: str, threads: int, exclude_ports: list, cve: bool = False):
    """Run a full scan pipeline in a background thread."""
    global SCAN_RESULTS, IS_SCANNING
    try:
        scanner = NetworkScanner(target, threads, exclude_ports=exclude_ports)
        scan_data = scanner.scan()

        enumerator = ServiceEnumerator(scan_data)
        services = enumerator.enumerate()

        if cve:
            from modules.vuln_lookup import VulnLookup
            lookup = VulnLookup(api_key=os.getenv('NVD_API_KEY'))
            services = lookup.enrich(services)

        exploiter = Exploiter(services)
        final_results = exploiter.exploit()

        with _state_lock:
            SCAN_RESULTS = final_results
    except Exception as e:
        logging.error("Background scan failed: %s", e)
    finally:
        with _state_lock:
            IS_SCANNING = False


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    with _state_lock:
        is_scanning = IS_SCANNING
        results = dict(SCAN_RESULTS)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "is_scanning": is_scanning,
        "results": results,
    })


@app.post("/scan", dependencies=[Depends(_require_api_key)])
async def start_scan(target: str, background_tasks: BackgroundTasks, cve: bool = False):
    """Start a background scan. Requires a valid IP address or CIDR range."""
    if not _validate_target(target):
        raise HTTPException(
            status_code=400,
            detail="Invalid target: must be a valid IP address or CIDR range",
        )

    with _state_lock:
        global IS_SCANNING
        if IS_SCANNING:
            return {"status": "error", "message": "Scan already in progress"}
        IS_SCANNING = True

    config = load_config()
    exclude_ports = config['default'].get('exclude_ports', [])
    background_tasks.add_task(
        run_scan_background, target, config['default']['max_threads'], exclude_ports, cve
    )
    return {"status": "success", "message": f"Scan started for {target}"}


@app.get("/api/status", dependencies=[Depends(_require_api_key)])
async def get_status():
    with _state_lock:
        return {
            "is_scanning": IS_SCANNING,
            "results_available": bool(SCAN_RESULTS),
        }


def start_server():
    uvicorn.run(app, host="127.0.0.1", port=8000, log_config=None)


if __name__ == "__main__":
    start_server()
