from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn
import yaml
import os
import json
from modules.scanner import NetworkScanner
from modules.enumerator import ServiceEnumerator
from modules.exploiter import Exploiter

app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="web/templates/static"), name="static")

# Templates
templates = Jinja2Templates(directory="web/templates")

# Global state for simple storage (in a real app, use a DB)
SCAN_RESULTS = {}
IS_SCANNING = False

def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)

def run_scan_background(target: str, threads: int):
    global SCAN_RESULTS, IS_SCANNING
    IS_SCANNING = True
    try:
        scanner = NetworkScanner(target, threads)
        scan_data = scanner.scan()
        
        enumerator = ServiceEnumerator(scan_data)
        services = enumerator.enumerate()
        
        exploiter = Exploiter(services)
        final_results = exploiter.exploit()
        
        SCAN_RESULTS = final_results
    finally:
        IS_SCANNING = False

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "is_scanning": IS_SCANNING,
        "results": SCAN_RESULTS
    })

@app.post("/scan")
async def start_scan(target: str, background_tasks: BackgroundTasks):
    global IS_SCANNING
    if IS_SCANNING:
        return {"status": "error", "message": "Scan already in progress"}
    
    # Set flag immediately to prevent race conditions and satisfy linter
    IS_SCANNING = True
    
    config = load_config()
    background_tasks.add_task(run_scan_background, target, config['default']['max_threads'])
    return {"status": "success", "message": f"Scan started for {target}"}

@app.get("/api/status")
async def get_status():
    return {
        "is_scanning": IS_SCANNING,
        "results_available": bool(SCAN_RESULTS)
    }

def start_server():
    uvicorn.run(app, host="127.0.0.1", port=8000, log_config=None)

if __name__ == "__main__":
    start_server()
