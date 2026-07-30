"""
main.py
=======
Single FastAPI service for the merged app.

It exposes, on ONE origin and ONE Dockerfile:

  Web layer:
    GET  /                     the user-facing analyzer page (trilingual)
    GET  /admin                the database review console

  Fused analysis (live detectors + database intelligence):
    POST /api/analyze          -> fusion.fuse()

  Raw database / retrieval API (used by the admin console and integrators):
    POST /api/retrieve         keyword retrieval over the database
    GET  /api/cases | /api/patterns | /api/knowledge-gaps | /api/reports
    POST /api/reports          submit a community scam report
    PUT  /api/reports/{id}     admin review update
    DELETE /api/reports/{id}   admin delete
    PUT  /api/cases/{id}       admin correction of a reference case

  GET  /api/health             liveness

Run (from the backend/ folder):
    uvicorn main:app --reload --port 8000
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from fusion import fuse
from models import AnalyzeRequest, AnalyzeResponse, ReportIn
from safelanding.data_store import (
    add_user_report,
    delete_user_report,
    init_database,
    load_database,
    update_case,
    update_user_report,
)
from safelanding.retrieval import retrieve

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend" / "index.html"
ADMIN = ROOT / "static" / "admin.html"
REPORT = ROOT / "static" / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Seed the SQLite database from the JSON files if it is empty.
    init_database()
    yield


app = FastAPI(
    title="SafeLanding Rental-Scam Assistant",
    description="Live scam analysis fused with a community threat-intelligence database.",
    version="1.0.0",
    lifespan=lifespan,
)

# Dev-only permissive CORS; tighten allow_origins for a real deployment.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# Fonts + images used by the frontend (and admin console).
app.mount("/assets", StaticFiles(directory=ROOT / "frontend" / "assets"), name="assets")


# ---------------------------------------------------------------------------
# Web pages
# ---------------------------------------------------------------------------
@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND)


@app.get("/admin")
def admin() -> FileResponse:
    return FileResponse(ADMIN)


@app.get("/report")
def report() -> FileResponse:
    return FileResponse(REPORT)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "safelanding-fullstack"}


# ---------------------------------------------------------------------------
# Fused analysis
# ---------------------------------------------------------------------------
@app.post("/api/analyze", response_model=AnalyzeResponse)
def do_analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    """Live detection (text / url / image) fused with database intelligence."""
    return fuse(req)


# ---------------------------------------------------------------------------
# Raw retrieval (kept for integrators / chatbot use)
# ---------------------------------------------------------------------------
@app.post("/api/retrieve")
def do_retrieve(payload: dict) -> dict:
    message = str(payload.get("message", "")).strip()
    if not message:
        raise HTTPException(status_code=400, detail="message is required")
    return retrieve(message, payload.get("top_n", 3))


# ---------------------------------------------------------------------------
# Database read endpoints (admin console)
# ---------------------------------------------------------------------------
@app.get("/api/cases")
def get_cases() -> list:
    return load_database()["cases"]


@app.get("/api/patterns")
def get_patterns() -> list:
    return load_database()["patterns"]


@app.get("/api/knowledge-gaps")
def get_knowledge_gaps() -> list:
    return load_database()["knowledge_gaps"]


@app.get("/api/reports")
def get_reports() -> list:
    return load_database()["user_reports"]


# ---------------------------------------------------------------------------
# Database write endpoints
# ---------------------------------------------------------------------------
@app.post("/api/reports", status_code=201)
def create_report(report: ReportIn) -> dict:
    return add_user_report(report.as_dict())


@app.put("/api/reports/{report_id}")
def edit_report(report_id: str, payload: dict) -> dict:
    updated = update_user_report(report_id, payload)
    if updated is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return updated


@app.delete("/api/reports/{report_id}")
def remove_report(report_id: str) -> dict:
    if not delete_user_report(report_id):
        raise HTTPException(status_code=404, detail="Report not found")
    return {"deleted": True, "Report_ID": report_id}


@app.put("/api/cases/{case_id}")
def edit_case(case_id: str, payload: dict) -> dict:
    updated = update_case(case_id, payload)
    if updated is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return updated
