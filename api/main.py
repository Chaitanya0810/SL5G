"""FastAPI interface for the simulated CyberSentinel defensive platform."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from core.platform import DefensePlatform

platform = DefensePlatform()


class EventRequest(BaseModel):
    model_config = {"extra": "allow"}
    timestamp: str | None = None
    source: str = "simulated"
    user: str = "unknown"
    host: str = "unknown"
    event_type: str
    process: str | None = None
    severity: str = "low"
    raw_log: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    src_ip: str | None = None
    dst_ip: str | None = None
    failed_attempts: int | None = None
    account: str | None = None
    resource: str | None = None
    bytes_out: int | None = None
    bytes_in: int | None = None
    unique_destination_ports: int | None = None
    asset_type: str = "workstation"
    asset_criticality: str | None = None


class HuntRequest(BaseModel):
    hypothesis: str = "Search ingested telemetry for related activity"
    user: str | None = None
    host: str | None = None
    process: str | None = None
    contains: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    resource: str | None = None


class SandboxActionRequest(BaseModel):
    type: str
    target: str
    approved_by: str = Field(min_length=1)


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(
    title="CyberSentinel AI",
    version="0.2.0",
    description=(
        "Evidence-based analysis of simulated security telemetry. Response operations "
        "are in-memory sandbox simulations and require an explicit analyst approval request."
    ),
    lifespan=lifespan,
)


@app.get("/")
async def root() -> HTMLResponse:
    return HTMLResponse((Path(__file__).parent.parent / "frontend" / "index.html").read_text(encoding="utf-8"))


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "storage": "in-memory", "response": "sandbox simulation only"}


@app.post("/api/v1/events")
async def ingest_event(request: EventRequest) -> dict[str, Any]:
    event, incident = platform.ingest(request.model_dump(exclude_none=True))
    return {"event": event, "detections": [d for d in (incident or {}).get("detections", []) if d["event_id"] == event["event_id"]], "incident": incident}


@app.get("/api/v1/events")
async def list_events(
    source: str | None = None,
    severity: str | None = None,
    user: str | None = None,
    host: str | None = None,
    q: str | None = None,
    sort_by: str = Query(default="timestamp", pattern="^(timestamp|severity|source)$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    events = platform.events
    if source:
        events = [e for e in events if e["source"] == source.lower()]
    if severity:
        events = [e for e in events if e["severity"] == severity.lower()]
    if user:
        events = [e for e in events if user.lower() in str(e.get("user", "")).lower()]
    if host:
        events = [e for e in events if host.lower() in str(e.get("host", "")).lower()]
    if q:
        events = [e for e in events if q.lower() in str(e).lower()]
    if sort_by == "severity":
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        events = sorted(events, key=lambda e: rank.get(e.get("severity", "low"), 1), reverse=(order == "desc"))
    else:
        events = sorted(events, key=lambda e: str(e.get(sort_by, "")), reverse=(order == "desc"))
    total = len(events)
    return {"events": events[offset:offset + limit], "total": total, "limit": limit, "offset": offset, "sort_by": sort_by, "order": order}


@app.get("/api/v1/incidents")
async def list_incidents() -> list[dict[str, Any]]:
    return list(platform.incidents.values())


@app.get("/api/v1/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    incident = platform.incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/api/v1/hunts")
async def run_hunt(request: HuntRequest) -> dict[str, Any]:
    return platform.hunt(request.model_dump(exclude_none=True))


@app.post("/api/v1/incidents/{incident_id}/actions/approve")
async def approve_sandbox_action(incident_id: str, request: SandboxActionRequest) -> dict[str, Any]:
    """Explicit analyst approval; the implementation only updates local simulated state."""
    try:
        return platform.approve_action(incident_id, request.model_dump())
    except KeyError:
        raise HTTPException(status_code=404, detail="Incident not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/incidents/{incident_id}/actions/{action_id}/rollback")
async def rollback_sandbox_action(incident_id: str, action_id: str) -> dict[str, Any]:
    try:
        return platform.rollback(incident_id, action_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Action not found or already rolled back") from None


@app.get("/api/v1/audit")
async def get_audit() -> list[dict[str, Any]]:
    return platform.audit


@app.get("/api/v1/metrics")
async def metrics() -> dict[str, Any]:
    return {"events_ingested": len(platform.events), "incidents": len(platform.incidents), "hunts": len(platform.hunts), "audit_records": len(platform.audit), "ml_baseline_samples": len(platform.ml.rows), "ml_model": "IsolationForest"}


@app.get("/api/v1/evaluation")
async def evaluation() -> dict[str, Any]:
    return platform.evaluation_metrics()
