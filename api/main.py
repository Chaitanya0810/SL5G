"""FastAPI interface for the simulated CyberSentinel defensive platform."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from core.platform import DefensePlatform

platform = DefensePlatform()


class EventRequest(BaseModel):
    timestamp: str | None = None
    source: str = "simulated"
    user: str = "unknown"
    host: str = "unknown"
    event_type: str
    process: str | None = None
    severity: str = "low"
    raw_log: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class HuntRequest(BaseModel):
    hypothesis: str = "Search ingested telemetry for related activity"
    user: str | None = None
    host: str | None = None
    process: str | None = None
    contains: str | None = None


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
async def root() -> dict[str, str]:
    return {"service": "CyberSentinel AI", "status": "ready", "mode": "simulated defensive MVP"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "storage": "in-memory", "response": "sandbox simulation only"}


@app.post("/api/v1/events")
async def ingest_event(request: EventRequest) -> dict[str, Any]:
    event, incident = platform.ingest(request.model_dump(exclude_none=True))
    return {"event": event, "detections": [d for d in (incident or {}).get("detections", []) if d["event_id"] == event["event_id"]], "incident": incident}


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
    return {"events_ingested": len(platform.events), "incidents": len(platform.incidents), "hunts": len(platform.hunts), "audit_records": len(platform.audit), "note": "Evaluation metrics require labeled scenarios; no precision/recall claim is inferred from live demo data."}
