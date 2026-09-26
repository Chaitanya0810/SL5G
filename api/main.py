"""FastAPI interface for the simulated CyberSentinel defensive platform."""
from __future__ import annotations

from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from core.platform import DefensePlatform, normalize_event
from core.telemetry import parse_telemetry

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


class RawTelemetryRequest(BaseModel):
    raw_data: str = Field(min_length=1, max_length=2_000_000)


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


@app.get("/api/v1/samples/lanl-auth", response_class=PlainTextResponse)
async def lanl_auth_sample() -> PlainTextResponse:
    sample = Path(__file__).parent.parent / "samples" / "lanl-auth-sample.jsonl"
    return PlainTextResponse(sample.read_text(encoding="utf-8"), media_type="application/x-ndjson")


@app.post("/api/v1/events")
async def ingest_event(request: EventRequest) -> dict[str, Any]:
    event, incident = platform.ingest(request.model_dump(exclude_none=True))
    return {"event": event, "detections": [d for d in (incident or {}).get("detections", []) if d["event_id"] == event["event_id"]], "incident": incident}


@app.post("/api/v1/telemetry/ingest")
async def ingest_raw_telemetry(request: RawTelemetryRequest) -> dict[str, Any]:
    """Infer event boundaries and source fields from pasted JSON, NDJSON, or log text."""
    try:
        records = parse_telemetry(request.raw_data)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if len(records) > 500:
        raise HTTPException(status_code=413, detail="A batch can contain at most 500 telemetry records")
    results = []
    for record in records:
        event, incident = platform.ingest(record)
        detections = [d for d in (incident or {}).get("detections", []) if d["event_id"] == event["event_id"]]
        results.append({"event_id": event["event_id"], "source": event["source"], "source_detection": event.get("source_detection"), "event_type": event["event_type"], "detections": detections, "incident_id": (incident or {}).get("incident_id")})
    return {"accepted": len(results), "results": results, "incidents": list({r["incident_id"] for r in results if r["incident_id"]}), "pipeline": ["parse", "source classification", "normalization", "rule and anomaly detection", "correlation", "investigation", "risk and graph"]}


@app.post("/api/v1/telemetry/analyze")
async def analyze_raw_telemetry(request: RawTelemetryRequest) -> StreamingResponse:
    """Stream actual pipeline results one completed analysis stage at a time."""
    try:
        records = parse_telemetry(request.raw_data)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not records:
        raise HTTPException(status_code=422, detail="No telemetry records were found")
    if len(records) > 500:
        raise HTTPException(status_code=413, detail="A batch can contain at most 500 telemetry records")

    def message(stage: str, title: str, details: dict[str, Any]) -> bytes:
        return (json.dumps({"stage": stage, "title": title, "details": details}, ensure_ascii=True, default=str) + "\n").encode()

    async def run_stages():
        sources: dict[str, int] = {}
        for record in records:
            sources[record["source"]] = sources.get(record["source"], 0) + 1
        yield message("parse", "Parse raw input and identify sources", {"records_found": len(records), "source_counts": sources, "format": "JSON / NDJSON / key-value logs", "sample": [{"source": r["source"], "source_detection": r.get("source_detection"), "event_type": r["event_type"]} for r in records[:8]]})

        normalized = [normalize_event(record) for record in records]
        baseline_before_batch = len(platform.ml.rows)
        normalized_rows = [{
            "number": index + 1,
            "event_time_seconds": event.get("event_time_seconds"),
            "source": event["source"],
            "user": event["user"],
            "host": event["host"],
            "destination_user": event.get("destination_user", ""),
            "destination_host": event.get("destination_host", ""),
            "event_type": event["event_type"],
            "auth_type": event.get("auth_type", ""),
            "logon_type": event.get("logon_type", ""),
            "auth_orientation": event.get("auth_orientation", ""),
            "auth_result": event.get("auth_result", ""),
        } for index, event in enumerate(normalized)]
        yield message("normalize", "Normalize records into a common event schema", {
            "normalized": len(normalized),
            "fields": ["timestamp", "source", "user", "host", "destination_user", "destination_host", "event_type", "auth_result", "event_time_seconds"],
            "records": normalized_rows,
            "processing": {
                "rules": {"method": "Explainable per-event behavior rules", "status": "run during detection stage"},
                "ml": {"model": "IsolationForest", "minimum_baseline": platform.ml.min_samples, "baseline_observations": baseline_before_batch, "ready_before_batch": baseline_before_batch >= platform.ml.min_samples},
                "llm": {"configured": bool(os.getenv("OPENAI_API_KEY")), "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"), "used_for": "investigation summaries for incidents with detections"},
            },
        })

        detections = [platform.detect_normalized(event) for event in normalized]
        ml_scored_events = sum(event.get("anomaly") is not None for event in normalized)
        ml_anomalies = sum(any(hit.get("rule") == "ml_anomaly" for hit in hits) for hits in detections)
        rule_matches = sum(hit.get("rule") != "ml_anomaly" for hits in detections for hit in hits)
        yield message("detect", "Run detection rules and anomaly scoring", {"events_checked": len(normalized), "matches": [{"event_id": event["event_id"], "source": event["source"], "matches": [{"title": d["title"], "rule": d["rule"], "evidence": d["evidence"], "techniques": d["techniques"]} for d in hits]} for event, hits in zip(normalized, detections)], "rules": {"events_checked": len(normalized), "rule_matches": rule_matches}, "ml": {"model": "IsolationForest", "minimum_baseline": platform.ml.min_samples, "baseline_before_batch": baseline_before_batch, "baseline_after_batch": len(platform.ml.rows), "events_scored": ml_scored_events, "anomaly_findings": ml_anomalies}, "ml_baseline_samples": len(platform.ml.rows), "note": "The Isolation Forest starts scoring once the local baseline has at least 24 observations; it learns from this stream for future events."})

        correlations = []
        incidents: dict[str, dict[str, Any]] = {}
        for event, hits in zip(normalized, detections):
            incident = platform.correlate_detected(event, hits)
            if incident:
                incidents[incident["incident_id"]] = incident
            correlations.append({"event_id": event["event_id"], "detection_count": len(hits), "incident_id": incident["incident_id"] if incident else None})
        yield message("correlate", "Correlate events and assemble incident timelines", {"events_stored": len(normalized), "event_links": correlations, "incidents_updated": len(incidents), "incidents": [{"incident_id": i["incident_id"], "event_count": len(i["events"]), "detection_count": len(i["detections"])} for i in incidents.values()]})

        for incident in incidents.values():
            platform.investigate_incident(incident)
        investigation_engines = [i["investigation"].get("engine", "unknown") for i in incidents.values()]
        llm_configured = bool(os.getenv("OPENAI_API_KEY"))
        yield message("investigate", "Build evidence-cited investigation hypotheses", {"investigations": [{"incident_id": i["incident_id"], "status": i["investigation"]["status"], "hypothesis": i["hypothesis"], "reasoning": i["investigation"].get("reasoning"), "event_ids": i["investigation"].get("event_ids", []), "engine": i["investigation"].get("engine"), "llm_failure": i["investigation"].get("llm_failure")} for i in incidents.values()], "llm": {"configured": llm_configured, "incident_summaries": len(incidents), "configured_llm_results": sum(engine.startswith("configured LLM") for engine in investigation_engines), "local_fallbacks": sum("local investigator" in engine for engine in investigation_engines), "engines": investigation_engines, "failures": [i["investigation"]["llm_failure"] for i in incidents.values() if i["investigation"].get("llm_failure")]}, "note": "The optional LLM is called only for incidents with detections. Without a key, or if the provider fails, the evidence-grounded local investigator is used."})

        for incident in incidents.values():
            platform.prioritize_incident(incident)
        yield message("prioritize", "Map techniques, score risk, and build attack graphs", {"incidents": [{"incident_id": i["incident_id"], "severity": i["severity"], "risk_score": i["risk_score"], "risk_factors": i["risk_factors"], "mitre_techniques": i["mitre_techniques"], "graph_nodes": len(i["attack_graph"]["nodes"]), "graph_edges": len(i["attack_graph"]["edges"]), "recommended_actions": i["recommended_actions"]} for i in incidents.values()]})
        yield message("complete", "Analysis complete", {"records_processed": len(normalized), "incident_ids": list(incidents), "response_executed": False, "response_note": "No response action was taken. Any simulated action requires analyst approval."})

    return StreamingResponse(run_stages(), media_type="application/x-ndjson", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


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
