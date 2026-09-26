"""Small, in-memory defensive incident pipeline for simulated telemetry."""
from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Map common source aliases into the project's shared event shape."""
    timestamp = raw.get("timestamp") or utc_now()
    try:
        timestamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).isoformat()
    except ValueError:
        timestamp = utc_now()
    source = str(raw.get("source", "unknown")).lower()
    event_type = raw.get("event_type", raw.get("type", "unknown"))
    return {
        **raw,
        "event_id": str(raw.get("event_id") or uuid.uuid4()),
        "timestamp": timestamp,
        "source": source,
        "user": raw.get("user", raw.get("username", "unknown")),
        "host": raw.get("host", raw.get("hostname", raw.get("source_host", "unknown"))),
        "event_type": str(event_type).lower(),
        "process": raw.get("process", raw.get("process_name", "")),
        "severity": str(raw.get("severity", "low")).lower(),
        "raw_log": str(raw.get("raw_log", raw.get("message", ""))),
    }


def inspect_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Return explainable detections; no conclusions without matching evidence."""
    text = " ".join((event.get("raw_log", ""), event.get("process", ""), event.get("event_type", ""))).lower()
    hits: list[dict[str, Any]] = []
    if "powershell" in text and ("encoded" in text or "-enc" in text or "frombase64string" in text):
        hits.append({"rule": "encoded_powershell", "title": "Encoded PowerShell execution", "evidence": [event.get("process") or event["event_type"], event.get("raw_log", "")], "techniques": ["T1059.001"], "tactics": ["TA0002"]})
    if any(term in text for term in ("credential dump", "lsass", "mimikatz", "credential_access")):
        hits.append({"rule": "credential_access", "title": "Credential access behavior", "evidence": [event.get("event_type"), event.get("raw_log", "")], "techniques": ["T1003"], "tactics": ["TA0006"]})
    if any(term in text for term in ("remote logon", "remote authentication", "lateral_movement", "psexec", "wmic /node")):
        hits.append({"rule": "remote_authentication", "title": "Possible lateral movement", "evidence": [event.get("event_type"), event.get("raw_log", "")], "techniques": ["T1021"], "tactics": ["TA0008"]})
    if any(term in text for term in ("exfiltration", "large_upload", "unusual outbound transfer")):
        hits.append({"rule": "data_transfer", "title": "Potential unusual data transfer", "evidence": [event.get("event_type"), event.get("raw_log", "")], "techniques": ["T1041"], "tactics": ["TA0010"]})
    return hits


class DefensePlatform:
    """In-memory demo platform. Response actions affect simulated state only."""
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.incidents: dict[str, dict[str, Any]] = {}
        self.audit: list[dict[str, Any]] = []
        self.hunts: dict[str, dict[str, Any]] = {}
        self.sandbox_state: dict[str, dict[str, Any]] = defaultdict(lambda: {"isolated": False, "disabled": False, "blocked": []})

    def ingest(self, raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
        event = normalize_event(raw)
        self.events.append(event)
        detections = inspect_event(event)
        self.audit.append({"timestamp": utc_now(), "action": "event_ingested", "event_id": event["event_id"]})
        incident = None
        if detections:
            # Correlate recent events sharing a user or host into one incident.
            related = [e for e in self.events[-50:] if e.get("user") == event.get("user") or e.get("host") == event.get("host")]
            existing = next((i for i in self.incidents.values() if any(e["event_id"] in {x["event_id"] for x in related} for e in i["events"])), None)
            if existing is None:
                incident = {"incident_id": str(uuid.uuid4()), "created_at": utc_now(), "status": "open", "events": [], "detections": [], "hypothesis": "", "confidence": 0.0, "risk_score": 0.0, "severity": "low", "attack_graph": {"nodes": [], "edges": []}, "recommended_actions": [], "approval_required": True, "actions": []}
                self.incidents[incident["incident_id"]] = incident
            else:
                incident = existing
            for related_event in related:
                if all(x["event_id"] != related_event["event_id"] for x in incident["events"]):
                    incident["events"].append(related_event)
            for hit in detections:
                if all(d["rule"] != hit["rule"] or d["event_id"] != event["event_id"] for d in incident["detections"]):
                    incident["detections"].append({**hit, "event_id": event["event_id"]})
            self._summarize(incident)
            self.audit.append({"timestamp": utc_now(), "action": "incident_correlated", "incident_id": incident["incident_id"]})
        return event, incident

    def _summarize(self, incident: dict[str, Any]) -> None:
        detections = incident["detections"]
        unique_rules = {d["rule"] for d in detections}
        score = min(1.0, 0.3 + 0.2 * len(unique_rules) + 0.1 * max(0, len(incident["events"]) - 1))
        techniques = sorted({tech for d in detections for tech in d["techniques"]})
        incident.update({"risk_score": round(score, 2), "severity": "critical" if score >= .9 else "high" if score >= .7 else "medium", "confidence": round(min(.95, .55 + .12 * len(unique_rules)), 2), "mitre_techniques": techniques, "mitre_tactics": sorted({t for d in detections for t in d["tactics"]}), "hypothesis": "Potential multi-stage activity: " + ", ".join(sorted({d["title"] for d in detections})), "recommended_actions": ["Review correlated evidence", "Consider isolating the affected simulated host", "Investigate related authentication and network telemetry"], "attack_graph": self._graph(incident["events"], detections)})

    @staticmethod
    def _graph(events: list[dict[str, Any]], detections: list[dict[str, Any]]) -> dict[str, Any]:
        nodes: dict[str, dict[str, str]] = {}
        edges: list[dict[str, str]] = []
        for event in events:
            for kind, value in (("user", event.get("user")), ("host", event.get("host")), ("process", event.get("process"))):
                if value and value != "unknown":
                    key = f"{kind}:{value}"
                    nodes[key] = {"id": key, "type": kind, "label": str(value)}
            user, host = event.get("user"), event.get("host")
            if user and host and user != "unknown" and host != "unknown":
                edges.append({"source": f"user:{user}", "target": f"host:{host}", "type": "ACTED_ON"})
        for detection in detections:
            key = f"behavior:{detection['rule']}"
            nodes[key] = {"id": key, "type": "behavior", "label": detection["title"]}
            event = next((e for e in events if e["event_id"] == detection["event_id"]), None)
            if event and event.get("host") not in (None, "unknown"):
                edges.append({"source": f"host:{event['host']}", "target": key, "type": "OBSERVED"})
        return {"nodes": list(nodes.values()), "edges": edges}

    def approve_action(self, incident_id: str, action: dict[str, Any]) -> dict[str, Any]:
        incident = self.incidents.get(incident_id)
        if not incident:
            raise KeyError(incident_id)
        kind = action.get("type")
        if kind not in {"isolate_host", "disable_account", "block_connection"}:
            raise ValueError("Supported sandbox actions: isolate_host, disable_account, block_connection")
        target = str(action.get("target", ""))
        if not target:
            raise ValueError("Action target is required")
        state = self.sandbox_state[target]
        before = {"isolated": state["isolated"], "disabled": state["disabled"], "blocked": list(state["blocked"])}
        if kind == "isolate_host": state["isolated"] = True
        elif kind == "disable_account": state["disabled"] = True
        else: state["blocked"].append(target)
        record = {"action_id": str(uuid.uuid4()), "type": kind, "target": target, "status": "approved_and_simulated", "approved_by": str(action.get("approved_by", "analyst")), "timestamp": utc_now(), "before": before}
        incident["actions"].append(record)
        self.audit.append({"timestamp": record["timestamp"], "action": "sandbox_action_approved_and_executed", "incident_id": incident_id, "action_id": record["action_id"], "approved_by": record["approved_by"]})
        return {"record": record, "simulated_state": dict(state)}

    def rollback(self, incident_id: str, action_id: str) -> dict[str, Any]:
        incident = self.incidents.get(incident_id)
        record = next((a for a in (incident or {}).get("actions", []) if a["action_id"] == action_id), None)
        if not record or record.get("status") != "approved_and_simulated":
            raise KeyError(action_id)
        self.sandbox_state[record["target"]] = record["before"]
        record["status"] = "rolled_back"
        self.audit.append({"timestamp": utc_now(), "action": "sandbox_action_rolled_back", "incident_id": incident_id, "action_id": action_id})
        return {"record": record, "simulated_state": dict(self.sandbox_state[record["target"]])}

    def hunt(self, query: dict[str, Any]) -> dict[str, Any]:
        terms = [str(query.get(k, "")).lower() for k in ("user", "host", "process", "contains") if query.get(k)]
        findings = [event for event in self.events if all(term in str(event).lower() for term in terms)] if terms else []
        result = {"hunt_id": str(uuid.uuid4()), "hypothesis": query.get("hypothesis", "Search ingested telemetry"), "status": "completed", "findings": findings, "finding_count": len(findings), "additional_telemetry_required": not bool(self.events)}
        self.hunts[result["hunt_id"]] = result
        self.audit.append({"timestamp": utc_now(), "action": "threat_hunt_completed", "hunt_id": result["hunt_id"], "finding_count": len(findings)})
        return result
