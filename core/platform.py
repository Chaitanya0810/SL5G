"""Evidence-grounded simulated cyber defense pipeline."""
from __future__ import annotations

import os
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from core.anomaly import AnomalyModel
from core.investigator import investigate


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    timestamp = raw.get("timestamp") or utc_now()
    try:
        timestamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).isoformat()
    except ValueError:
        timestamp = utc_now()
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    return {
        **raw,
        "event_id": str(raw.get("event_id") or uuid.uuid4()),
        "timestamp": timestamp,
        "source": str(raw.get("source", "unknown")).lower(),
        "user": raw.get("user", raw.get("username", raw.get("account", "unknown"))),
        "host": raw.get("host", raw.get("hostname", raw.get("source_host", "unknown"))),
        "event_type": str(raw.get("event_type", raw.get("type", "unknown"))).lower(),
        "process": raw.get("process", raw.get("process_name", "")),
        "parent_process": raw.get("parent_process", raw.get("parent_process_name", "")),
        "severity": str(raw.get("severity", "low")).lower(),
        "raw_log": str(raw.get("raw_log", raw.get("message", ""))),
        "src_ip": raw.get("src_ip", raw.get("source_ip", raw.get("srcip", metadata.get("src_ip", "")))),
        "dst_ip": raw.get("dst_ip", raw.get("destination_ip", raw.get("dstip", metadata.get("dst_ip", "")))),
        "src_port": raw.get("src_port", raw.get("source_port", metadata.get("src_port"))),
        "dst_port": raw.get("dst_port", raw.get("destination_port", metadata.get("dst_port"))),
        "protocol": str(raw.get("protocol", metadata.get("protocol", ""))).upper(),
        "bytes_out": raw.get("bytes_out", raw.get("bytes_sent", raw.get("upload_bytes", metadata.get("bytes_out", 0)))),
        "bytes_in": raw.get("bytes_in", raw.get("bytes_received", metadata.get("bytes_in", 0))),
        "auth_result": raw.get("auth_result", raw.get("result", metadata.get("result", ""))),
        "action": raw.get("action", raw.get("cloud_action", metadata.get("action", ""))),
        "file_path": raw.get("file_path", raw.get("filename", metadata.get("file_path", ""))),
        "registry_path": raw.get("registry_path", metadata.get("registry_path", "")),
        "account": raw.get("account", raw.get("user", "unknown")),
        "resource": raw.get("resource", raw.get("cloud_resource", "")),
        "metadata": metadata,
    }


def inspect_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    text = " ".join(str(event.get(k, "")) for k in ("raw_log", "process", "event_type", "severity", "auth_result", "action", "file_path")).lower()
    hits: list[dict[str, Any]] = []

    def add(rule: str, title: str, evidence: list[str], technique: str, tactic: str, confidence: float = .78) -> None:
        hits.append({"rule": rule, "title": title, "evidence": [x for x in evidence if x], "techniques": [technique], "tactics": [tactic], "confidence": confidence})

    if "powershell" in text and any(s in text for s in ("encoded", "-enc", "frombase64string")):
        add("encoded_powershell", "Encoded PowerShell execution", [event.get("process", ""), event.get("raw_log", "")], "T1059.001", "TA0002", .9)
    if any(s in text for s in ("credential dump", "lsass", "mimikatz", "credential_access", "dump credentials")):
        add("credential_access", "Credential access behavior", [event.get("event_type", ""), event.get("raw_log", "")], "T1003", "TA0006", .88)
    if event.get("auth_result", "").lower() in {"failure", "failed", "failed_authentication"} and int(event.get("failed_attempts", 0) or 0) >= 5:
        add("authentication_failures", "Repeated failed authentication", [f"Failed attempts: {event.get('failed_attempts')}", event.get("src_ip", "")], "T1110", "TA0006", .82)
    if any(s in text for s in ("remote logon", "remote authentication", "lateral_movement", "psexec", "wmic /node", "remote_authentication")):
        add("remote_authentication", "Possible lateral movement", [event.get("event_type", ""), event.get("raw_log", "")], "T1021", "TA0008", .8)
    if any(s in text for s in ("exfiltration", "large_upload", "unusual outbound transfer")):
        add("data_transfer", "Potential unusual data transfer", [event.get("event_type", ""), event.get("raw_log", "")], "T1041", "TA0010", .8)
    if any(s in text for s in ("privilege escalation", "privilege_escalation", "sudo", "runas")):
        add("privilege_escalation", "Possible privilege escalation", [event.get("event_type", ""), event.get("raw_log", "")], "T1068", "TA0004", .72)
    if any(s in text for s in ("account created", "account_creation", "new user")):
        add("account_creation", "Account created", [event.get("event_type", ""), event.get("raw_log", "")], "T1136", "TA0003", .72)
    if any(s in text for s in ("access key created", "access_key_creation", "createaccesskey", "iam policy", "iam change", "permission change")):
        add("cloud_permission_change", "Cloud identity or permission change", [event.get("event_type", ""), event.get("raw_log", "")], "T1098", "TA0003", .7)
    return hits


class DefensePlatform:
    """In-memory demo platform. Response operations only mutate mock state."""
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.incidents: dict[str, dict[str, Any]] = {}
        self.audit: list[dict[str, Any]] = []
        self.hunts: dict[str, dict[str, Any]] = {}
        self.sandbox_state: dict[str, dict[str, Any]] = defaultdict(lambda: {"isolated": False, "disabled": False, "blocked": [], "terminated_processes": [], "revoked_credentials": []})
        self.asset_criticality: dict[str, float] = {"workstation": .5, "database": .85, "identity": 1.0, "critical": 1.0}
        self.ml = AnomalyModel()

    def _related(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        entity_keys = ("user", "host", "account", "destination_user", "destination_host", "src_ip", "dst_ip", "resource")
        keys = {event.get(k) for k in entity_keys if event.get(k) and event.get(k) != "unknown"}
        return [prior for prior in self.events[-200:] if keys.intersection(prior.get(k) for k in entity_keys)]

    def ingest(self, raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
        event = normalize_event(raw)
        detections = self.detect_normalized(event)
        incident = self.correlate_detected(event, detections)
        if incident:
            self.investigate_incident(incident)
            self.prioritize_incident(incident)
        return event, incident

    def detect_normalized(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Score a normalized event, then learn it for future anomaly comparisons."""
        anomaly = self.ml.score(event)
        detections = inspect_event(event)
        if anomaly and anomaly["score"] >= .68:
            detections.append({"rule": "ml_anomaly", "title": "Behavioral anomaly", "evidence": anomaly["evidence"], "techniques": [], "tactics": [], "confidence": anomaly["score"], "anomaly_score": anomaly["score"], "model": anomaly["model"]})
        self.ml.learn(event)
        event["anomaly"] = anomaly
        return detections

    def correlate_detected(self, event: dict[str, Any], detections: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Store one processed event and attach its detections to a related incident."""
        self.events.append(event)
        self.audit.append({"timestamp": utc_now(), "action": "event_ingested", "event_id": event["event_id"]})
        incident = None
        if detections:
            related = self._related(event) + [event]
            related_ids = {e["event_id"] for e in related}
            existing = next((i for i in reversed(list(self.incidents.values())) if any(e["event_id"] in related_ids for e in i["events"])), None)
            if existing is None:
                incident = {"incident_id": str(uuid.uuid4()), "created_at": utc_now(), "status": "open", "events": [], "detections": [], "hypothesis": "", "investigation": {}, "confidence": 0.0, "risk_score": 0.0, "severity": "low", "attack_graph": {"nodes": [], "edges": []}, "recommended_actions": [], "approval_required": True, "actions": []}
                self.incidents[incident["incident_id"]] = incident
            else:
                incident = existing
            for item in related:
                if all(x["event_id"] != item["event_id"] for x in incident["events"]):
                    incident["events"].append(item)
            for hit in detections:
                if all(d["rule"] != hit["rule"] or d["event_id"] != event["event_id"] for d in incident["detections"]):
                    incident["detections"].append({**hit, "event_id": event["event_id"]})
            self.audit.append({"timestamp": utc_now(), "action": "incident_correlated", "incident_id": incident["incident_id"]})
        return incident

    def investigate_incident(self, incident: dict[str, Any]) -> None:
        investigation = investigate(incident["events"], incident["detections"])
        incident["hypothesis"] = investigation["hypothesis"]
        incident["investigation"] = investigation
        incident["confidence"] = round(max((d.get("confidence", .6) for d in incident["detections"]), default=.5), 2)
        incident["status"] = "investigating" if investigation["status"] == "INSUFFICIENT EVIDENCE" else "open"

    def prioritize_incident(self, incident: dict[str, Any]) -> None:
        detections, events = incident["detections"], incident["events"]
        techniques = sorted({t for d in detections for t in d["techniques"]})
        rule_score = min(1.0, .25 + .18 * len({d["rule"] for d in detections}) + .08 * max(0, len(events) - 1))
        ml_scores = [d.get("anomaly_score", 0) for d in detections]
        evidence_confidence = max((d.get("confidence", .6) for d in detections), default=.5)
        criticality = max((self.asset_criticality.get(str(e.get("asset_criticality", e.get("asset_type", "workstation"))).lower(), .5) for e in events), default=.5)
        risk = min(1.0, rule_score * .45 + evidence_confidence * .3 + criticality * .15 + (max(ml_scores, default=0) * .1))
        incident.update({
            "risk_score": round(risk, 3),
            "risk_factors": {"rule_and_correlation": round(rule_score, 3), "evidence_confidence": round(evidence_confidence, 3), "asset_criticality": round(criticality, 3), "anomaly_score": round(max(ml_scores, default=0), 3)},
            "severity": "critical" if risk >= .85 else "high" if risk >= .68 else "medium" if risk >= .45 else "low",
            "confidence": round(evidence_confidence, 2), "mitre_techniques": techniques,
            "mitre_tactics": sorted({t for d in detections for t in d["tactics"]}),
            "recommended_actions": ["Review cited events and validate affected assets", "Search related user, host, and network telemetry", "Request analyst approval before any simulated containment"],
            "attack_graph": self._graph(events, detections),
        })

    def _summarize(self, incident: dict[str, Any]) -> None:
        self.investigate_incident(incident)
        self.prioritize_incident(incident)

    @staticmethod
    def _graph(events: list[dict[str, Any]], detections: list[dict[str, Any]]) -> dict[str, Any]:
        nodes: dict[str, dict[str, str]] = {}
        edges: list[dict[str, str]] = []
        for event in events:
            entities = [(kind, event.get(key)) for kind, key in (("user", "user"), ("user", "destination_user"), ("account", "account"), ("host", "host"), ("host", "destination_host"), ("process", "process"), ("ip", "src_ip"), ("ip", "dst_ip"), ("resource", "resource"))]
            for kind, value in entities:
                if value and value != "unknown":
                    nid = f"{kind}:{value}"
                    nodes[nid] = {"id": nid, "type": kind, "label": str(value)}
            if event.get("user") not in (None, "unknown") and event.get("host") not in (None, "unknown"):
                edges.append({"source": f"user:{event['user']}", "target": f"host:{event['host']}", "type": "LOGIN_OR_ACTIVITY"})
            if event.get("host") and event.get("destination_host"):
                edges.append({"source": f"host:{event['host']}", "target": f"host:{event['destination_host']}", "type": "AUTHENTICATED_TO"})
            if event.get("src_ip") and event.get("dst_ip"):
                edges.append({"source": f"ip:{event['src_ip']}", "target": f"ip:{event['dst_ip']}", "type": "CONNECTED_TO"})
        for d in detections:
            key = f"behavior:{d['rule']}"
            nodes[key] = {"id": key, "type": "behavior", "label": d["title"]}
            event = next((e for e in events if e["event_id"] == d["event_id"]), None)
            if event and event.get("host") not in (None, "unknown"):
                edges.append({"source": f"host:{event['host']}", "target": key, "type": "OBSERVED"})
        return {"nodes": list(nodes.values()), "edges": edges}

    def approve_action(self, incident_id: str, action: dict[str, Any]) -> dict[str, Any]:
        incident = self.incidents.get(incident_id)
        if not incident:
            raise KeyError(incident_id)
        kind, target = action.get("type"), str(action.get("target", ""))
        allowed = {"isolate_host", "disable_account", "block_connection", "terminate_process", "revoke_credential"}
        if kind not in allowed:
            raise ValueError("Supported sandbox actions: " + ", ".join(sorted(allowed)))
        if not target:
            raise ValueError("Action target is required")
        state = self.sandbox_state[target]
        before = {k: list(v) if isinstance(v, list) else v for k, v in state.items()}
        if kind == "isolate_host": state["isolated"] = True
        elif kind == "disable_account": state["disabled"] = True
        elif kind == "block_connection": state["blocked"].append(target)
        elif kind == "terminate_process": state["terminated_processes"].append(target)
        elif kind == "revoke_credential": state["revoked_credentials"].append(target)
        record = {"action_id": str(uuid.uuid4()), "type": kind, "target": target, "status": "approved_and_simulated", "approved_by": str(action["approved_by"]), "timestamp": utc_now(), "before": before}
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
        terms = [str(query.get(k, "")).lower() for k in ("user", "host", "process", "contains", "src_ip", "dst_ip", "resource") if query.get(k)]
        findings = [e for e in self.events if all(term in str(e).lower() for term in terms)] if terms else []
        result = {"hunt_id": str(uuid.uuid4()), "hypothesis": query.get("hypothesis", "Search ingested telemetry"), "status": "completed" if findings else "INSUFFICIENT EVIDENCE", "findings": findings, "finding_count": len(findings), "additional_telemetry_required": not bool(findings)}
        self.hunts[result["hunt_id"]] = result
        self.audit.append({"timestamp": utc_now(), "action": "threat_hunt_completed", "hunt_id": result["hunt_id"], "finding_count": len(findings)})
        return result

    def evaluation_metrics(self) -> dict[str, Any]:
        """Evaluate a fixed, labeled synthetic corpus against the rule engine."""
        corpus = [
            ({"event_type": "login", "source": "identity", "user": "normal", "host": "ws-1", "raw_log": "successful login"}, False),
            ({"event_type": "process_execution", "source": "endpoint", "user": "normal", "host": "ws-1", "process": "explorer.exe", "raw_log": "normal process"}, False),
            ({"event_type": "process_execution", "source": "endpoint", "user": "alice", "host": "ws-2", "process": "powershell.exe -EncodedCommand abc", "raw_log": "encoded PowerShell"}, True),
            ({"event_type": "credential_access", "source": "endpoint", "user": "alice", "host": "ws-2", "raw_log": "LSASS credential dump"}, True),
            ({"event_type": "remote_authentication", "source": "identity", "user": "alice", "host": "srv-2", "raw_log": "remote authentication"}, True),
            ({"event_type": "cloud_audit", "source": "cloud", "user": "bob", "host": "unknown", "raw_log": "ordinary API read"}, False),
        ]
        tp = fp = tn = fn = 0
        for event, label in corpus:
            predicted = bool(inspect_event(normalize_event(event)))
            tp += int(predicted and label); fp += int(predicted and not label)
            tn += int(not predicted and not label); fn += int(not predicted and label)
        return {"labeled_scenarios": len(corpus), "precision": round(tp / (tp + fp), 3) if tp + fp else 0, "recall": round(tp / (tp + fn), 3) if tp + fn else 0, "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else 0, "true_positives": tp, "false_positives": fp, "true_negatives": tn, "false_negatives": fn, "scope": "small deterministic synthetic baseline; not a production benchmark"}
