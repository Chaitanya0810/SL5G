# CyberSentinel AI

CyberSentinel is a defensive cybersecurity project that turns **simulated** security events into correlated, evidence-backed incidents. This repository currently provides a runnable API MVP for telemetry normalization, explainable rule detections, event correlation, attack graph generation, threat hunting, and approval-gated response simulation.

## What works in this MVP

- Normalize identity, endpoint, network, and cloud shaped events into a common event record.
- Detect a small set of explicit behaviors (encoded PowerShell, credential access, remote authentication, and unusual data transfer). Every detection includes the event and evidence that triggered it.
- Correlate recent events that share a user or host, produce a basic attack graph, MITRE ATT&CK technique/tactic references, hypothesis, confidence, and risk priority.
- Search ingested events with a threat hunt query.
- Require a named analyst approval request before simulating endpoint isolation, account disablement, or a connection block. Actions only update in-memory mock state and can be rolled back.
- Record ingestion, correlation, hunts, response approval, and rollback in an in-memory audit log.

The implementation is intentionally a safe, small MVP. It does **not** connect to real endpoints, cloud accounts, SIEMs, or networks. It does not execute containment on infrastructure. Storage is in memory and is cleared when the API process restarts. The current anomaly score is a transparent rule-based prioritization score, not a trained ML model; the current investigator is deterministic and does not call an LLM. These are extension points, not completed features. Metrics are counters only; precision, recall, false-positive rate, latency, and mapping accuracy require labeled evaluation scenarios.

## Run locally

```powershell
cd CyberSentinel-AI
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn api.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API. Health check: `GET /health`.

## API flow

1. Submit events to `POST /api/v1/events`. The API returns the normalized event, any detections, and a correlated incident when evidence matches a rule.
2. Review incidents at `GET /api/v1/incidents` or `GET /api/v1/incidents/{incident_id}`. Incident evidence, ATT&CK references, and graph nodes/edges are included.
3. Search ingested telemetry with `POST /api/v1/hunts`, providing one or more of `user`, `host`, `process`, or `contains`.
4. After analyst review, explicitly request a mock response at `POST /api/v1/incidents/{incident_id}/actions/approve` with `type`, `target`, and `approved_by`. Supported types: `isolate_host`, `disable_account`, `block_connection`.
5. Roll back a simulated action with `POST /api/v1/incidents/{incident_id}/actions/{action_id}/rollback`.
6. Review the audit records at `GET /api/v1/audit` and counters at `GET /api/v1/metrics`.

Example simulated event:

```json
{
  "source": "endpoint",
  "user": "alice",
  "host": "PC-101",
  "event_type": "process_execution",
  "process": "powershell.exe -EncodedCommand ...",
  "raw_log": "powershell.exe launched with encoded command"
}
```

Then send another event for the same user or host, for example a `remote_authentication` event, to see correlation. Only send synthetic or otherwise authorized telemetry to this demo service.

## Project layout

```text
api/main.py          FastAPI endpoints and request validation
core/platform.py     Normalization, detection, correlation, graph, hunts, sandbox, audit
requirements.txt     Minimal runtime dependencies
```

## Requirements roadmap

The reference project brief describes a broader target platform. The current MVP implements the safe core flow above. Still needed for that full target: persistent SQLite/PostgreSQL storage, source-specific ingestion adapters, a trained and evaluated anomaly model, LLM investigation grounded in cited event IDs, richer ATT&CK mappings with technique-level evidence, labeled scenario data and evaluation, frontend/dashboard, and durable audit/rollback storage. Any future active response integration must retain explicit human approval, sandbox-only execution, rollback, and auditability.
