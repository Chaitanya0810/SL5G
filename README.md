# CyberSentinel AI

CyberSentinel turns **synthetic or otherwise authorized** identity, endpoint, network, and cloud events into evidence-backed incident stories. It combines explainable behavior rules, a local Isolation Forest baseline, cross-entity correlation, attack-graph data, MITRE ATT&CK evidence, threat hunts, and analyst-approved response simulations.

## Current capabilities

- Normalize common source fields (`username`, `hostname`, IPs, accounts, cloud resources) into a shared event shape.
- Detect encoded PowerShell, credential access, remote authentication, unusual transfers, privilege escalation, account creation, and cloud permission changes. Each rule includes the matching evidence and supported ATT&CK references.
- Learn a local Isolation Forest baseline from previously ingested events and report anomalies after 24 baseline observations. Features and scores are visible in event/incident output. The model is in memory and resets when the process restarts.
- Correlate recent events by user, account, host, source/destination IP, and cloud resource. Incidents include an entity graph, timeline, cited event IDs, evidence-limited investigation, confidence, asset-aware risk factors, and recommended analyst actions.
- Run telemetry hunts across users, hosts, processes, IPs, and cloud resources.
- Use the built-in analyst dashboard at `/` or the API at `/docs`.
- Simulate host isolation, account disablement, connection blocking, process termination, and credential revocation only after a named analyst approves. Every action is audited and can be rolled back.
- Report precision, recall, and false-positive rate for a small deterministic synthetic scenario set at `/api/v1/evaluation`. These are demonstration metrics, not production performance claims.

## Investigation engine

Without configuration, the investigator uses a local evidence-grounded fallback that cites only events in the incident and reports insufficient evidence for an isolated signal. To use an OpenAI-compatible Chat Completions endpoint, set `OPENAI_API_KEY`; optionally set `OPENAI_BASE_URL` and `OPENAI_MODEL`. When enabled, event details are sent to that configured provider. The response is checked so its cited event IDs must belong to the incident. If the provider is unavailable or returns invalid output, the local investigator is used.

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn api.main:app --reload
```

Open `http://127.0.0.1:8000` for the dashboard, `/docs` for the API, and `/health` for the service health check.

## Docker / Render

```sh
docker compose up --build
```

The container uses Render's `PORT` environment variable when available and serves the dashboard and API on the same port. The deployed service runs in Singapore. Render auto-deploys commits to the configured `main` branch.

## API workflow

1. `POST /api/v1/events` with a normalized or source-shaped synthetic event.
2. Review `GET /api/v1/incidents`, `GET /api/v1/incidents/{incident_id}`, and the generated graph/evidence.
3. Search with `POST /api/v1/hunts`.
4. Explicitly approve a simulated action with `POST /api/v1/incidents/{incident_id}/actions/approve`, including `type`, `target`, and `approved_by`.
5. Roll it back with `POST /api/v1/incidents/{incident_id}/actions/{action_id}/rollback`.
6. Review `GET /api/v1/audit`, `GET /api/v1/metrics`, and `GET /api/v1/evaluation`.

Example event:

```json
{
  "source": "endpoint",
  "user": "alice",
  "host": "PC-101",
  "asset_type": "workstation",
  "event_type": "process_execution",
  "process": "powershell.exe -EncodedCommand ...",
  "raw_log": "powershell.exe launched with an encoded command"
}
```

Send related identity, endpoint, and network observations with shared entity fields to build the incident timeline and graph. Response operations only alter local mock state; they do not contact real endpoints or networks.

## Project layout

```text
api/main.py             FastAPI routes and request models
core/platform.py        Normalization, rules, correlation, graph, risk, sandbox, audit
core/anomaly.py         Local Isolation Forest baseline
core/investigator.py    Evidence-constrained LLM adapter and local fallback
frontend/index.html     Analyst dashboard
```

## Scope and limitations

The service uses in-memory storage; telemetry, incidents, anomaly baselines, and audit records reset on restart. The Isolation Forest learns from the event stream and is not a separately trained or validated production model. Correlation is heuristic, not a graph database. The rule set and synthetic evaluation corpus are intentionally small. Dashboard evaluation reports only the metrics supported by its labeled cases; latency, attack-graph accuracy, and broader MITRE mapping accuracy still require a larger labeled scenario suite. The app has no authentication or durable multi-user access control and is intended as a demo, not a public production SOC.

All response behavior must stay in the simulation. Do not connect this demo to real endpoints, accounts, cloud resources, or networks.
