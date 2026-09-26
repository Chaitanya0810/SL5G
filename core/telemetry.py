"""Parse common raw security payloads into the platform's normalized event inputs."""
from __future__ import annotations

import json
import re
from typing import Any


def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            out[_key(name)] = child
            if isinstance(child, dict):
                out.update(_flatten(child, name))
    return out


def _pick(flat: dict[str, Any], *names: str) -> Any:
    for name in names:
        candidate = flat.get(_key(name))
        if candidate not in (None, "", [], {}):
            return candidate
    return None


def _source(event: dict[str, Any], flat: dict[str, Any], text: str) -> tuple[str, str]:
    explicit = _pick(flat, "source", "sourcetype", "category", "telemetrysource", "dataset")
    if explicit:
        name = str(explicit).lower()
        if any(x in name for x in ("cloud", "aws", "azure", "gcp", "trail", "iam")):
            return "cloud", f"source field: {explicit}"
        if any(x in name for x in ("network", "firewall", "flow", "proxy", "dns")):
            return "network", f"source field: {explicit}"
        if any(x in name for x in ("endpoint", "sysmon", "edr", "process", "windows")):
            return "endpoint", f"source field: {explicit}"
        if any(x in name for x in ("identity", "auth", "login", "okta", "entra", "iam")):
            return "identity", f"source field: {explicit}"

    keys = set(flat)
    low = text.lower()
    if keys.intersection({"eventname", "cloudtrail", "useridentity", "cloudresource", "awsregion", "principalid"}) or any(x in low for x in ("cloudtrail", "aws iam", "azure activity", "gcp audit")):
        return "cloud", "cloud audit fields or provider markers"
    if keys.intersection({"process", "processname", "image", "commandline", "parentimage", "parentprocess", "registrypath"}):
        return "endpoint", "process or endpoint activity fields"
    if keys.intersection({"authresult", "authenticationresult", "clientipaddress", "logontype", "failurecode"}) or any(x in low for x in ("authentication", "login", "logon", "failed sign-in", "failed login")):
        return "identity", "authentication fields or login markers"
    if keys.intersection({"dstip", "destinationip", "destinationaddress", "sourceport", "destinationport", "bytesout", "bytesin", "protocol"}) or (keys.intersection({"srcip", "sourceip"}) and keys.intersection({"dstip", "destinationip"})) or re.search(r"\b(?:src|source)[_-]?ip\s*[=:].+\b(?:dst|dest|destination)[_-]?ip\s*[=:]", low) or "network_flow" in low:
        return "network", "network flow fields"
    if any(x in low for x in ("powershell", "sysmon", "process create", "process_execution", "lsass")):
        return "endpoint", "process or endpoint activity markers"
    return "unknown", "source could not be confidently inferred"


def _event(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        text = raw.strip()
        fields: dict[str, Any] = {}
        for match in re.finditer(r"(?:^|[\s,;|])([A-Za-z][\w.-]*)\s*[=:]\s*(\"[^\"]*\"|'[^']*'|[^\s,;|]+)", text):
            fields[match.group(1)] = match.group(2).strip("\"'")
        flat = _flatten(fields)
        source, reason = _source(fields, flat, text)
        return {
            "source": source, "source_detection": reason,
            "timestamp": _pick(flat, "timestamp", "time", "eventtime", "utctime", "datetime"),
            "user": _pick(flat, "user", "username", "account", "principal", "actor.alternateid", "useridentity.username") or "unknown",
            "host": _pick(flat, "host", "hostname", "computer", "device", "source_host") or "unknown",
            "event_type": _pick(flat, "eventtype", "event_type", "eventname", "action", "operation") or _infer_type(source, text),
            "process": _pick(flat, "process", "processname", "image", "commandline") or "",
            "parent_process": _pick(flat, "parentprocess", "parentimage") or "",
            "src_ip": _pick(flat, "srcip", "sourceip", "clientipaddress", "sourceaddress") or "",
            "dst_ip": _pick(flat, "dstip", "destinationip", "remoteip", "destinationaddress") or "",
            "severity": _pick(flat, "severity", "level", "priority") or "low",
            "raw_log": text,
            "metadata": {"parsed_fields": fields},
        }
    if not isinstance(raw, dict):
        raise ValueError("Each telemetry record must be a JSON object or a log line")

    flat = _flatten(raw)
    rendered = json.dumps(raw, ensure_ascii=True, default=str)
    source, reason = _source(raw, flat, rendered)
    event_type = _pick(flat, "eventtype", "event_type", "eventname", "operation", "activitydisplayname", "action")
    process = _pick(flat, "process", "processname", "image", "commandline", "process.commandline", "process.name")
    actor = _pick(flat, "user", "username", "account", "principal", "actor.alternateid", "useridentity.username", "useridentity.arn", "subject.username", "principalid")
    host = _pick(flat, "host", "hostname", "computer", "computername", "device", "devicename", "agent.hostname", "source_host")
    timestamp = _pick(flat, "timestamp", "time", "eventtime", "utctime", "datetime", "creationtime")
    src_ip = _pick(flat, "srcip", "sourceip", "sourceaddress", "clientipaddress", "source.ip", "src_addr")
    dst_ip = _pick(flat, "dstip", "destinationip", "destinationaddress", "destination.ip", "dst_addr", "remoteip")
    bytes_out = _pick(flat, "bytesout", "bytessent", "uploadbytes", "bytes_sent", "sentbytes")
    bytes_in = _pick(flat, "bytesin", "bytesreceived", "receivedbytes")
    record = {
        "source": source, "source_detection": reason,
        "timestamp": timestamp, "user": actor or "unknown", "account": actor or "unknown",
        "host": host or "unknown", "event_type": event_type or _infer_type(source, rendered),
        "process": process or "", "parent_process": _pick(flat, "parentprocess", "parentimage", "process.parent.name") or "",
        "src_ip": src_ip or "", "dst_ip": dst_ip or "",
        "src_port": _pick(flat, "srcport", "sourceport"), "dst_port": _pick(flat, "dstport", "destinationport"),
        "protocol": _pick(flat, "protocol", "network.transport") or "",
        "bytes_out": _number(bytes_out), "bytes_in": _number(bytes_in),
        "auth_result": _pick(flat, "authresult", "authenticationresult", "result", "status") or "",
        "action": _pick(flat, "action", "cloudaction", "eventname", "operation") or "",
        "resource": _pick(flat, "resource", "resourcename", "cloudresource", "resources.0.arn") or "",
        "severity": _pick(flat, "severity", "level", "priority") or "low",
        "raw_log": str(_pick(flat, "rawlog", "message", "description") or rendered),
        "metadata": {"original_record": raw},
    }
    # Preserve useful vendor-specific attributes for analysis and the telemetry viewer.
    for key, value in raw.items():
        if key not in record:
            record[key] = value
    return record


def _number(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _infer_type(source: str, text: str) -> str:
    low = text.lower()
    for needle, kind in (("powershell", "process_execution"), ("credential", "credential_access"), ("remote authentication", "remote_authentication"), ("failed login", "failed_authentication"), ("upload", "large_upload"), ("accesskey", "cloud_credential_change")):
        if needle in low:
            return kind
    return {"identity": "authentication_event", "endpoint": "endpoint_event", "network": "network_flow", "cloud": "cloud_audit_event"}.get(source, "unknown")


def parse_telemetry(raw_data: str) -> list[dict[str, Any]]:
    """Accept one JSON record, JSON arrays/wrappers, NDJSON, or plain log lines."""
    text = raw_data.strip()
    if not text:
        raise ValueError("Paste raw telemetry before submitting")
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, dict):
            wrappers = {"events", "records", "logs", "logevents", "items", "value"}
            records = next((value for key, value in parsed.items() if _key(key) in wrappers and isinstance(value, list)), [parsed])
        else:
            records = [parsed]
        return [_event(item) for item in records]
    except json.JSONDecodeError:
        pass

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > 1:
        records = []
        for line in lines:
            try:
                item = json.loads(line)
                records.extend(item if isinstance(item, list) else [item])
            except json.JSONDecodeError:
                records.append(line)
        return [_event(item) for item in records]
    return [_event(text)]
