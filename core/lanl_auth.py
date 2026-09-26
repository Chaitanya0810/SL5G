"""Streaming adapter for LANL's de-identified auth.txt event format."""
from __future__ import annotations

import csv
import gzip
from pathlib import Path
from typing import Any, Iterator, TextIO


def _open_text(path: str | Path) -> TextIO:
    path = Path(path)
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="")
    return path.open("rt", encoding="utf-8", errors="replace", newline="")


def iter_auth_events(
    path: str | Path,
    *,
    limit: int | None = None,
    sample_every: int = 1,
    time_start: int | None = None,
    time_end: int | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield normalized inputs from LANL auth rows without loading the file in memory.

    LANL's first column is elapsed seconds from dataset start, not a wall-clock
    timestamp, so it is kept as ``event_time_seconds`` rather than misdated.
    """
    if sample_every < 1:
        raise ValueError("sample_every must be at least 1")
    emitted = 0
    with _open_text(path) as stream:
        reader = csv.reader(stream)
        for row_number, row in enumerate(reader, 1):
            if len(row) != 9:
                raise ValueError(f"Expected 9 comma-separated columns at row {row_number}, got {len(row)}")
            if (row_number - 1) % sample_every:
                continue
            try:
                elapsed = int(row[0])
            except ValueError as exc:
                raise ValueError(f"Invalid elapsed time at row {row_number}: {row[0]!r}") from exc
            if time_start is not None and elapsed < time_start:
                continue
            if time_end is not None and elapsed > time_end:
                continue
            source_user, destination_user, source_host, destination_host, auth_type, logon_type, orientation, result = row[1:]
            result_value = result.strip().lower()
            outcome = "success" if result_value == "success" else "failure" if result_value == "failure" else "unknown"
            raw_log = (
                f"LANL auth elapsed={elapsed} source_user={source_user} destination_user={destination_user} "
                f"source_host={source_host} destination_host={destination_host} auth_type={auth_type} "
                f"logon_type={logon_type} orientation={orientation} result={result}"
            )
            yield {
                "source": "identity",
                "dataset": "LANL Comprehensive Multi-Source Cybersecurity Events",
                "event_type": "authentication_event",
                "event_time_seconds": elapsed,
                "user": source_user,
                "account": source_user,
                "host": source_host,
                "source_host": source_host,
                "destination_host": destination_host,
                "destination_user": destination_user,
                "auth_type": auth_type,
                "logon_type": logon_type,
                "auth_orientation": orientation,
                "auth_result": outcome,
                "severity": "medium" if outcome == "failure" else "low",
                "raw_log": raw_log,
            }
            emitted += 1
            if limit is not None and emitted >= limit:
                return
