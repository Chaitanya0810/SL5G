"""Local Isolation Forest scorer trained only on previously ingested synthetic events."""
from __future__ import annotations

from typing import Any

from sklearn.ensemble import IsolationForest


class AnomalyModel:
    def __init__(self, min_samples: int = 24) -> None:
        self.min_samples = min_samples
        self.rows: list[list[float]] = []
        self.model: IsolationForest | None = None
        self.last_fit_count = 0
        self.refit_interval = 50

    @staticmethod
    def features(event: dict[str, Any]) -> list[float]:
        meta = event.get("metadata", {})
        def number(key: str, default: Any = 0) -> float:
            try:
                return float(meta.get(key, event.get(key, default)) or 0)
            except (TypeError, ValueError):
                return 0.0
        severity = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(event.get("severity", "low")).lower(), 1)
        try:
            hour = int(str(event.get("timestamp", ""))[11:13])
        except (ValueError, TypeError):
            hour = 12
        return [
            float(severity), float(hour), number("bytes_out"), number("bytes_in"),
            number("failed_attempts"), number("port_count", event.get("unique_destination_ports", 0)),
            float(bool(event.get("src_ip"))), float(bool(event.get("dst_ip"))),
            float(bool(event.get("process"))), float(str(event.get("source", "")) == "cloud"),
            float("auth" in str(event.get("event_type", ""))), float("network" in str(event.get("source", ""))),
        ]

    def score(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if len(self.rows) < self.min_samples:
            return None
        if self.model is None or len(self.rows) - self.last_fit_count >= self.refit_interval:
            self.model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
            self.model.fit(self.rows[-500:])
            self.last_fit_count = len(self.rows)
        vector = [self.features(event)]
        raw = float(self.model.decision_function(vector)[0])
        # Isolation Forest's decision boundary is zero; map negative margins to [0, 1].
        score = max(0.0, min(1.0, .5 - raw * 4.0))
        return {"score": round(score, 3), "model": "IsolationForest", "evidence": [f"Local Isolation Forest anomaly score {score:.3f}", f"Baseline observations: {len(self.rows)}"]}

    def learn(self, event: dict[str, Any]) -> None:
        self.rows.append(self.features(event))
        if len(self.rows) > 1000:
            self.rows = self.rows[-1000:]
