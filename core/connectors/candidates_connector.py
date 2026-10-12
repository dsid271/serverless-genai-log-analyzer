"""Consumes spike candidates from the Spark job (Kafka topic incident-candidates)
and raises them through the existing triage pipeline as `error_spike` incidents."""
from __future__ import annotations

import asyncio
import logging
import os
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from core.connectors.kafka_connector import KafkaConnector
from core.event_bus import EventBus
from core.triage import TriageService

logger = logging.getLogger(__name__)


class CandidateHandler:
    """Turns candidate records into incidents, once per (source, window_start).

    The Spark job runs in "update" mode, so a window is re-sent each time its count grows.
    """

    def __init__(self, triage: TriageService, incident_bus: Optional[EventBus] = None,
                 max_seen: int = 10_000):
        self._triage = triage
        self._incident_bus = incident_bus
        self._seen: "OrderedDict[tuple, None]" = OrderedDict()
        self._max_seen = max_seen

    def _details(self, c: Dict[str, Any]) -> Dict[str, Any]:
        source = str(c.get("source") or "unknown")
        count = int(c.get("count") or 0)
        return {
            "origin": "spark",
            "window_start": c.get("window_start"),
            "window_end": c.get("window_end"),
            "threshold": c.get("threshold"),
            "baseline": c.get("baseline"),
            "reason": c.get("reason", "threshold"),
            "count": count,
            "critical_count": int(c.get("critical_count") or 0),
            "contains_pii": bool(c.get("contains_pii", False)),
            "patterns": c.get("patterns"),
            "samples": [str(c["sample"])[:200]] if c.get("sample") else [],
            "sources": [source],
            "source_counts": {source: count},
        }

    async def __call__(self, candidates: List[Dict[str, Any]]) -> None:
        for c in candidates:
            key = (c.get("source"), c.get("window_start"))
            if key in self._seen:
                continue
            details = self._details(c)
            inc, is_new = await asyncio.to_thread(
                self._triage.raise_incident,
                kind="error_spike",
                message=(f"Error spike detected: {details['count']} errors from {details['sources'][0]}"
                         f" in window starting {details['window_start']}"),
                details=details,
            )
            self._seen[key] = None
            while len(self._seen) > self._max_seen:
                self._seen.popitem(last=False)
            if is_new and self._incident_bus is not None:
                try:
                    await self._incident_bus.publish({"incident_id": inc.id, "incident": inc.to_dict()})
                except Exception:
                    logger.exception("failed to publish incident %s", inc.id)


def build_candidates_connector(triage: TriageService, incident_bus: Optional[EventBus] = None) -> KafkaConnector:
    return KafkaConnector(
        CandidateHandler(triage, incident_bus),
        topic=os.getenv("SPARK_CANDIDATES_TOPIC", "incident-candidates"),
        group_id=os.getenv("CANDIDATES_GROUP_ID", "log-analyzer-candidates"),
    )
