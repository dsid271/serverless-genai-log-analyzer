from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import Counter, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from core.event_bus import EventBus
from core.triage import TriageService

logger = logging.getLogger(__name__)


class ErrorSpikeDetector:
    def __init__(self, bus: EventBus, triage: TriageService, incident_bus: Optional[EventBus] = None):
        self._bus = bus
        self._triage = triage
        self._incident_bus = incident_bus
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._samples: Deque[str] = deque(maxlen=5)

        self._window_seconds = int(os.getenv("ERROR_SPIKE_WINDOW_SECONDS", "60"))
        self._threshold = int(os.getenv("ERROR_SPIKE_THRESHOLD", "20"))
        self._cooldown_seconds = int(os.getenv("ERROR_SPIKE_COOLDOWN_SECONDS", "60"))
        self._last_incident_at: float = 0.0

        # (timestamp, contains_pii, source, severity, malicious_ip, country) per error in the sliding window.
        self._events: Deque[Tuple[float, bool, str, str, bool, Optional[str]]] = deque()

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()

    async def _run(self) -> None:
        q = self._bus.queue()
        while self._running:
            # Drain whatever is queued so a large ingest batch is evaluated once,
            # not once per error log.
            batch: List[Dict[str, Any]] = [await q.get()]
            while not q.empty():
                batch.append(q.get_nowait())
            errors = [e for e in batch if str(e.get("severity", "")).upper() in {"ERROR", "CRITICAL"}]
            if not errors:
                continue

            try:
                await self._handle_error_events(errors)
            except Exception:
                # One bad batch must not kill the detector task, but it must be visible.
                logger.exception("error_spike detector failed to handle events")

    async def _handle_error_events(self, events: List[Dict[str, Any]]) -> None:
        now = time.time()
        for event in events:
            self._events.append((
                now,
                bool(event.get("contains_pii", False)),
                str(event.get("source") or "unknown"),
                str(event.get("severity", "")).upper(),
                any(v is True for k, v in event.items() if k.endswith("_malicious")),
                event.get("source_ip_country"),
            ))
            self._samples.append(str(event.get("message", ""))[:200])

        cutoff = now - self._window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

        if len(self._events) < self._threshold:
            return
        # The window is NOT cleared when an incident fires, so `count` reflects the
        # real number of errors in the window; the cooldown is what suppresses repeats.
        if self._cooldown_seconds > 0 and (now - self._last_incident_at) < self._cooldown_seconds:
            return

        count = len(self._events)
        source_counts = Counter(e[2] for e in self._events)
        countries = Counter(e[5] for e in self._events if e[5])
        details = {
            "window_seconds": self._window_seconds,
            "threshold": self._threshold,
            "count": count,
            "critical_count": sum(1 for e in self._events if e[3] == "CRITICAL"),
            "cooldown_seconds": self._cooldown_seconds,
            # Aggregated over the whole window, not just the triggering event.
            "contains_pii": any(e[1] for e in self._events),
            "samples": list(self._samples),
            "sources": sorted(source_counts),
            "source_counts": dict(source_counts),
            "malicious_ip_count": sum(1 for e in self._events if e[4]),
            "top_countries": dict(countries.most_common(5)),
        }

        # SQLite work runs in a thread so it never stalls the API's event loop.
        inc, is_new = await asyncio.to_thread(
            self._triage.raise_incident,
            kind="error_spike",
            message=f"Error spike detected: {count} errors in last {self._window_seconds}s",
            details=details,
        )
        self._last_incident_at = now

        # Grouped hits update the existing incident; analyzers (and LLM cost) run once per incident.
        if is_new and self._incident_bus is not None:
            try:
                await self._incident_bus.publish({"incident_id": inc.id, "incident": inc.to_dict()})
            except Exception:
                logger.exception("failed to publish incident %s", inc.id)
