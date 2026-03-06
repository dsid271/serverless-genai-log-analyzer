from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from typing import Any, Deque, Dict, Optional

from core.event_bus import EventBus
from core.incident_store import IncidentStore


class ErrorSpikeDetector:
    def __init__(self, bus: EventBus, store: IncidentStore, incident_bus: Optional[EventBus] = None):
        self._bus = bus
        self._store = store
        self._incident_bus = incident_bus
        self._task: Optional[asyncio.Task] = None
        self._running = False

        self._window_seconds = int(os.getenv("ERROR_SPIKE_WINDOW_SECONDS", "60"))
        self._threshold = int(os.getenv("ERROR_SPIKE_THRESHOLD", "20"))
        self._cooldown_seconds = int(os.getenv("ERROR_SPIKE_COOLDOWN_SECONDS", "60"))
        self._last_incident_at: float = 0.0

        self._events: Deque[float] = deque()

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
            event: Dict[str, Any] = await q.get()
            severity = str(event.get("severity", "")).upper()
            if severity not in {"ERROR", "CRITICAL"}:
                continue

            now = time.time()
            self._events.append(now)

            cutoff = now - self._window_seconds
            while self._events and self._events[0] < cutoff:
                self._events.popleft()

            if len(self._events) >= self._threshold:
                if self._cooldown_seconds > 0 and (now - self._last_incident_at) < self._cooldown_seconds:
                    continue

                # Emit a single incident and reset the window to avoid spamming.
                inc = self._store.add(
                    kind="error_spike",
                    message=f"Error spike detected: {len(self._events)} errors in last {self._window_seconds}s",
                    details={
                        "window_seconds": self._window_seconds,
                        "threshold": self._threshold,
                        "count": len(self._events),
                        "cooldown_seconds": self._cooldown_seconds,
                    },
                )
                self._last_incident_at = now

                if self._incident_bus is not None:
                    try:
                        await self._incident_bus.publish({"incident_id": inc.id, "incident": inc.to_dict()})
                    except Exception:
                        pass
                self._events.clear()
