from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

from core.event_bus import EventBus
from core.plugin_registry import PluginRegistry
from core.triage import TriageService


class AnalyzerRunner:
    def __init__(
        self,
        incident_bus: EventBus,
        registry: PluginRegistry,
        triage: TriageService,
        enabled_analyzers: list[str],
    ) -> None:
        self._bus = incident_bus
        self._registry = registry
        self._triage = triage
        self._enabled = enabled_analyzers
        self._task: Optional[asyncio.Task] = None
        self._running = False

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
        print(f"RUNNER STARTED, enabled={self._enabled}", flush=True)
        while self._running:
            # Errors from q.get() itself (e.g. queue bound to another event loop)
            # are not retryable; let them end the task instead of spinning.
            event: Dict[str, Any] = await q.get()
            try:
                incident = event.get("incident")
                incident_id = event.get("incident_id")
                print(f"RUNNER: got {incident_id}", flush=True)
                if not incident or not incident_id:
                    continue

                for name in self._enabled:
                    spec = self._registry.get("analyzer", name)
                    if spec is None:
                        print(f"RUNNER: no spec for {name}", flush=True)
                        continue
                    try:
                        analyzer = spec.factory()
                        res = await analyzer.analyze({"incident": incident})
                        await asyncio.to_thread(self._triage.attach_analysis, incident_id, res)
                        print(f"RUNNER: attached {name}", flush=True)
                    except Exception as e:
                        print(f"ANALYZER FAILED [{name}]: {type(e).__name__}: {e}", flush=True)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f"RUNNER LOOP ERROR: {type(e).__name__}: {e}", flush=True)