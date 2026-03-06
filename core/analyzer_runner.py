from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

from core.event_bus import EventBus
from core.plugin_registry import PluginRegistry


class AnalyzerRunner:
    def __init__(
        self,
        incident_bus: EventBus,
        registry: PluginRegistry,
        incident_store: Any,
        enabled_analyzers: list[str],
    ) -> None:
        self._bus = incident_bus
        self._registry = registry
        self._store = incident_store
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
        while self._running:
            event: Dict[str, Any] = await q.get()
            incident = event.get("incident")
            incident_id = event.get("incident_id")
            if not incident or not incident_id:
                continue

            for name in self._enabled:
                spec = self._registry.get("analyzer", name)
                if spec is None:
                    continue

                try:
                    analyzer = spec.factory()
                    res = await analyzer.analyze({"incident": incident})
                    attach = getattr(self._store, "attach_analysis", None)
                    if callable(attach):
                        attach(incident_id, res)
                except Exception:
                    # Analyzer failures should not stop the runner.
                    continue
