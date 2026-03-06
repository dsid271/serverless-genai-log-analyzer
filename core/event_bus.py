from __future__ import annotations

import asyncio
from typing import Any, Dict


class EventBus:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()

    async def publish(self, event: Dict[str, Any]) -> None:
        await self._queue.put(event)

    def queue(self) -> asyncio.Queue[Dict[str, Any]]:
        return self._queue
