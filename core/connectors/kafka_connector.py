from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from ingestion.kafka_consumer import LogConsumer

logger = logging.getLogger(__name__)


class KafkaConnector:
    def __init__(self, on_batch_callback, *, topic: Optional[str] = None):
        self._on_batch_callback = on_batch_callback
        self._topic = topic
        self._consumer: Optional[LogConsumer] = None
        self._task: Optional[asyncio.Task] = None
        self._stopping = False

    async def start(self) -> None:
        bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        topic = self._topic or os.getenv("LOG_TOPIC", "logs-raw")
        group_id = os.getenv("KAFKA_GROUP_ID", "log-analyzer-group")

        self._consumer = LogConsumer(
            self._on_batch_callback,
            topic=topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            max_batch=int(os.getenv("KAFKA_MAX_BATCH", "500")),
        )
        # Connect in the background so the API starts even if the broker is not up yet.
        self._task = asyncio.create_task(self._connect_and_run(bootstrap_servers))

    async def _connect_and_run(self, bootstrap_servers: str) -> None:
        delay = 2.0
        while not self._stopping:
            if await self._consumer.start():
                await self._consumer.run()
                if self._stopping:
                    return
                delay = 2.0
            logger.warning("Kafka unavailable at %s; retrying in %.0fs", bootstrap_servers, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60.0)

    async def stop(self) -> None:
        self._stopping = True
        if self._consumer is not None:
            await self._consumer.stop()
        if self._task is not None:
            self._task.cancel()
