from __future__ import annotations

import asyncio
import os
from typing import Optional

from ingestion.kafka_consumer import LogConsumer


class KafkaConnector:
    def __init__(self, on_message_callback, *, topic: Optional[str] = None):
        self._on_message_callback = on_message_callback
        self._topic = topic
        self._consumer: Optional[LogConsumer] = None
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        topic = self._topic or os.getenv("LOG_TOPIC", "logs-raw")
        group_id = os.getenv("KAFKA_GROUP_ID", "log-analyzer-group")

        self._consumer = LogConsumer(
            topic=topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
        )

        # Run consumer loop in background
        self._task = asyncio.create_task(self._consumer.start(on_message_callback=self._on_message_callback))

    async def stop(self) -> None:
        if self._consumer is not None:
            await self._consumer.stop()
        if self._task is not None:
            self._task.cancel()
