import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger("KafkaConsumer")


def _decode(raw: bytes) -> Optional[Dict[str, Any]]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


class LogConsumer:
    """Async Kafka consumer: hands each polled batch of decoded logs to `on_batch`.

    Redaction happens downstream in the orchestrator's enricher, the same path
    as `POST /ingest`. Offsets are committed only after `on_batch` succeeds
    (at-least-once delivery).
    """

    def __init__(
        self,
        on_batch: Callable[[List[Dict[str, Any]]], Awaitable[Any]],
        topic: str = "logs-raw",
        bootstrap_servers: str = "localhost:9092",
        group_id: str = "log-analyzer-group",
        max_batch: int = 500,
    ):
        self.on_batch = on_batch
        self.topic = topic
        self.bootstrap_servers = bootstrap_servers
        self.group_id = group_id
        self.max_batch = max_batch
        self.consumer: Optional[Any] = None
        self._running = False

    async def start(self) -> bool:
        """Connect only. Returns False if Kafka is unavailable (graceful degradation)."""
        try:
            from aiokafka import AIOKafkaConsumer
        except Exception as e:
            logger.error(f"aiokafka not installed: {e}. Running without Kafka ingestion.")
            return False

        self.consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            request_timeout_ms=5000,
        )

        try:
            await self.consumer.start()
        except Exception as e:
            logger.error(f"Cannot reach Kafka at {self.bootstrap_servers}: {e}")
            self.consumer = None
            return False

        self._running = True
        logger.info(f"Kafka consumer connected (topic={self.topic})")
        return True

    async def run(self):
        """Consume loop. Run as a background task: asyncio.create_task(c.run())"""
        from aiokafka import ConsumerStoppedError

        if not self._running:
            return

        try:
            while self._running:
                polled = await self.consumer.getmany(timeout_ms=1000, max_records=self.max_batch)
                if not polled:
                    continue
                logs: List[Dict[str, Any]] = []
                for tp, messages in polled.items():
                    for msg in messages:
                        value = _decode(msg.value)
                        if value is None:
                            logger.warning(f"Skipping non-JSON-object message at {tp.partition}:{msg.offset}")
                            continue
                        logs.append(value)
                if logs:
                    try:
                        await self.on_batch(logs)
                    except Exception as e:
                        # Rewind so the same batch is retried; nothing is committed past it.
                        logger.error(f"Error ingesting batch of {len(logs)} logs: {e}")
                        for tp, messages in polled.items():
                            self.consumer.seek(tp, messages[0].offset)
                        await asyncio.sleep(5)
                        continue
                await self.consumer.commit()
        except ConsumerStoppedError:
            logger.info("Consumer stopped cleanly.")
        except asyncio.CancelledError:
            logger.info("Consumer task cancelled.")
            raise
        except Exception as e:
            logger.error(f"Fatal consumer loop error: {e}")
        finally:
            await self.stop()

    async def stop(self):
        self._running = False
        if self.consumer:
            await self.consumer.stop()
            self.consumer = None
            logger.info("Kafka consumer stopped.")