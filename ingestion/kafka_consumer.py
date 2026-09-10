import asyncio
import json
import logging
from typing import Any, Optional

logger = logging.getLogger("KafkaConsumer")


class LogConsumer:
    """Async Kafka consumer: ingests logs, redacts PII, hands off to orchestrator."""

    def __init__(
        self,
        orchestrator,
        topic: str = "logs-raw",
        bootstrap_servers: str = "localhost:9092",
        group_id: str = "log-analyzer-group",
        redactor_profile: str = "financial",
    ):
        self.orchestrator = orchestrator
        self.topic = topic
        self.bootstrap_servers = bootstrap_servers
        self.group_id = group_id

        try:
            from processing.redactor import LogRedactor
        except Exception:
            logger.warning("Primary redactor unavailable; falling back to null redactor.")
            from processing.redactor_null import LogRedactor

        self.redactor = LogRedactor(profile=redactor_profile)
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
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
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
            async for msg in self.consumer:
                if not self._running:
                    break
                try:
                    clean_log = self.redactor.redact_log(msg.value)
                    await self.orchestrator.ingest_single_log(clean_log)
                except json.JSONDecodeError:
                    logger.warning(f"Skipping malformed JSON at offset {msg.offset}")
                except Exception as e:
                    logger.error(f"Error processing message at offset {msg.offset}: {e}")
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