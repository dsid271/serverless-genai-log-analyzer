import asyncio
import json
import logging
from aiokafka import AIOKafkaConsumer
from processing.redactor import LogRedactor
from typing import Optional, Callable, Dict, Any

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("KafkaConsumer")

class LogConsumer:
    """
    Asynchronous Kafka consumer that ingests logs from a topic,
    redacts PII, and passes them to a processor or storage.
    """
    def __init__(
        self, 
        topic: str = "logs-raw", 
        bootstrap_servers: str = "localhost:9092",
        group_id: str = "log-analyzer-group",
        redactor_profile: str = "financial"
    ):
        self.topic = topic
        self.bootstrap_servers = bootstrap_servers
        self.group_id = group_id
        self.redactor = LogRedactor(profile=redactor_profile)
        self.consumer: Optional[AIOKafkaConsumer] = None
        self._running = False

    async def start(self, on_message_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        """
        Starts the Kafka consumer loop with graceful failure.
        """
        self.consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            request_timeout_ms=5000  # Fail fast
        )
        
        try:
            await self.consumer.start()
            self._running = True
            logger.info(f"--- Kafka Consumer Connected (Topic: {self.topic}) ---")
        except Exception as e:
            logger.error(f"Failed to connect to Kafka at {self.bootstrap_servers}: {e}")
            logger.warning("API will run without real-time Kafka ingestion.")
            return

        try:
            async for msg in self.consumer:
                if not self._running:
                    break
                
                raw_log = msg.value
                # logger.info(f"Received log from {raw_log.get('source', 'unknown')}")
                
                # 1. Redact PII
                clean_log = self.redactor.redact_log(raw_log)
                
                # 2. Hand over to the rest of the system
                if on_message_callback:
                    if asyncio.iscoroutinefunction(on_message_callback):
                        await on_message_callback(clean_log)
                    else:
                        on_message_callback(clean_log)
                else:
                    logger.info(f"Redacted Log: {clean_log}")
                    
        except Exception as e:
            logger.error(f"Error in Kafka consumer loop: {e}")
        finally:
            await self.stop()

    async def stop(self):
        """Stops the Kafka consumer."""
        self._running = False
        if self.consumer:
            await self.consumer.stop()
            logger.info("--- Kafka Consumer Stopped ---")

if __name__ == "__main__":
    # Test runner (Requires a running Kafka broker)
    consumer = LogConsumer()
    try:
        asyncio.run(consumer.start())
    except KeyboardInterrupt:
        pass
