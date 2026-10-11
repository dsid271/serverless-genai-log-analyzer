import asyncio
import logging
import os
import threading
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class SystemOrchestrator:
    """
    Connects all modules: Ingestion -> Processing -> Storage -> Engine.
    Now Uses Dependency Injection for High Modularity.
    """
    def __init__(
        self, 
        enricher,
        storage,
        vector_store,
        engine,
        event_bus: Optional[object] = None
    ):
        self.enricher = enricher
        self.storage = storage
        self.vector_store = vector_store
        self.engine = engine
        self.event_bus = event_bus
        # Embedding is the slowest step (~0.3s/log on CPU), so batches are indexed
        # in the background, one at a time, in fixed-size chunks.
        self._index_lock = threading.Lock()
        self._index_chunk = int(os.getenv("VECTOR_INDEX_CHUNK", "64"))
        self._index_tasks: set = set()
        # "pattern" embeds one example per message pattern (re-embedded after the TTL);
        # "all" embeds every log. Delta Lake always stores every log either way.
        self._index_mode = os.getenv("VECTOR_INDEX_MODE", "pattern").strip().lower()
        if self._index_mode not in ("pattern", "all"):
            raise ValueError(f"VECTOR_INDEX_MODE must be 'pattern' or 'all', got {self._index_mode!r}")
        self._sampler = None
        if self._index_mode == "pattern":
            from processing.log_pattern import PatternSampler
            self._sampler = PatternSampler(
                ttl_seconds=float(os.getenv("VECTOR_PATTERN_TTL_SECONDS", "3600")),
                max_patterns=int(os.getenv("VECTOR_PATTERN_MAX", "100000")),
            )

    def _select_for_index(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self._sampler.select(logs) if self._sampler is not None else logs

    async def ingest_single_log(self, raw_log: Dict[str, Any]):
        """Runs a single log through the full pipeline."""
        # 1. Process (Redact & Enrich)
        processed_log = self.enricher.process_log(raw_log)

        if self.event_bus is not None:
            publish = getattr(self.event_bus, "publish", None)
            if callable(publish):
                try:
                    await publish(processed_log)
                except Exception:
                    # Detectors are best-effort; ingestion continues, but log why.
                    logger.exception("event_bus publish failed during ingestion")
        
        # 2. Save to Delta Lake (ACID Transaction)
        self.storage.save_logs([processed_log])
        
        # 3. Index in Vector DB
        to_index = self._select_for_index([processed_log])
        if to_index:
            self.vector_store.add_logs(to_index)

        return processed_log

    def _index_sync(self, logs: List[Dict[str, Any]]) -> None:
        with self._index_lock:
            # Pattern matching runs here, in the worker thread, not on the event loop.
            logs = self._select_for_index(logs)
            for i in range(0, len(logs), self._index_chunk):
                try:
                    self.vector_store.add_logs(logs[i:i + self._index_chunk])
                except Exception:
                    logger.exception("vector indexing failed for %d logs", len(logs[i:i + self._index_chunk]))

    def _schedule_index(self, logs: List[Dict[str, Any]]) -> None:
        task = asyncio.create_task(asyncio.to_thread(self._index_sync, logs))
        self._index_tasks.add(task)
        task.add_done_callback(self._index_tasks.discard)

    async def ingest_logs(self, raw_logs: List[Dict[str, Any]]):
        """Full pipeline ingestion for a batch of logs.

        Redaction and the Delta Lake commit run once per batch in a worker
        thread before the response. Chroma indexing runs afterwards in the
        background, so semantic search sees new logs shortly after ingest
        returns rather than immediately.
        """
        if not raw_logs:
            return {"status": "success", "count": 0, "contains_pii": False}

        processed = await asyncio.to_thread(self.enricher.process_logs, raw_logs)

        publish = getattr(self.event_bus, "publish", None) if self.event_bus is not None else None
        if callable(publish):
            for log in processed:
                try:
                    await publish(log)
                except Exception:
                    # Detectors are best-effort; ingestion continues, but log why.
                    logger.exception("event_bus publish failed during ingestion")

        await asyncio.to_thread(self.storage.save_logs, processed)
        self._schedule_index(processed)

        contains_pii = any(bool(log.get("contains_pii", False)) for log in processed)
        return {
            "status": "success",
            "count": len(processed),
            "contains_pii": contains_pii,
            "vector_index": "queued",
            "pending_index_batches": len(self._index_tasks),
        }

    async def analyze_query(self, query: str):
        """Agentic analysis."""
        # engine.analyze() makes blocking LLM calls (sync .invoke()); run it in a
        # worker thread so it doesn't stall the event loop for other requests.
        return await asyncio.to_thread(self.engine.analyze, query)

    def search(self, query: str, limit: int = 10, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return self.vector_store.search_logs(query, limit, filters)

    def get_summary(self, service: Optional[str] = None, granularity: str = "hourly", date: Optional[str] = None) -> Dict[str, Any]:
        return self.storage.get_summary(service, granularity, date)
