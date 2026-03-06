from typing import List, Dict, Any, Optional

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
                    pass
        
        # 2. Save to Delta Lake (ACID Transaction)
        self.storage.save_logs([processed_log])
        
        # 3. Index in Vector DB
        self.vector_store.add_logs([processed_log])
        
        return processed_log

    async def ingest_logs(self, raw_logs: List[Dict[str, Any]]):
        """Full pipeline ingestion for batch logs."""
        results = []
        for log in raw_logs:
            res = await self.ingest_single_log(log)
            results.append(res)
            
        return {"status": "success", "count": len(results)}

    async def analyze_query(self, query: str):
        """Agentic analysis."""
        # Note: Analysis is usually compute-intensive, we keep it async for the API
        return self.engine.analyze(query)
