from typing import List, Dict, Any
from engine.analyzer import LogAnalysisEngine
from processing.enricher import LogEnricher
from storage.lake_mock import DeltaLakeStorage
from vector_db.store import VectorStore

class SystemOrchestrator:
    """
    Connects all modules: Ingestion -> Processing -> Storage -> Engine.
    """
    def __init__(self, gemini_api_key: str):
        self.enricher = LogEnricher()
        self.storage = DeltaLakeStorage()
        self.vector_store = VectorStore()
        self.engine = LogAnalysisEngine(gemini_api_key)

    async def ingest_single_log(self, raw_log: Dict[str, Any]):
        """Runs a single log through the full pipeline."""
        # 1. Process (Redact & Enrich)
        processed_log = self.enricher.process_log(raw_log)
        
        # 2. Save to Delta Lake (Async in the future, currently mock sync)
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
