from fastapi import FastAPI, BackgroundTasks, HTTPException
from api.orchestrator import SystemOrchestrator
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import asyncio
from ingestion.kafka_consumer import LogConsumer
from dotenv import load_dotenv

# Load .env file at the very start
load_dotenv()

from contextlib import asynccontextmanager

# Initialize Orchestrator
gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
orchestrator = SystemOrchestrator(gemini_key)

# Global Kafka Consumer
kafka_consumer: Optional[LogConsumer] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- STARTUP ---
    global kafka_consumer
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    
    kafka_consumer = LogConsumer(
        topic="logs-raw",
        bootstrap_servers=bootstrap_servers,
        group_id="log-analyzer-group"
    )
    
    # Start consumer in a background task
    asyncio.create_task(kafka_consumer.start(on_message_callback=orchestrator.ingest_single_log))
    
    yield
    # --- SHUTDOWN ---
    if kafka_consumer:
        await kafka_consumer.stop()

app = FastAPI(
    title="GenAI Log Analyzer",
    description="Serverless log analysis platform with agentic AI insights.",
    version="0.1.0",
    lifespan=lifespan
)

class LogIngestRequest(BaseModel):
    logs: List[Dict[str, Any]]

class AnalysisRequest(BaseModel):
    query: str

@app.post("/ingest", tags=["Ingestion"])
async def ingest_logs(request: LogIngestRequest):
    """Manual API ingestion route (for fallback)."""
    return orchestrator.ingest_logs(request.logs)

@app.post("/analyze", tags=["Analysis"])
async def analyze_logs(request: AnalysisRequest):
    """Run agentic RAG analysis on the log store."""
    return orchestrator.analyze_query(request.query)

@app.get("/", tags=["Health"])
async def root():
    return {
        "status": "online",
        "kafka_connected": bool(kafka_consumer and kafka_consumer._running),
        "message": "GenAI Log Analyzer API is running."
    }
