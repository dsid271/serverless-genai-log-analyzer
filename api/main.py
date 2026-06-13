from fastapi import FastAPI, Request, Depends
from api.orchestrator import SystemOrchestrator
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
from dotenv import load_dotenv
from contextlib import asynccontextmanager
from core.plugin_registry import PluginRegistry, PluginSpec
from core.plugin_loader import load_plugins
from core.event_bus import EventBus
from core.incident_store import IncidentStore
from core.analyzer_runner import AnalyzerRunner

import structlog
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from api.auth import require_role, User
from api.rate_limit import limiter, rate_limit_default, rate_limit_ingest, rate_limit_analyze
from api.middleware import AuditLoggingMiddleware
from api.audit import audit_logger
load_dotenv()

def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}

def _env_csv(name: str) -> list[str]:
    val = os.getenv(name, "")
    parts = [p.strip() for p in val.split(",")]
    return [p for p in parts if p]

def _build_orchestrator(event_bus: Optional[object] = None) -> SystemOrchestrator:
    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    redactor_profile = os.getenv("REDACTOR_PROFILE", "financial")

    try:
        from processing.redactor import LogRedactor as Redactor
    except Exception:
        from processing.redactor_null import LogRedactor as Redactor

    try:
        from vector_db.store import VectorStore as VStore
    except Exception:
        from vector_db.null_store import VectorStore as VStore

    try:
        from storage.lake import DeltaLakeStorage as Lake
    except Exception:
        try:
            from storage.lake_mock import DeltaLakeStorage as Lake
        except Exception:
            from storage.null_storage import DeltaLakeStorage as Lake

    try:
        from processing.enricher import LogEnricher as Enricher
    except Exception:
        Enricher = None

    try:
        from engine.analyzer import LogAnalysisEngine as Analyzer
        if not gemini_key:
            raise RuntimeError("Missing GEMINI_API_KEY")
    except Exception:
        from engine.null_analyzer import LogAnalysisEngine as Analyzer

    redactor = Redactor(profile=redactor_profile)
    vector_store = VStore()
    storage = Lake()
    enricher = Enricher(redactor=redactor) if Enricher is not None else None
    if enricher is None:
        from processing.enricher import LogEnricher as EnricherFallback
        enricher = EnricherFallback(redactor=redactor)

    engine = Analyzer(gemini_api_key=gemini_key, vector_store=vector_store)

    return SystemOrchestrator(
        enricher=enricher,
        storage=storage,
        vector_store=vector_store,
        engine=engine,
        event_bus=event_bus,
    )


event_bus = EventBus()
incident_bus = EventBus()
incident_store = IncidentStore()
orchestrator = _build_orchestrator(event_bus=event_bus)

plugin_registry = PluginRegistry()

# Register built-in plugins
plugin_registry.register(
    PluginSpec(
        name="kafka",
        kind="connector",
        factory=lambda: __import__("core.connectors.kafka_connector", fromlist=["KafkaConnector"]).KafkaConnector(
            orchestrator.ingest_single_log
        ),
    )
)

plugin_registry.register(
    PluginSpec(
        name="error_spike",
        kind="detector",
        factory=lambda: __import__("core.detectors.error_spike", fromlist=["ErrorSpikeDetector"]).ErrorSpikeDetector(
            event_bus,
            incident_store,
            incident_bus,
        ),
    )
)

plugin_registry.register(
    PluginSpec(
        name="simple_summary",
        kind="analyzer",
        factory=lambda: __import__("core.analyzers.simple_incident_summary", fromlist=["SimpleIncidentSummaryAnalyzer"]).SimpleIncidentSummaryAnalyzer(),
    )
)

plugin_registry.register(
    PluginSpec(
        name="gemini_triage",
        kind="analyzer",
        factory=lambda: __import__("core.analyzers.gemini_incident_triage", fromlist=["GeminiIncidentTriageAnalyzer"]).GeminiIncidentTriageAnalyzer(),
    )
)

load_plugins(plugin_registry)

# Global plugin-managed runners
_running_connectors: list[Any] = []
_running_detectors: list[Any] = []
_analyzer_runner: Optional[AnalyzerRunner] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- STARTUP ---
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
    
    global _running_connectors, _running_detectors, _analyzer_runner

    enabled_connectors = _env_csv("ENABLED_CONNECTORS")
    enabled_detectors = _env_csv("ENABLED_DETECTORS")
    enabled_analyzers = _env_csv("ENABLED_ANALYZERS")

    # Backward compatibility: ENABLE_KAFKA=true implies ENABLED_CONNECTORS includes kafka
    if _env_bool("ENABLE_KAFKA", default=False) and "kafka" not in enabled_connectors:
        enabled_connectors.append("kafka")

    for connector_name in enabled_connectors:
        spec = plugin_registry.get("connector", connector_name)
        if spec is None:
            continue

        try:
            connector = spec.factory()
            await connector.start()
            _running_connectors.append(connector)
        except Exception:
            # Individual connectors should not prevent the API from starting.
            pass

    if enabled_analyzers:
        try:
            _analyzer_runner = AnalyzerRunner(
                incident_bus=incident_bus,
                registry=plugin_registry,
                incident_store=incident_store,
                enabled_analyzers=enabled_analyzers,
            )
            await _analyzer_runner.start()
        except Exception:
            _analyzer_runner = None

    for detector_name in enabled_detectors:
        spec = plugin_registry.get("detector", detector_name)
        if spec is None:
            continue

        try:
            detector = spec.factory()
            await detector.start()
            _running_detectors.append(detector)
        except Exception:
            pass
    
    yield
    # --- SHUTDOWN ---
    for c in _running_connectors:
        try:
            await c.stop()
        except Exception:
            pass
    _running_connectors = []

    for d in _running_detectors:
        try:
            await d.stop()
        except Exception:
            pass
    _running_detectors = []

    if _analyzer_runner is not None:
        try:
            await _analyzer_runner.stop()
        except Exception:
            pass
        _analyzer_runner = None

app = FastAPI(
    title="GenAI Log Analyzer",
    description="Serverless log analysis platform with agentic AI insights.",
    version="0.1.0",
    lifespan=lifespan
)

app.state.plugin_registry = plugin_registry
app.state.incident_store = incident_store
app.state.limiter = limiter

app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(AuditLoggingMiddleware)

class LogIngestRequest(BaseModel):
    logs: List[Dict[str, Any]]

class AnalysisRequest(BaseModel):
    query: str

@app.post("/ingest", tags=["Ingestion"])
@limiter.limit(rate_limit_ingest)
async def ingest_logs(request: Request, body: LogIngestRequest, user: User = Depends(require_role("admin", "analyst"))):
    """Manual API ingestion route (for fallback)."""
    return await orchestrator.ingest_logs(body.logs)

@app.post("/analyze", tags=["Analysis"])
@limiter.limit(rate_limit_analyze)
async def analyze_logs(request: Request, body: AnalysisRequest, user: User = Depends(require_role("admin", "analyst"))):
    """Run agentic RAG analysis on the log store."""
    return await orchestrator.analyze_query(body.query)

@app.get("/", tags=["Health"])
async def root():
    kafka_connected = False
    for c in _running_connectors:
        consumer = getattr(c, "_consumer", None)
        if consumer is not None and getattr(consumer, "_running", False):
            kafka_connected = True
            break

    return {
        "status": "online",
        "kafka_connected": kafka_connected,
        "message": "GenAI Log Analyzer API is running."
    }


@app.get("/plugins", tags=["Plugins"])
@limiter.limit(rate_limit_default)
async def list_plugins(request: Request, user: User = Depends(require_role("admin", "analyst", "viewer"))):
    registry = getattr(app.state, "plugin_registry", None)
    if registry is None:
        return {"plugins": []}

    plugins = []
    for p in registry.list():
        plugins.append({"name": p.name, "kind": p.kind})
    plugins.sort(key=lambda x: (x["kind"], x["name"]))
    return {"plugins": plugins}


@app.get("/incidents", tags=["Incidents"])
@limiter.limit(rate_limit_default)
async def list_incidents(request: Request, limit: int = 50, user: User = Depends(require_role("admin", "analyst", "viewer"))):
    store = getattr(app.state, "incident_store", None)
    if store is None:
        return {"incidents": []}
    return {"incidents": store.list(limit=limit)}

class SearchRequest(BaseModel):
    query: str
    limit: int = 10
    filters: Optional[Dict[str, Any]] = None

@app.post("/search", tags=["Search"])
@limiter.limit(rate_limit_default)
async def search_logs(request: Request, body: SearchRequest, user: User = Depends(require_role("admin", "analyst"))):
    results = orchestrator.search(body.query, body.limit, body.filters)
    return {"results": results, "count": len(results)}

@app.get("/summary", tags=["Summary"])
@limiter.limit(rate_limit_default)
async def get_summary(
    request: Request,
    service: Optional[str] = None,
    granularity: str = "hourly",
    date: Optional[str] = None,
    user: User = Depends(require_role("admin", "analyst", "viewer"))
):
    return orchestrator.get_summary(service, granularity, date)

@app.get("/audit-trail", tags=["Audit"])
@limiter.limit(rate_limit_default)
async def get_audit_trail(
    request: Request,
    user_filter: Optional[str] = None,
    limit: int = 100,
    user: User = Depends(require_role("admin"))
):
    return {"events": audit_logger.query(user_filter=user_filter, limit=limit)}
