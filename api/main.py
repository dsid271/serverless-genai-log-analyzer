from fastapi import FastAPI, Request, Depends, Response, HTTPException
from api.orchestrator import SystemOrchestrator
from pydantic import BaseModel, Field
from typing import Literal, List, Dict, Any, Optional
import json
import os
import time
import logging
from dotenv import load_dotenv
from contextlib import asynccontextmanager
from core.plugin_registry import PluginRegistry, PluginSpec
from core.plugin_loader import load_plugins
from core.event_bus import EventBus
from core.incident_store import IncidentStore, STATUSES
from core.analyzer_runner import AnalyzerRunner
from core.knowledge import KINDS as KNOWLEDGE_KINDS, KnowledgeBase
from core.ticketing import TicketDispatcher
from core.triage import TriageService, VERDICTS
from core.severity import LEVELS
from datetime import datetime

import structlog
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from api.auth import require_scope, User, _auth_enabled
from api.key_store import PROFILES, get_key_store
from api.rate_limit import limiter, rate_limit_default, rate_limit_ingest, rate_limit_analyze
from api.middleware import AuditLoggingMiddleware
from api.audit import audit_logger
from api.metrics import record_ingestion, record_pii_rule_counts, render_latest
from fastapi.responses import FileResponse
from processing.format_profiles import DEFAULT_PROFILE, get_normalizer
load_dotenv()

logger = logging.getLogger(__name__)

class Triage(BaseModel):
    severity: Literal["low", "medium", "high"]
    hypotheses: List[str] = Field(max_length=3)
    mitigations: List[str] = Field(max_length=3)
    next_steps: List[str] = Field(max_length=3)
    impact: str = Field(max_length=200)
    
def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}

def _env_csv(name: str) -> list[str]:
    val = os.getenv(name, "")
    parts = [p.strip() for p in val.split(",")]
    return [p for p in parts if p]

_AUDIT_TEXT_MAX = 500

def _audit_text(text: Any) -> str:
    """Redacted, truncated copy of free text for the audit trail.

    Search queries and prompts can contain PII, so the rule tier (cards, SSNs, emails, approved
    learned entities) is applied first. NER is skipped on purpose: `redact_text` would feed
    these strings into the learned-entity store, which is meant for ingested logs only.
    """
    try:
        redacted, _ = orchestrator.enricher.redactor.rules.apply(str(text or ""))
    except Exception:
        logger.exception("audit redaction failed; text omitted from the audit event")
        return "[OMITTED: redaction failed]"
    return redacted[:_AUDIT_TEXT_MAX]

def _build_orchestrator(event_bus: Optional[object] = None) -> SystemOrchestrator:
    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    redactor_profile = os.getenv("REDACTOR_PROFILE", "financial")

    # No fallbacks: a missing dependency must stop startup rather than
    # silently storing unredacted logs or returning fabricated results.
    from processing.redactor import LogRedactor
    from processing.enricher import LogEnricher
    from processing.ip_intel import IpIntel
    from storage.lake import DeltaLakeStorage
    from vector_db.store import VectorStore

    try:
        redactor = LogRedactor(profile=redactor_profile)
    except SystemExit as e:
        # spaCy's model auto-downloader (presidio's SpacyNlpEngine.load) calls
        # sys.exit(1) on a failed download; surface it as a normal startup error.
        raise RuntimeError(f"PII redactor failed to initialise: {e}") from e

    vector_store = VectorStore()
    storage = DeltaLakeStorage()
    enricher = LogEnricher(redactor=redactor, ip_intel=IpIntel.from_env())

    engine = None
    if gemini_key:
        from engine.analyzer import LogAnalysisEngine
        engine = LogAnalysisEngine(gemini_api_key=gemini_key, vector_store=vector_store)
    else:
        logger.warning("GEMINI_API_KEY not set; POST /analyze will return 503")

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
knowledge_base = KnowledgeBase()
ticket_dispatcher = TicketDispatcher.from_env(incident_store)
triage = TriageService(
    incident_store,
    knowledge=knowledge_base,
    on_change=ticket_dispatcher.notify if ticket_dispatcher is not None else None,
)
orchestrator = _build_orchestrator(event_bus=event_bus)

plugin_registry = PluginRegistry()


def _make_ingest_callback(channel: str, format_profile: Optional[str] = None):
    """Wraps orchestrator.ingest_logs so streaming connectors report per-source
    ingestion counters, same as the /ingest route. Takes a batch of logs.

    `format_profile` (processing/format_profiles.yaml) maps the platform's field
    names onto the internal schema first; an unknown name fails at startup."""
    normalizer = get_normalizer()
    format_profile = format_profile or DEFAULT_PROFILE
    if not normalizer.has(format_profile):
        raise ValueError(f"unknown format profile {format_profile!r}; available: {normalizer.names()}")

    async def _callback(raw_logs):
        raw_logs = normalizer.normalize_batch(raw_logs, format_profile)
        result = await orchestrator.ingest_logs(raw_logs)
        record_ingestion(
            channel=channel,
            sources=[log.get("source") for log in raw_logs],
            contains_pii=bool(result.get("contains_pii", False)),
        )
        return result
    return _callback


# Register built-in plugins
plugin_registry.register(
    PluginSpec(
        name="kafka",
        kind="connector",
        factory=lambda: __import__("core.connectors.kafka_connector", fromlist=["KafkaConnector"]).KafkaConnector(
            _make_ingest_callback("kafka", os.getenv("KAFKA_FORMAT_PROFILE") or os.getenv("LOG_FORMAT_PROFILE"))
        ),
    )
)

plugin_registry.register(
    PluginSpec(
        name="spark_candidates",
        kind="connector",
        factory=lambda: __import__("core.connectors.candidates_connector", fromlist=["build_candidates_connector"]).build_candidates_connector(
            triage,
            incident_bus,
        ),
    )
)

plugin_registry.register(
    PluginSpec(
        name="error_spike",
        kind="detector",
        factory=lambda: __import__("core.detectors.error_spike", fromlist=["ErrorSpikeDetector"]).ErrorSpikeDetector(
            event_bus,
            triage,
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
        factory=lambda: __import__("core.analyzers.gemini_incident_triage", fromlist=["GeminiIncidentTriageAnalyzer"]).GeminiIncidentTriageAnalyzer(
            knowledge=knowledge_base
        ),
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

    if not _auth_enabled():
        logger.warning(
            "AUTH IS OFF: ENABLE_AUTH is not true, so every caller is an anonymous admin. "
            "Set ENABLE_AUTH=true and issue keys with scripts/manage_keys.py before exposing this API."
        )

    if ticket_dispatcher is not None:
        ticket_dispatcher.start()

    enabled_connectors = _env_csv("ENABLED_CONNECTORS")
    enabled_detectors = _env_csv("ENABLED_DETECTORS")
    enabled_analyzers = _env_csv("ENABLED_ANALYZERS")

    # Backward compatibility: ENABLE_KAFKA=true implies ENABLED_CONNECTORS includes kafka
    if _env_bool("ENABLE_KAFKA", default=False) and "kafka" not in enabled_connectors:
        enabled_connectors.append("kafka")

    for connector_name in enabled_connectors:
        spec = plugin_registry.get("connector", connector_name)
        if spec is None:
            logger.warning("Enabled connector %r is not registered; skipping", connector_name)
            continue

        try:
            connector = spec.factory()
            await connector.start()
            _running_connectors.append(connector)
        except Exception:
            # Individual connectors should not prevent the API from starting,
            # but the failure must be visible.
            logger.exception("Connector %r failed to start", connector_name)

    if enabled_analyzers:
        try:
            _analyzer_runner = AnalyzerRunner(
                incident_bus=incident_bus,
                registry=plugin_registry,
                triage=triage,
                enabled_analyzers=enabled_analyzers,
            )
            await _analyzer_runner.start()
        except Exception:
            logger.exception("Analyzer runner failed to start; incidents will not be analyzed")
            _analyzer_runner = None

    for detector_name in enabled_detectors:
        spec = plugin_registry.get("detector", detector_name)
        if spec is None:
            logger.warning("Enabled detector %r is not registered; skipping", detector_name)
            continue

        try:
            detector = spec.factory()
            await detector.start()
            _running_detectors.append(detector)
        except Exception:
            logger.exception("Detector %r failed to start", detector_name)

    yield
    # --- SHUTDOWN ---
    for c in _running_connectors:
        try:
            await c.stop()
        except Exception:
            logger.exception("Connector failed to stop cleanly")
    _running_connectors = []

    for d in _running_detectors:
        try:
            await d.stop()
        except Exception:
            logger.exception("Detector failed to stop cleanly")
    _running_detectors = []

    if _analyzer_runner is not None:
        try:
            await _analyzer_runner.stop()
        except Exception:
            logger.exception("Analyzer runner failed to stop cleanly")
        _analyzer_runner = None

    if ticket_dispatcher is not None:
        ticket_dispatcher.stop()

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
    # Name from processing/format_profiles.yaml; defaults to LOG_FORMAT_PROFILE or "generic".
    format: Optional[str] = Field(default=None, max_length=100)

class AnalysisRequest(BaseModel):
    query: str

@app.post("/ingest", tags=["Ingestion"])
@limiter.limit(rate_limit_ingest)
async def ingest_logs(request: Request, body: LogIngestRequest, user: User = Depends(require_scope("logs:ingest"))):
    """Manual API ingestion route (for fallback)."""
    normalizer = get_normalizer()
    profile = body.format or os.getenv("LOG_FORMAT_PROFILE") or DEFAULT_PROFILE
    if not normalizer.has(profile):
        raise HTTPException(status_code=400, detail=f"Unknown format profile {profile!r}. Available: {normalizer.names()}")
    logs = normalizer.normalize_batch(body.logs, profile)
    response = await orchestrator.ingest_logs(logs)
    request.state.results_count = response.get("count", 0)
    contains_pii = bool(response.get("contains_pii", False))
    request.state.pii_accessed = contains_pii
    request.state.contains_pii = contains_pii
    record_ingestion(channel="api", sources=[log.get("source") for log in logs], contains_pii=contains_pii)
    return response

@app.post("/analyze", tags=["Analysis"])
@limiter.limit(rate_limit_analyze)
async def analyze_logs(request: Request, body: AnalysisRequest, user: User = Depends(require_scope("analyze:run"))):
    """Run agentic RAG analysis on the log store."""
    if orchestrator.engine is None:
        raise HTTPException(status_code=503, detail="Analysis unavailable: GEMINI_API_KEY is not configured.")
    prompt = _audit_text(body.query)
    request.state.audit_detail = f"prompt={prompt}"  # kept even if the analysis fails
    result = await orchestrator.analyze_query(body.query)
    if isinstance(result, dict):
        request.state.results_count = len(result.get("documents") or [])
        request.state.audit_detail = f"prompt={prompt} | response={_audit_text(result.get('generation'))}"
    return result

@app.get("/metrics", tags=["Observability"], include_in_schema=False)
async def metrics():
    """Prometheus scrape endpoint. Returns a plain-text disabled notice if
    `prometheus_client` isn't installed (see api/metrics.py)."""
    store = _pii_rule_store()
    if store is not None:
        record_pii_rule_counts(store.counts())
    body, content_type = render_latest()
    return Response(content=body, media_type=content_type)


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
async def list_plugins(request: Request, user: User = Depends(require_scope("plugins:read"))):
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
async def list_incidents(
    request: Request,
    limit: int = 50,
    status: Optional[str] = None,
    team: Optional[str] = None,
    user: User = Depends(require_scope("incidents:read")),
):
    if status is not None and status not in STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {list(STATUSES)}")
    return {"incidents": incident_store.list(limit=limit, status=status, team=team)}


@app.get("/incidents/{incident_id}", tags=["Incidents"])
@limiter.limit(rate_limit_default)
async def get_incident(request: Request, incident_id: str, user: User = Depends(require_scope("incidents:read"))):
    inc = incident_store.get(incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {
        **inc.to_dict(),
        "analyses": incident_store.analyses(incident_id),
        "feedback": incident_store.list_feedback(incident_id=incident_id),
        "tickets": list(incident_store.tickets(incident_id).values()),
    }


class FeedbackRequest(BaseModel):
    verdict: Optional[Literal[VERDICTS]] = None  # type: ignore[valid-type]
    reassign_team: Optional[str] = Field(default=None, max_length=100)
    severity_override: Optional[Literal[LEVELS]] = None  # type: ignore[valid-type]
    note: Optional[str] = Field(default=None, max_length=4000)


@app.post("/incidents/{incident_id}/feedback", tags=["Incidents"])
@limiter.limit(rate_limit_default)
async def submit_feedback(
    request: Request,
    incident_id: str,
    body: FeedbackRequest,
    user: User = Depends(require_scope("incidents:feedback")),
):
    """Mark false positive / resolved / reopen, re-route, or override severity. Every change is recorded."""
    try:
        inc, record = triage.apply_feedback(
            incident_id,
            submitted_by=request.state.user_identity,
            verdict=body.verdict,
            reassign_team=body.reassign_team,
            severity_override=body.severity_override,
            note=body.note,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Incident not found.")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"incident": inc.to_dict(), "feedback": record}


@app.get("/feedback", tags=["Incidents"])
@limiter.limit(rate_limit_default)
async def list_feedback(request: Request, limit: int = 100, user: User = Depends(require_scope("incidents:read"))):
    """Operator feedback history (false positives, re-routes, overrides) for review and tuning."""
    return {"feedback": incident_store.list_feedback(limit=limit)}


class DeploymentEvent(BaseModel):
    service: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=200)
    environment: str = Field(default="production", max_length=50)
    deployed_at: Optional[datetime] = None
    commit_sha: Optional[str] = Field(default=None, max_length=64)
    url: Optional[str] = Field(default=None, max_length=500)


@app.post("/events/deployments", tags=["Change events"], status_code=201)
@limiter.limit(rate_limit_default)
async def record_deployment(request: Request, body: DeploymentEvent, user: User = Depends(require_scope("events:write"))):
    """Webhook for CI/CD: records a deployment and links it to open incidents on that service."""
    deployed_at = body.deployed_at.timestamp() if body.deployed_at else time.time()
    record = incident_store.add_deployment(
        body.service, body.version, body.environment, deployed_at, body.commit_sha, body.url
    )
    return {"deployment": record, "linked_incidents": triage.relink_deployment(body.service, deployed_at)}


@app.get("/deployments", tags=["Change events"])
@limiter.limit(rate_limit_default)
async def list_deployments(
    request: Request, limit: int = 50, service: Optional[str] = None,
    user: User = Depends(require_scope("incidents:read")),
):
    return {"deployments": incident_store.list_deployments(limit=limit, service=service)}


class KnowledgeDoc(BaseModel):
    kind: Literal[KNOWLEDGE_KINDS]  # type: ignore[valid-type]
    title: str = Field(min_length=1, max_length=300)
    content: str = Field(min_length=1, max_length=50000)
    services: List[str] = Field(default_factory=list, max_length=50)
    url: Optional[str] = Field(default=None, max_length=500)


@app.post("/knowledge", tags=["Knowledge"], status_code=201)
@limiter.limit(rate_limit_default)
async def add_knowledge(request: Request, body: KnowledgeDoc, user: User = Depends(require_scope("knowledge:write"))):
    """Add or replace (same kind + title) a runbook, postmortem or security reference used to enrich incident triage."""
    return knowledge_base.add(body.kind, body.title, body.content, services=body.services, url=body.url)


@app.get("/knowledge", tags=["Knowledge"])
@limiter.limit(rate_limit_default)
async def list_knowledge(
    request: Request, limit: int = 100, q: Optional[str] = None,
    user: User = Depends(require_scope("incidents:read")),
):
    if q:
        return {"documents": knowledge_base.search(q, limit=min(limit, 20))}
    return {"documents": knowledge_base.list(limit=limit)}


@app.delete("/knowledge/{doc_id}", tags=["Knowledge"])
@limiter.limit(rate_limit_default)
async def delete_knowledge(request: Request, doc_id: str, user: User = Depends(require_scope("knowledge:write"))):
    if not knowledge_base.delete(doc_id):
        raise HTTPException(status_code=404, detail="Document not found.")
    return {"id": doc_id, "deleted": True}

class SearchRequest(BaseModel):
    query: str
    limit: int = 10
    filters: Optional[Dict[str, Any]] = None

@app.post("/search", tags=["Search"])
@limiter.limit(rate_limit_default)
async def search_logs(request: Request, body: SearchRequest, user: User = Depends(require_scope("logs:search"))):
    detail = f"query={_audit_text(body.query)} limit={body.limit}"
    if body.filters:
        detail += f" filters={_audit_text(json.dumps(body.filters, default=str, sort_keys=True))}"
    request.state.audit_detail = detail
    results = orchestrator.search(body.query, body.limit, body.filters)
    request.state.results_count = len(results)
    return {"results": results, "count": len(results)}

@app.get("/summary", tags=["Summary"])
@limiter.limit(rate_limit_default)
async def get_summary(
    request: Request,
    service: Optional[str] = None,
    granularity: str = "hourly",
    date: Optional[str] = None,
    user: User = Depends(require_scope("summary:read"))
):
    if granularity not in {"hourly", "daily"}:
        raise HTTPException(status_code=400, detail="granularity must be 'hourly' or 'daily'")
    return orchestrator.get_summary(service, granularity, date)

@app.get("/audit-trail", tags=["Audit"])
@limiter.limit(rate_limit_default)
async def get_audit_trail(
    request: Request,
    user_filter: Optional[str] = None,
    limit: int = 100,
    user: User = Depends(require_scope("audit:read"))
):
    return {"events": audit_logger.query(user_filter=user_filter, limit=limit)}


class KeyIssueRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    profile: str
    ttl_days: Optional[int] = Field(default=None, gt=0, le=3650)


@app.get("/admin/integrations", tags=["Admin"])
@limiter.limit(rate_limit_default)
async def integrations_status(request: Request, user: User = Depends(require_scope("keys:admin"))):
    """Which ticketing providers and IP enrichment sources are configured. No credentials are returned."""
    ip_intel = getattr(orchestrator.enricher, "ip_intel", None)
    return {
        "ticketing": ticket_dispatcher.status() if ticket_dispatcher is not None else None,
        "ip_intel": ip_intel.status() if ip_intel is not None else None,
    }


@app.get("/admin/profiles", tags=["Admin"])
@limiter.limit(rate_limit_default)
async def list_key_profiles(request: Request, user: User = Depends(require_scope("keys:admin"))):
    return {
        "profiles": [
            {"profile": name, "scopes": sorted(scopes), "default_ttl_days": ttl}
            for name, (scopes, ttl) in sorted(PROFILES.items())
        ]
    }


@app.post("/admin/keys", tags=["Admin"], status_code=201)
@limiter.limit(rate_limit_default)
async def issue_api_key(request: Request, body: KeyIssueRequest, user: User = Depends(require_scope("keys:admin"))):
    """Issue a key for a profile. The plaintext key is returned once and never stored.

    Requires ENABLE_AUTH=true: with auth off any caller is anonymous, and a key minted then
    would stay valid after auth is turned on. Use scripts/manage_keys.py instead."""
    if user.key_id is None:
        raise HTTPException(
            status_code=403,
            detail="Issuing keys over the API requires ENABLE_AUTH=true. Use scripts/manage_keys.py.",
        )
    try:
        raw_key, record = get_key_store().issue(
            body.name, body.profile, body.ttl_days, issued_by=request.state.user_identity,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"api_key": raw_key, **record.to_dict()}


@app.get("/admin/keys", tags=["Admin"])
@limiter.limit(rate_limit_default)
async def list_api_keys(request: Request, include_revoked: bool = False, user: User = Depends(require_scope("keys:admin"))):
    return {"keys": [r.to_dict() for r in get_key_store().list(include_revoked=include_revoked)]}


@app.delete("/admin/keys/{key_id}", tags=["Admin"])
@limiter.limit(rate_limit_default)
async def revoke_api_key(request: Request, key_id: str, user: User = Depends(require_scope("keys:admin"))):
    if not get_key_store().revoke(key_id):
        raise HTTPException(status_code=404, detail="Key not found or already revoked.")
    return {"key_id": key_id, "revoked": True}


def _pii_rule_store():
    """Writable rule store of the API's redactor, or None when suggestions are off."""
    redactor = getattr(orchestrator.enricher, "redactor", None)
    store = getattr(redactor, "pii_rules", None)
    return store if store is not None and not store.read_only else None


def _require_pii_rule_store():
    store = _pii_rule_store()
    if store is None:
        raise HTTPException(status_code=503, detail="PII rule suggestions are disabled (PII_RULE_SUGGESTIONS).")
    return store


def _learned_store():
    """Writable learned-entity store of the API's redactor, or None when PII_LEARNING is off."""
    redactor = getattr(orchestrator.enricher, "redactor", None)
    store = getattr(redactor, "learned", None)
    return store if store is not None and not store.read_only else None


class PiiRuleDecision(BaseModel):
    ids: List[str] = Field(min_length=1, max_length=500)
    status: Literal["approved", "rejected", "pending"]


@app.get("/admin/pii-rules", tags=["Admin"])
@limiter.limit(rate_limit_default)
async def list_pii_rules(
    request: Request,
    status: Optional[str] = "pending",
    limit: int = 100,
    kind: Literal["template", "entity"] = "template",
    user: User = Depends(require_scope("pii:admin")),
):
    """Suggested PII rules. `status`: collecting, pending, approved, rejected, or all.

    `kind=template` (default) lists message-shape suggestions; `kind=entity` lists learned
    entities (only when PII_LEARNING is on). Both are decided at /admin/pii-rules/decisions."""
    from processing.pii_rules import STATUSES as RULE_STATUSES
    if kind == "entity":
        store = _learned_store()
        if store is None:
            raise HTTPException(status_code=503, detail="Learned entities are disabled (PII_LEARNING).")
    else:
        store = _require_pii_rule_store()
    if status == "all":
        status = None
    elif status not in RULE_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be 'all' or one of {list(RULE_STATUSES)}")
    return {"rules": store.list(status=status, limit=limit), "counts": store.counts()}


@app.post("/admin/pii-rules/decisions", tags=["Admin"])
@limiter.limit(rate_limit_default)
async def decide_pii_rules(request: Request, body: PiiRuleDecision, user: User = Depends(require_scope("pii:admin"))):
    """Approve, reject or reset (`pending`) suggestions and learned entities by id.
    Approved rules apply in the rule tier (API and Spark)."""
    stores = [s for s in (_pii_rule_store(), _learned_store()) if s is not None]
    if not stores:
        raise HTTPException(status_code=503, detail="PII rule suggestions are disabled (PII_RULE_SUGGESTIONS).")
    rules: List[Dict[str, Any]] = []
    for store in stores:
        rules += store.decide(body.ids, body.status, by=request.state.user_identity)
    found = {r["id"] for r in rules}
    return {"updated": rules, "not_found": sorted(set(body.ids) - found)}


@app.get("/ui/pii-rules", include_in_schema=False)
async def pii_rules_page():
    """Review page; it calls /admin/pii-rules with the key entered on the page."""
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "pii_rules.html"))
