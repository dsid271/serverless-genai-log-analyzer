"""
Prometheus metrics for the API.

`prometheus_client` is an optional dependency. If it isn't installed, every
function here becomes a no-op and `/metrics` reports itself as disabled,
matching the rest of the codebase's null-fallback pattern (redactor,
storage, vector store, analyzer all degrade the same way).
"""
from __future__ import annotations

from typing import Iterable, Mapping, Set, Tuple

# Caps label cardinality: each distinct log `source` becomes a time series.
_MAX_SOURCE_LABELS = 200
_MAX_SOURCE_LEN = 64
_seen_sources: Set[str] = set()

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

    METRICS_ENABLED = True

    HTTP_REQUESTS_TOTAL = Counter(
        "http_requests_total",
        "Total HTTP requests processed",
        ["method", "path", "status_code"],
    )
    HTTP_REQUEST_DURATION_SECONDS = Histogram(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "path"],
    )
    LOGS_INGESTED_TOTAL = Counter(
        "logs_ingested_total",
        "Total number of log records ingested",
        ["channel", "source"],
    )
    LOGS_PII_REDACTED_TOTAL = Counter(
        "logs_pii_redacted_total",
        "Total number of ingested log records that contained PII",
    )
    PII_RULE_SUGGESTIONS = Gauge(
        "pii_rule_suggestions",
        "PII rule suggestions by review status (collecting/pending/approved/rejected)",
        ["status"],
    )

except ImportError:  # pragma: no cover - exercised only when dep is absent
    METRICS_ENABLED = False
    HTTP_REQUESTS_TOTAL = None
    HTTP_REQUEST_DURATION_SECONDS = None
    LOGS_INGESTED_TOTAL = None
    LOGS_PII_REDACTED_TOTAL = None
    PII_RULE_SUGGESTIONS = None


def record_request(method: str, path: str, status_code: int, duration_seconds: float) -> None:
    if not METRICS_ENABLED:
        return
    HTTP_REQUESTS_TOTAL.labels(method=method, path=path, status_code=str(status_code)).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(method=method, path=path).observe(duration_seconds)


def _source_label(source: object) -> str:
    label = str(source).strip()[:_MAX_SOURCE_LEN] if source is not None else ""
    if not label:
        return "unknown"
    if label not in _seen_sources:
        if len(_seen_sources) >= _MAX_SOURCE_LABELS:
            return "other"
        _seen_sources.add(label)
    return label


def record_ingestion(channel: str, sources: Iterable[object], contains_pii: bool) -> None:
    """`channel` is how logs arrived (api/kafka/spark); `sources` holds each
    log's own `source` field, one entry per ingested record."""
    if not METRICS_ENABLED:
        return
    counts: dict = {}
    for source in sources:
        label = _source_label(source)
        counts[label] = counts.get(label, 0) + 1
    if not counts:
        return
    for label, n in counts.items():
        LOGS_INGESTED_TOTAL.labels(channel=channel, source=label).inc(n)
    if contains_pii:
        LOGS_PII_REDACTED_TOTAL.inc()


def record_pii_rule_counts(counts: Mapping[str, int]) -> None:
    if not METRICS_ENABLED:
        return
    for status, n in counts.items():
        PII_RULE_SUGGESTIONS.labels(status=status).set(n)


def render_latest() -> Tuple[bytes, str]:
    """Returns (body, content_type). Falls back to a plain-text notice if disabled."""
    if not METRICS_ENABLED:
        return (
            b"# prometheus_client not installed; metrics disabled.\n"
            b"# Install with: uv sync --extra observability\n",
            "text/plain; version=0.0.4",
        )
    return generate_latest(), CONTENT_TYPE_LATEST
