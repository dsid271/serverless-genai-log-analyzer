"""OTLP/HTTP JSON logs -> flat log records for the `otlp` format profile.

Accepts the body of an OpenTelemetry logs export (ExportLogsServiceRequest as JSON):
resourceLogs[] -> scopeLogs[] -> logRecords[]. Each log record becomes one flat dict:

  timeUnixNano / observedTimeUnixNano, severityText, severityNumber, body, traceId, spanId
      kept under their OTLP names (processing/format_profiles.yaml maps them),
  resource_<name>   resource attributes, e.g. resource_service_name,
  <name>            log attributes, e.g. http_status_code, http_duration_ms.

Dots in attribute names become underscores so they are safe Delta column names.
Not a trace backend: spans and metrics are not handled, only the trace and span ids
that logs carry.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

_ZERO_ID = re.compile(r"^0+$")


class OtlpError(ValueError):
    """The payload is not a valid OTLP logs export."""


def _any_value(value: Any) -> Any:
    """OTLP AnyValue -> a plain Python value (arrays and maps become JSON text)."""
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:  # int64 is a string in OTLP/JSON
        try:
            return int(value["intValue"])
        except (TypeError, ValueError):
            return str(value["intValue"])
    if "doubleValue" in value:
        return value["doubleValue"]
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "arrayValue" in value:
        items = (value["arrayValue"] or {}).get("values") or []
        return json.dumps([_any_value(v) for v in items], default=str)
    if "kvlistValue" in value:
        return json.dumps(_attributes(((value["kvlistValue"] or {}).get("values")) or [], ""), default=str)
    if "bytesValue" in value:
        return str(value["bytesValue"])
    return None


def _key(name: str, prefix: str) -> str:
    return prefix + re.sub(r"[^A-Za-z0-9_]", "_", str(name))


def _attributes(items: Any, prefix: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for kv in items if isinstance(items, list) else []:
        if isinstance(kv, dict) and kv.get("key") is not None:
            value = _any_value(kv.get("value"))
            if value is not None:
                out[_key(kv["key"], prefix)] = value
    return out


def _present(value: Any) -> bool:
    """False for unset OTLP fields: absent, empty, or the zero value of a number or id."""
    if value in (None, "", 0, "0"):
        return False
    return not (isinstance(value, str) and _ZERO_ID.match(value))


def flatten_otlp_logs(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("resourceLogs", []), list):
        raise OtlpError("expected an OTLP logs export with a resourceLogs list")
    try:
        return _flatten(payload)
    except (AttributeError, TypeError) as e:
        raise OtlpError(f"malformed OTLP logs export: {e}") from e


def _flatten(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    logs: List[Dict[str, Any]] = []
    for resource_logs in payload.get("resourceLogs") or []:
        resource = _attributes(((resource_logs.get("resource") or {}).get("attributes")), "resource_")
        for scope_logs in resource_logs.get("scopeLogs") or []:
            scope = scope_logs.get("scope") or {}
            for record in scope_logs.get("logRecords") or []:
                flat: Dict[str, Any] = {**resource}
                if scope.get("name"):
                    flat["otel_scope"] = scope["name"]
                flat.update(_attributes(record.get("attributes"), ""))
                # OTLP's own fields last so an attribute can never overwrite them.
                for name in ("timeUnixNano", "observedTimeUnixNano", "severityText", "severityNumber"):
                    if _present(record.get(name)):
                        flat[name] = record[name]
                body = _any_value(record.get("body"))
                if body is not None:
                    flat["body"] = body
                if _present(record.get("traceId")):
                    flat["traceId"] = record["traceId"]
                if _present(record.get("spanId")):
                    flat["span_id"] = record["spanId"]
                logs.append(flat)
    return logs
