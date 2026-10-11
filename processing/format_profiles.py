"""Log-format profiles: map a platform's field names onto the internal schema.

Runs before redaction, storage and detection (see processing/format_profiles.yaml
for the profile format). Records that already use the internal field names pass
through unchanged under the `generic` profile. A single malformed record never
raises: unmappable fields are left as they were.
"""
from __future__ import annotations

import functools
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

import yaml

logger = logging.getLogger(__name__)

CANONICAL = ("timestamp", "severity", "source", "message")
DEFAULT_PROFILE = "generic"
_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "format_profiles.yaml")

# OpenTelemetry severityNumber bands -> internal levels.
_OTEL_BANDS = ((4, "DEBUG"), (8, "DEBUG"), (12, "INFO"), (16, "WARNING"), (20, "ERROR"), (24, "CRITICAL"))


def _empty(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _get(rec: Dict[str, Any], path: str) -> Any:
    if path in rec:  # flat keys that contain dots (e.g. ECS "service.name")
        return rec[path]
    node: Any = rec
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _pop(rec: Dict[str, Any], path: str) -> None:
    """Remove `path` from `rec`, copying dicts along the way (input is untouched)."""
    if path in rec:
        del rec[path]
        return
    parts = path.split(".")
    chain = [rec]
    for part in parts[:-1]:
        child = chain[-1].get(part)
        if not isinstance(child, dict):
            return
        child = dict(child)
        chain[-1][part] = child
        chain.append(child)
    chain[-1].pop(parts[-1], None)
    # Drop parents emptied by the removal so no hollow containers are stored.
    for depth in range(len(chain) - 1, 0, -1):
        if chain[depth]:
            break
        del chain[depth - 1][parts[depth - 1]]


def _to_iso(value: Any, formats: Sequence[str]) -> Optional[str]:
    dt: Optional[datetime] = None
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip()
        try:
            value = float(text) if text.replace(".", "", 1).isdigit() else text
        except ValueError:
            value = text
    if isinstance(value, (int, float)):
        n = float(value)
        for limit, divisor in ((1e11, 1), (1e14, 1e3), (1e17, 1e6), (float("inf"), 1e9)):
            if abs(n) < limit:
                try:
                    dt = datetime.fromtimestamp(n / divisor, tz=timezone.utc)
                except (OverflowError, OSError, ValueError):
                    return None
                break
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            for fmt in formats:
                try:
                    dt = datetime.strptime(value, fmt)
                    break
                except ValueError:
                    continue
    if dt is None:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


class FormatProfile:
    def __init__(self, name: str, spec: Dict[str, Any]):
        fields = spec.get("fields") or {}
        unknown = set(fields) - set(CANONICAL)
        if unknown:
            raise ValueError(f"profile {name!r}: unknown canonical fields {sorted(unknown)}")
        self.name = name
        self.fields: Dict[str, List[str]] = {k: [str(p) for p in v] for k, v in fields.items()}
        self.severity_map = {str(k).upper(): str(v).upper() for k, v in (spec.get("severity_map") or {}).items()}
        self.timestamp_formats = list(spec.get("timestamp_formats") or [])
        self.defaults = {k: v for k, v in (spec.get("defaults") or {}).items() if k in CANONICAL}

    def _severity(self, value: Any) -> str:
        if not isinstance(value, bool) and (isinstance(value, (int, float)) or str(value).strip().isdigit()):
            n = int(float(value))
            return next((lvl for top, lvl in _OTEL_BANDS if 1 <= n <= top), "CRITICAL" if n > 24 else "INFO")
        text = str(value).strip().upper()
        return self.severity_map.get(text, text)

    def normalize(self, log: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(log)
        for canon in CANONICAL:
            value, used = None, None
            for path in self.fields.get(canon, ()):
                candidate = _get(out, path)
                if not _empty(candidate):
                    value, used = candidate, path
                    break
            if used is None:
                if _empty(out.get(canon)) and canon in self.defaults:
                    out[canon] = self.defaults[canon]
                continue
            if canon == "severity":
                value = self._severity(value)
            elif canon == "timestamp":
                iso = _to_iso(value, self.timestamp_formats)
                if iso is None:
                    logger.debug("profile %s: unparseable timestamp %r kept as-is", self.name, value)
                value = iso or value
            elif canon == "message":
                value = value if isinstance(value, str) else json.dumps(value, default=str)
            else:
                value = str(value)
            if used != canon:
                _pop(out, used)
            out[canon] = value
        return out


class FormatNormalizer:
    def __init__(self, path: Optional[str] = None):
        path = path or os.getenv("FORMAT_PROFILES_PATH") or _DEFAULT_PATH
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        self.profiles: Dict[str, FormatProfile] = {
            name: FormatProfile(name, spec or {}) for name, spec in (doc.get("profiles") or {}).items()
        }
        if DEFAULT_PROFILE not in self.profiles:
            raise ValueError(f"{path}: required profile {DEFAULT_PROFILE!r} is missing")

    def names(self) -> List[str]:
        return sorted(self.profiles)

    def has(self, name: str) -> bool:
        return name in self.profiles

    def normalize_batch(self, logs: List[Dict[str, Any]], profile: Optional[str] = None) -> List[Dict[str, Any]]:
        selected = self.profiles.get(profile or DEFAULT_PROFILE)
        if selected is None:
            raise KeyError(f"unknown format profile {profile!r}; available: {self.names()}")
        out = []
        for log in logs:
            try:
                out.append(selected.normalize(log))
            except Exception:
                logger.exception("profile %s failed on a record; passing it through unchanged", selected.name)
                out.append(log)
        return out


@functools.lru_cache(maxsize=1)
def get_normalizer() -> FormatNormalizer:
    return FormatNormalizer()
