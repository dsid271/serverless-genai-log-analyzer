"""Per-record logic of the Spark job, kept free of pyspark so it can be unit-tested.

Each Kafka value goes through the same bricks as the API path: format profile
(processing/format_profiles.py), rule-tier redaction including learned entities
(processing/redactor.py, NER off), and message patterns (processing/log_pattern.py).
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, Iterator, Optional

from processing.format_profiles import DEFAULT_PROFILE, get_normalizer
from processing.log_pattern import message_pattern, pattern_id
from processing.redactor import LogRedactor

ERROR_LEVELS = {"ERROR", "CRITICAL"}

# Column name -> Spark SQL type; streaming_job.py builds the schema from this.
COLUMNS = {
    "timestamp": "string",
    "kafka_ts": "timestamp",
    "source": "string",
    "severity": "string",
    "message": "string",
    "pattern_id": "string",
    "pattern": "string",
    "is_error": "boolean",
    "contains_pii": "boolean",
    "pii_fields": "string",
    "redaction_mode": "string",
    "record": "string",
}


def format_profile_from_env() -> str:
    return (os.getenv("SPARK_FORMAT_PROFILE") or os.getenv("KAFKA_FORMAT_PROFILE")
            or os.getenv("LOG_FORMAT_PROFILE") or DEFAULT_PROFILE)


class RecordProcessor:
    def __init__(self, format_profile: Optional[str] = None, pii_profile: Optional[str] = None):
        self.normalizer = get_normalizer()
        self.format_profile = format_profile or format_profile_from_env()
        if not self.normalizer.has(self.format_profile):
            raise ValueError(f"unknown format profile {self.format_profile!r}; "
                             f"available: {self.normalizer.names()}")
        self.redactor = LogRedactor(profile=pii_profile or os.getenv("REDACTOR_PROFILE", "financial"),
                                    use_ner=False)

    @staticmethod
    def _decode(value: Any) -> Optional[Dict[str, Any]]:
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value).decode("utf-8", errors="replace")
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def process(self, value: Any, kafka_ts: Any = None) -> Optional[Dict[str, Any]]:
        """One Kafka value -> one output row, or None for non-JSON-object values."""
        log = self._decode(value)
        if log is None:
            return None
        log = self.normalizer.normalize_batch([log], self.format_profile)[0]
        clean = self.redactor.redact_log(log)
        message = str(clean.get("message") or "")
        severity = str(clean.get("severity") or "INFO").upper()
        return {
            "timestamp": None if clean.get("timestamp") is None else str(clean["timestamp"]),
            "kafka_ts": kafka_ts,
            "source": str(clean.get("source") or "unknown"),
            "severity": severity,
            "message": message,
            "pattern_id": pattern_id(clean),
            "pattern": message_pattern(message),
            "is_error": severity in ERROR_LEVELS,
            "contains_pii": bool(clean.get("contains_pii", False)),
            "pii_fields": ",".join(clean.get("pii_fields") or []),
            "redaction_mode": str(clean.get("redaction_mode", "")),
            "record": json.dumps(clean, default=str),
        }


_PROCESSOR: Optional[RecordProcessor] = None


def process_frames(frames: Iterable[Any]) -> Iterator[Any]:
    """mapInPandas function: frames with `value` and `kafka_ts` -> COLUMNS.

    The processor is built once per Python worker and reused across batches.
    """
    import pandas as pd

    global _PROCESSOR
    if _PROCESSOR is None:
        _PROCESSOR = RecordProcessor()
    for frame in frames:
        rows = [row for row in (_PROCESSOR.process(v, ts)
                                for v, ts in zip(frame["value"], frame["kafka_ts"])) if row]
        yield pd.DataFrame(rows, columns=list(COLUMNS)).astype({"is_error": bool, "contains_pii": bool})
