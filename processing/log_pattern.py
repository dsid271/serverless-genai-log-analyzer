"""Log patterns: one example per distinct message shape, for vector indexing.

Embedding costs about 0.3 s per log on CPU, and most high-volume logs repeat
the same few messages with different ids, IPs and numbers. Masking those
variable parts gives a pattern; only the first log per pattern is embedded,
and it is embedded again after a TTL so the stored example stays recent.
"""
import hashlib
import re
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional

_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX = re.compile(r"\b(?:0x[0-9a-fA-F]+|[0-9a-fA-F]{8,})\b")
_NUM = re.compile(r"\d+")
_SPACE = re.compile(r"\s+")


def message_pattern(message: str) -> str:
    """Message with ids, addresses and numbers masked, e.g. 'timeout after <n>ms'."""
    text = _UUID.sub("<uuid>", message)
    text = _IPV4.sub("<ip>", text)
    text = _HEX.sub("<hex>", text)
    text = _NUM.sub("<n>", text)
    return _SPACE.sub(" ", text).strip().lower()


def pattern_id(log: Dict[str, Any]) -> str:
    """Stable id from source, severity and message pattern (call after redaction)."""
    message = str(log.get("message") or log.get("raw") or log)
    key = "|".join((
        str(log.get("source", "")),
        str(log.get("severity", "")).upper(),
        message_pattern(message),
    ))
    return hashlib.sha1(key.encode()).hexdigest()[:16]


class PatternSampler:
    """Picks the logs worth embedding: the first of each pattern, then one per TTL."""

    def __init__(self, ttl_seconds: float = 3600.0, max_patterns: int = 100_000,
                 clock=time.monotonic) -> None:
        self.ttl = ttl_seconds
        self.max_patterns = max_patterns
        self._clock = clock
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        self._lock = threading.Lock()

    def select(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Copies of the chosen logs, each tagged with its `pattern_id`.

        The inputs are not modified, so the tag never reaches Delta Lake.
        """
        now = self._clock()
        chosen: List[Dict[str, Any]] = []
        with self._lock:
            for log in logs:
                pid = pattern_id(log)
                last: Optional[float] = self._seen.get(pid)
                if last is not None and now - last < self.ttl:
                    continue
                self._seen[pid] = now
                self._seen.move_to_end(pid)
                chosen.append({**log, "pattern_id": pid})
            while len(self._seen) > self.max_patterns:
                self._seen.popitem(last=False)
        return chosen
