"""Per-source error baseline for the Spark spike query, kept free of pyspark.

Each source keeps an exponentially weighted average (EWMA) of its error count per window.
A window is a spike when its count reaches `factor` x baseline and at least `min_count`.
Until a source has `warmup` finished windows, the fixed `threshold` applies instead.

Windows are fed in as they update (Spark "update" mode). A window joins the baseline once a
later window for the same source arrives; windows with no errors in between count as zero.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class _SourceState:
    mean: float = 0.0
    windows: int = 0
    last_closed: Optional[float] = None      # start (epoch s) of the newest window in the mean
    pending: Dict[float, int] = field(default_factory=dict)   # open window start -> latest count


class SpikeBaseline:
    def __init__(self, threshold: int, factor: float = 3.0, min_count: int = 5,
                 alpha: float = 0.2, warmup: int = 5, state_path: Optional[str] = None,
                 max_published: int = 10_000):
        self.threshold = threshold
        self.factor = factor
        self.min_count = min_count
        self.alpha = alpha
        self.warmup = warmup
        self.state_path = state_path
        self._sources: Dict[str, _SourceState] = {}
        self._published: Dict[Tuple[str, float], None] = {}
        self._max_published = max_published
        self._load()

    @classmethod
    def from_env(cls, threshold: int, state_path: Optional[str] = None) -> "SpikeBaseline":
        return cls(
            threshold=threshold,
            factor=float(os.getenv("SPARK_BASELINE_FACTOR") or 3.0),
            min_count=int(os.getenv("SPARK_BASELINE_MIN_COUNT") or 5),
            alpha=float(os.getenv("SPARK_BASELINE_ALPHA") or 0.2),
            warmup=int(os.getenv("SPARK_BASELINE_WARMUP") or 5),
            state_path=state_path,
        )

    @property
    def enabled(self) -> bool:
        return self.factor > 0

    def baseline(self, source: str) -> Optional[float]:
        s = self._sources.get(source)
        return s.mean if s and s.windows >= self.warmup else None

    def _close(self, s: _SourceState, start: float, count: int, length: float) -> None:
        if s.last_closed is not None and length > 0:
            gaps = int(round((start - s.last_closed) / length)) - 1
            for _ in range(min(max(gaps, 0), 1000)):
                s.mean *= (1 - self.alpha)
                s.windows += 1
        s.mean = count if s.windows == 0 else (1 - self.alpha) * s.mean + self.alpha * count
        s.windows += 1
        s.last_closed = start

    def _observe(self, source: str, start: float, count: int, length: float) -> None:
        s = self._sources.setdefault(source, _SourceState())
        if s.last_closed is not None and start <= s.last_closed:
            return                                       # late update to a window already in the mean
        s.pending[start] = count
        for older in sorted(k for k in s.pending if k < start):
            self._close(s, older, s.pending.pop(older), length)

    def evaluate(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """rows: source, start, end (epoch s), count, plus any extra fields.
        Returns rows to publish, each with `threshold`, `baseline` and `reason` added."""
        out = []
        for r in sorted(rows, key=lambda r: (r["source"], r["start"])):
            source, start, count = r["source"], float(r["start"]), int(r["count"])
            self._observe(source, start, count, float(r["end"]) - start)
            base = self.baseline(source) if self.enabled else None
            if base is None:
                limit, reason = float(self.threshold), "threshold"
            else:
                limit, reason = max(float(self.min_count), self.factor * base), "baseline"
            key = (source, start)
            if count >= limit and key not in self._published:
                self._published[key] = None
                while len(self._published) > self._max_published:
                    self._published.pop(next(iter(self._published)))
                out.append({**r, "threshold": round(limit, 2), "reason": reason,
                            "baseline": None if base is None else round(base, 2)})
        self._save()
        return out

    def _load(self) -> None:
        if not self.state_path or not os.path.exists(self.state_path):
            return
        with open(self.state_path, encoding="utf-8") as f:
            data = json.load(f)
        for name, s in data.get("sources", {}).items():
            self._sources[name] = _SourceState(
                mean=s["mean"], windows=s["windows"], last_closed=s["last_closed"],
                pending={float(k): v for k, v in s.get("pending", {}).items()})
        self._published = {(src, float(st)): None for src, st in data.get("published", [])}

    def _save(self) -> None:
        if not self.state_path:
            return
        data = {
            "sources": {n: {"mean": s.mean, "windows": s.windows, "last_closed": s.last_closed,
                            "pending": s.pending} for n, s in self._sources.items()},
            "published": [list(k) for k in self._published],
        }
        os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, self.state_path)
