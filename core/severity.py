"""
Rule-based incident severity scoring.

The score (0-100) is a sum of explainable factors. The LLM triage severity is
one more input, not the final word, and an operator override (from feedback)
always wins. Every factor is returned so the result can be audited and tuned.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

LEVELS = ("low", "medium", "high", "critical")

# Score thresholds: >= value -> level
_LEVEL_FLOORS = (("critical", 75), ("high", 50), ("medium", 25), ("low", 0))

_TIER_POINTS = {1: 20, 2: 10}
_LLM_POINTS = {"low": 0, "medium": 10, "high": 20}


def level_for(score: int) -> str:
    for level, floor in _LEVEL_FLOORS:
        if score >= floor:
            return level
    return "low"


def score_incident(
    details: Dict[str, Any],
    *,
    occurrences: int = 1,
    tier: Optional[int] = None,
    deployments: int = 0,
    llm_severity: Optional[str] = None,
    override: Optional[str] = None,
    prior_false_positives: int = 0,
) -> Dict[str, Any]:
    factors: List[Dict[str, Any]] = []

    def add(name: str, points: int, detail: str) -> None:
        if points:
            factors.append({"factor": name, "points": points, "detail": detail})

    count = int(details.get("count") or 0)
    threshold = max(int(details.get("threshold") or 1), 1)
    ratio = count / threshold
    add("volume", min(30, int(10 * ratio)), f"{count} errors vs threshold {threshold}")

    critical = int(details.get("critical_count") or 0)
    if critical:
        add("critical_logs", 20, f"{critical} CRITICAL log(s) in window")

    sources = details.get("sources") or []
    add("blast_radius", min(15, 5 * max(len(sources) - 1, 0)), f"{len(sources)} source(s) affected")

    if details.get("contains_pii"):
        add("pii_in_errors", 10, "error messages contained PII (redacted)")

    malicious = int(details.get("malicious_ip_count") or 0)
    if malicious:
        add("threat_intel", 15, f"{malicious} error(s) from IPs AbuseIPDB reports as malicious")

    if tier is not None:
        add("service_tier", _TIER_POINTS.get(tier, 0), f"most critical affected service is tier {tier}")

    add("recurrence", min(10, 2 * max(occurrences - 1, 0)), f"grouped {occurrences} occurrence(s)")

    if deployments:
        add("recent_deploy", 10, f"{deployments} deployment(s) to affected services near incident start")

    if llm_severity in _LLM_POINTS:
        add("llm_triage", _LLM_POINTS[llm_severity], f"LLM triage rated {llm_severity}")

    if prior_false_positives:
        add(
            "prior_false_positives",
            -min(30, 10 * prior_false_positives),
            f"{prior_false_positives} incident(s) on this service marked false positive in the last 7 days",
        )

    score = max(0, min(100, sum(f["points"] for f in factors)))
    result: Dict[str, Any] = {
        "score": score,
        "level": level_for(score),
        "rule_level": level_for(score),
        "factors": factors,
        "llm_severity": llm_severity,
        "override": None,
    }
    if override in LEVELS:
        result["level"] = override
        result["override"] = override
    return result
