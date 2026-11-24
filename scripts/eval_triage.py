"""Grounding eval for the gemini_triage analyzer.

  uv run python scripts/eval_triage.py                       # scripts/eval_triage_cases.yaml
  uv run python scripts/eval_triage.py --cases my.yaml --out report.json --min-pass 0.8

Seeds the case file's documents into a throwaway knowledge base, runs the analyzer on each
incident and checks the answer. Needs GEMINI_API_KEY (the free tier is enough; --delay paces calls).

Checks per case:
  ok          the analyzer returned a structured answer
  retrieved   every expected document was among the references given to the model
  cited       the answer names an expected document (or, when none is expected, names none)
  no_misuse   every document the answer names is an expected one
  severity    severity is one of the accepted levels
  keywords    each keyword group ("a|b" = either) appears in the answer
A document counts as named when its title appears in the answer, ignoring case and punctuation.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import tempfile
import time
from typing import Any, Dict, List

CHECKS = ("ok", "retrieved", "cited", "no_misuse", "severity", "keywords")
_DEFAULT_CASES = os.path.join(os.path.dirname(__file__), "eval_triage_cases.yaml")


def _norm(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text.lower()).split())


def _answer_text(analysis: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("hypotheses", "mitigations", "next_steps"):
        parts += [str(s) for s in analysis.get(key) or []]
    parts.append(str(analysis.get("impact") or ""))
    return _norm(" ".join(parts))


def grade(case: Dict[str, Any], analysis: Dict[str, Any], titles: List[str]) -> Dict[str, Any]:
    """`titles`: every document in the knowledge base, so citations of unretrieved ones count too."""
    expected = list(case.get("expected_docs") or [])
    retrieved = [r.get("title") for r in analysis.get("references") or []]
    answer = _answer_text(analysis)
    named = [t for t in titles if _norm(t) and _norm(t) in answer]
    accepted = case.get("severity") or []
    accepted = [accepted] if isinstance(accepted, str) else list(accepted)
    groups = [[_norm(k) for k in str(g).split("|")] for g in case.get("keywords") or []]
    missing = [g for g in groups if not any(k in answer for k in g)]
    ok = analysis.get("status") == "ok"
    checks = {
        "ok": ok,
        "retrieved": all(t in retrieved for t in expected),
        "cited": ok and (any(t in named for t in expected) if expected else not named),
        "no_misuse": ok and all(t in expected for t in named),
        "severity": ok and (not accepted or analysis.get("severity") in accepted),
        "keywords": ok and not missing,
    }
    return {
        "case": case.get("name"),
        "passed": all(checks.values()),
        "checks": checks,
        "named": named,
        "retrieved": retrieved,
        "missing_keywords": ["|".join(g) for g in missing],
        "severity": analysis.get("severity"),
        "error": analysis.get("detail") if not ok else None,
    }


def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(results) or 1
    return {
        "cases": len(results),
        "pass_rate": sum(r["passed"] for r in results) / n,
        "check_rates": {c: sum(r["checks"][c] for r in results) / n for c in CHECKS},
    }


def run(cases_path: str, delay: float) -> List[Dict[str, Any]]:
    import yaml
    from core.analyzers.gemini_incident_triage import GeminiIncidentTriageAnalyzer
    from core.knowledge import KnowledgeBase

    with open(cases_path, encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    results = []
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        kb = KnowledgeBase(collection_name="triage_eval", path=tmp)
        for doc in spec.get("documents") or []:
            kb.add(doc["kind"], doc["title"], doc["content"], services=doc.get("services"))
        titles = [d["title"] for d in spec.get("documents") or []]
        analyzer = GeminiIncidentTriageAnalyzer(knowledge=kb)
        for i, case in enumerate(spec.get("cases") or []):
            if i and delay:
                time.sleep(delay)
            analysis = asyncio.run(analyzer.analyze({"incident": case["incident"]}))
            results.append(grade(case, analysis, titles))
    return results


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--cases", default=_DEFAULT_CASES)
    p.add_argument("--out", default="", help="write the full JSON report here")
    p.add_argument("--min-pass", type=float, default=0.8, help="exit 1 below this pass rate")
    p.add_argument("--delay", type=float, default=4.0, help="seconds between LLM calls")
    args = p.parse_args()

    from dotenv import load_dotenv
    load_dotenv()
    results = run(args.cases, args.delay)
    for r in results:
        failed = [c for c, v in r["checks"].items() if not v]
        print(f"{'PASS' if r['passed'] else 'FAIL'}  {r['case']}" + (f"  failed: {', '.join(failed)}" if failed else ""))
    summary = summarize(results)
    print(f"\npass rate {summary['pass_rate']:.0%} over {summary['cases']} cases")
    for c, rate in summary["check_rates"].items():
        print(f"  {c:<10} {rate:.0%}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "results": results}, f, indent=2)
    sys.exit(0 if summary["pass_rate"] >= args.min_pass else 1)


if __name__ == "__main__":
    main()
