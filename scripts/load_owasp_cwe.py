"""
Seed the knowledge base with OWASP Top 10 (2021) and MITRE CWE descriptions,
stored as kind="reference" through POST /knowledge.

The API key is read from the GLA_API_KEY environment variable (needs the
knowledge:write scope). Re-running replaces documents instead of duplicating them.

    $env:GLA_API_KEY = $admin
    uv run python scripts/load_owasp_cwe.py                 # OWASP + CWE Top 25
    uv run python scripts/load_owasp_cwe.py --cwe 117,770   # extra CWE ids
    uv run python scripts/load_owasp_cwe.py --all-cwe       # every CWE in view 1000
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import urllib.error
import urllib.request
import zipfile

CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"

# 2024 CWE Top 25 Most Dangerous Software Weaknesses.
CWE_TOP_25 = [79, 787, 89, 352, 22, 125, 78, 416, 862, 434, 94, 20, 77, 287, 269,
              502, 200, 863, 918, 119, 476, 798, 190, 400, 306]

OWASP_TOP_10 = [
    ("A01:2021", "Broken Access Control",
     "Users act outside their intended permissions: IDOR, missing authorization checks, "
     "privilege escalation, CORS misconfiguration, forced browsing. Log signals: 403/401 bursts, "
     "access to other users' resource ids. Mitigate: deny by default, server-side checks, log failures.",
     [22, 200, 284, 285, 352, 639, 862, 863]),
    ("A02:2021", "Cryptographic Failures",
     "Sensitive data exposed through weak or missing encryption: plaintext transport, weak algorithms, "
     "hard-coded or reused keys, missing certificate validation. Mitigate: TLS everywhere, strong "
     "algorithms, key rotation, do not store data you do not need.",
     [259, 295, 310, 319, 321, 326, 327, 328]),
    ("A03:2021", "Injection",
     "Untrusted input interpreted as code or query: SQL, NoSQL, OS command, LDAP, XSS. Log signals: "
     "SQL syntax errors, quotes/UNION/script tags in parameters. Mitigate: parameterized queries, "
     "input validation, output encoding.",
     [20, 74, 77, 78, 79, 89, 94, 917]),
    ("A04:2021", "Insecure Design",
     "Missing or ineffective security controls at design level: no rate limits on sensitive flows, "
     "trust boundaries not defined, business-logic abuse. Mitigate: threat modeling, secure design "
     "patterns, abuse-case tests.",
     [73, 183, 209, 213, 256, 501, 522, 656]),
    ("A05:2021", "Security Misconfiguration",
     "Insecure defaults, verbose errors with stack traces, unnecessary features enabled, missing "
     "hardening, XXE. Mitigate: repeatable hardened configuration, remove unused features, "
     "generic error messages.",
     [2, 11, 13, 15, 16, 260, 315, 611]),
    ("A06:2021", "Vulnerable and Outdated Components",
     "Running libraries, frameworks or OS packages with known vulnerabilities or no longer supported. "
     "Mitigate: dependency inventory, SCA scanning, timely patching, remove unused dependencies.",
     [937, 1035, 1104]),
    ("A07:2021", "Identification and Authentication Failures",
     "Credential stuffing, brute force, weak passwords, session fixation, missing MFA. Log signals: "
     "many failed logins per account or IP. Mitigate: MFA, rate limiting, secure session handling.",
     [255, 287, 288, 290, 294, 307, 384, 798]),
    ("A08:2021", "Software and Data Integrity Failures",
     "Code or data used without integrity verification: unsigned updates, insecure CI/CD, insecure "
     "deserialization. Mitigate: signatures, trusted repositories, pipeline access control.",
     [345, 353, 426, 494, 502, 565, 784, 829]),
    ("A09:2021", "Security Logging and Monitoring Failures",
     "Attacks not detected because events are not logged, monitored or alerted on; logs contain "
     "sensitive data or are injectable. Mitigate: log auth and access failures, alerting, "
     "tamper-resistant storage, neutralize log input.",
     [117, 223, 532, 778]),
    ("A10:2021", "Server-Side Request Forgery (SSRF)",
     "The server fetches an attacker-supplied URL, reaching internal services or cloud metadata "
     "endpoints. Log signals: outbound requests to 169.254.169.254 or internal ranges. Mitigate: "
     "allow-list destinations, block internal ranges, disable redirects.",
     [918]),
]


def post(base_url: str, key: str, doc: dict) -> None:
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/knowledge",
        data=json.dumps(doc).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


def mitigations(raw: str) -> list[str]:
    # Format: ::PHASE:...:STRATEGY:...:DESCRIPTION:...::PHASE:...
    out = []
    for entry in raw.split("::"):
        if ":DESCRIPTION:" in entry or entry.startswith("DESCRIPTION:"):
            text = entry.split("DESCRIPTION:", 1)[1].split(":EFFECTIVENESS:", 1)[0]
            out.append(text.strip())
    return out


def load_cwe(ids: set[int] | None) -> list[dict]:
    with urllib.request.urlopen(CWE_CSV_URL, timeout=60) as resp:
        archive = zipfile.ZipFile(io.BytesIO(resp.read()))
    rows = csv.DictReader(io.TextIOWrapper(archive.open(archive.namelist()[0]), encoding="utf-8"))
    docs = []
    for row in rows:
        cwe_id = int(row["CWE-ID"])
        if (ids is not None and cwe_id not in ids) or row.get("Status") == "Deprecated":
            continue
        parts = [row["Description"].strip(), row.get("Extended Description", "").strip()]
        mits = mitigations(row.get("Potential Mitigations", ""))[:3]
        if mits:
            parts.append("Mitigations:\n- " + "\n- ".join(mits))
        docs.append({
            "kind": "reference",
            "title": f"CWE-{cwe_id}: {row['Name']}"[:300],
            "content": "\n\n".join(p for p in parts if p)[:50000],
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
        })
    return docs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=os.getenv("GLA_API_URL", "http://localhost:8000"))
    parser.add_argument("--cwe", default="", help="comma-separated extra CWE ids")
    parser.add_argument("--all-cwe", action="store_true", help="load every CWE in the research view")
    parser.add_argument("--skip-cwe", action="store_true", help="load OWASP only (no download)")
    args = parser.parse_args()

    key = os.getenv("GLA_API_KEY")
    if not key:
        print("Set GLA_API_KEY to a key with the knowledge:write scope.", file=sys.stderr)
        return 2

    docs = [{
        "kind": "reference",
        "title": f"OWASP {code} {name}",
        "content": f"{summary}\n\nRelated CWEs: " + ", ".join(f"CWE-{c}" for c in cwes),
        "url": "https://owasp.org/Top10/",
    } for code, name, summary, cwes in OWASP_TOP_10]

    if not args.skip_cwe:
        ids = None if args.all_cwe else set(CWE_TOP_25) | {c for *_, cwes in OWASP_TOP_10 for c in cwes}
        if args.cwe:
            ids = None if ids is None else ids | {int(x) for x in args.cwe.split(",") if x.strip()}
        docs += load_cwe(ids)

    failed = 0
    for doc in docs:
        try:
            post(args.url, key, doc)
        except urllib.error.HTTPError as e:
            failed += 1
            print(f"{doc['title']}: HTTP {e.code}", file=sys.stderr)
    print(f"loaded {len(docs) - failed}/{len(docs)} reference documents")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
