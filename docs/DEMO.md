# Pitch and tutorial

## Purpose

During an incident, on-call engineers read thousands of near-identical log lines, and those logs often hold personal data (names, emails, card numbers, IPs). Two things go wrong:

1. **Triage is slow.** Nobody can tell quickly which error burst is new, who owns it, or whether a deploy caused it.
2. **Redaction misses things.** Regexes catch emails and card numbers but not names. A name-detection model (NER) catches names, but it is too slow for a high-volume stream and sometimes misses.

This project is a local-first prototype that addresses both:

| Problem | What it does |
|---|---|
| Too many raw logs | Ingests logs (HTTP, Kafka, or Spark for high volume), detects error spikes per source against that source's own baseline, and raises one **incident** instead of thousands of alerts. |
| Slow triage | Groups incidents, scores severity, routes to an owner, correlates with deploys, and (optionally) asks Gemini for a triage summary using your runbooks. |
| PII in logs | Redacts before storage. NER finds names; **the system learns where they appear** and proposes fast rules so the high-volume path catches them without NER. |
| Trusting the learning | A human approves or rejects each proposed rule in a web page. Every decision records who made it and when. |

**Honest scope:** this is a prototype. Detection is threshold/baseline based, LLM triage is unmeasured, and redaction quality has no evaluation set. See [Known Limitations](../README.md#known-limitations).

### 60-second pitch

> "Logs are full of personal data, and the fast redaction path can't recognise names. Our pipeline lets the slow NER model *teach* the fast path: it notices that `profile update failed for <name>` always has a person in that spot, proposes a rule, and a reviewer approves it once. From then on the high-volume Spark path redacts new names in that message shape with no model call. Alongside that, error spikes become single, routed, summarised incidents. Everything runs locally with Docker Compose."

## Tutorial (about 10 minutes)

Needs Docker, PowerShell, and a copy of `.env.example` saved as `.env`. `GEMINI_API_KEY` is only needed for the LLM triage step, which this tutorial skips.

### 1. Start the stack
```powershell
cp .env.example .env
docker compose up -d --build api prometheus grafana
```
Wait until `curl.exe -s http://localhost:8000/` returns JSON. The image installs the spaCy model with `|| true`; if the log says "Rule-only mode active", NER is not available and step 3 will not produce suggestions.

### 2. Get an admin key
Auth is off by default (`ENABLE_AUTH=false`). To demo it on, set `ENABLE_AUTH=true` in `.env`, run `docker compose up -d api` (a plain `restart` does not re-read `.env`), then:
```powershell
docker compose exec api python scripts/manage_keys.py issue --name demo-reviewer --profile admin
$env:KEY = "<paste the key>"     # shown once; with auth off, skip this and the -H header below
```

### 3. Ingest logs and see redaction
```powershell
curl.exe -s -X POST http://localhost:8000/ingest -H "X-API-Key: $env:KEY" -H "Content-Type: application/json" --data-binary "@demo_payload.json"
```
The emails in `demo_payload.json` come back masked. `sh demo.sh` does the same and also prints `/plugins` and `/incidents` (add the key header if auth is on).

### 4. Let the system learn a rule
Send the same message shape with six different names (the default is five distinct values per slot, `PII_SUGGEST_MIN_DISTINCT`):
```powershell
$names = "Maria Gonzalez","Liam Okafor","Priya Natarajan","Chen Wei","Sofia Rossi","Omar Haddad"
$logs = $names | % { @{timestamp=(Get-Date).ToUniversalTime().ToString("o"); severity="ERROR"; source="profile-svc"; message="profile update failed for $_, retry scheduled"} }
@{logs=@($logs)} | ConvertTo-Json -Depth 4 | Set-Content body.json -Encoding utf8
curl.exe -s -X POST http://localhost:8000/ingest -H "X-API-Key: $env:KEY" -H "Content-Type: application/json" --data-binary "@body.json"
Remove-Item body.json
```
Only the message shape (`profile update failed for <<PERSON>>, retry scheduled`), counts and keyed hashes are stored. The names are not.

### 5. Review and approve
Open http://localhost:8000/ui/pii-rules, paste the key (kept for the browser tab only), and find the **pending** `PERSON` suggestion. Select it and approve. The **approved** filter shows **Decided by** and **Decided at**.

> Tested in the API container: after six distinct names the `PERSON` suggestion was `pending` (5 hits, 5 distinct values). Which names NER recognises can vary, so use a different set if one does not register.

### 6. Show the payoff
A redactor with NER switched off, which is how the Spark job runs, masks a name it has never seen once the rule is approved:
```
before approval: profile update failed for Ahmed Karimi, retry scheduled
after approval:  profile update failed for [REDACTED], retry scheduled
```
To see it live, run the Spark path (`.env`: `ENABLED_CONNECTORS=spark_candidates`):
```powershell
docker compose --profile kafka --profile spark up -d kafka spark api
uv run python scripts/load_test.py --rate 2000 --duration 30
```
It reports producer rate, end-to-end throughput and lag. Spark reads approved rules from `data/learned_pii.sqlite3` every `PII_LEARNED_RELOAD_SECONDS`.

### 7. Show the metrics
- Grafana: http://localhost:3000 (`admin`/`admin`), dashboard **GenAI Log Analyzer - API Overview**, panel **PII rule suggestions by status**. It updates within about 30 s.
- Prometheus: http://localhost:9090, query `pii_rule_suggestions`. Prometheus has no saved queries; Grafana is the persistent view.

### Reset between demos
Remove rule suggestions and learned entities by deleting `data/learned_pii.sqlite3*` while the containers are stopped. Delete `data/api_keys.sqlite3` only if you want to revoke every key.

### Troubleshooting
| Symptom | Cause |
|---|---|
| `/ui/pii-rules` is 404 | The container started before the code changed. `docker compose restart api`. |
| 401 on the page | Auth is on and the key is missing or lacks `pii:admin` (the `admin` profile has it). |
| 403 on `POST /admin/keys` | Intentional with auth off. Use `scripts/manage_keys.py`. |
| No suggestions appear | NER unavailable (see step 1), or fewer than five distinct values in that slot. |
| `.env` and container disagree | `docker compose up -d api` to recreate the container. |
