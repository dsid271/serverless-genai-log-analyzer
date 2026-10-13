# Status

Overwrite this file as things change; don't append. Why-decisions go in `DECISIONS.md`.

**Last updated:** 2026-10-13

## Current state
- `ruff check .` passes; `pytest` passes (84 tests).
- Implemented (verified by reading code and git history): SQLite incident store, severity scoring, incident grouping, ownership routing, feedback endpoint, deployment events, knowledge base, IP enrichment, ticketing notifiers, Kafka batching with manual commit, Spark job and load generator, learned PII entities behind approval, SQLite API key store.
- Repo is at `C:\c\Dev\serverless-genai-log-analyzer` (off OneDrive).
- `.env`: `GEMINI_API_KEY` is set. `SERVICENOW_*`, `PAGERDUTY_ROUTING_KEY`, `ABUSEIPDB_API_KEY` are empty.

## Known gaps
- **Kafka/Spark load check (2026-10-12):** all five Compose services started. Command for every run: `uv run python scripts/load_test.py --rate 2000 --duration 30 --wait 180`. The producer managed only 1,750–1,850 logs/s, not 2,000. One run per condition, in this order, same stack unless noted:

  | Run | Condition | Sent | End-to-end logs/s | Lag after last send |
  |---|---|---|---|---|
  | 0 | first run after container start | 55,200 | 810 | 38.0 s |
  | 1 | identical | 53,000 | 754 | 40.2 s |
  | 2 | identical | 52,600 | 709 | 44.1 s |
  | 3 | Prometheus + Grafana stopped | 55,200 | 1,136 | 18.5 s |
  | 3b | Prometheus + Grafana started again (control) | 55,200 | 1,273 | 13.3 s |
  | 4 | 5 approved PII rules set to `pending` (restored afterwards, verified) | 55,600 | 1,089 | 21.0 s |

  - **Result:** none of the changes can be shown to matter. Run 3b has the same setup as runs 0–2 but is 60–80% faster, so the gap between runs is larger than any effect tested. Runs 0–2 were all slower than runs 3–4. The cause is unknown.
  - **Run 4 only measured the cost of checking 5 extra patterns:** the 5 approved rules were load-test artefacts (templates with old run IDs), so they could not match new messages. They are now deleted (backup: `data/learned_pii.bench-backup.sqlite3`, gitignored). 49 more load-test rules remain (20 collecting, 29 pending).
  - **Counter fixed** (commit `185b626`): `scripts/load_test.py` counted Delta-log stages as Kafka rows (run 4 showed 60,163 for 55,600 sent). It now counts only Kafka-read stages; over the six runs above it returns exactly 326,800 sent rows. Runs 0–3b were not affected in a way that changes the table; run 4's 1,089 logs/s is slightly low.
  - **Delta transaction-log hypothesis: not supported** (checked 2026-10-13, below). Each run adds only 2–3 Delta commits, and the slowest run came right after a checkpoint, when replay cost should be lowest.
- **5-run benchmark (2026-10-13, method in `DECISIONS.md`):** same stack and command as above, all five services running, Spark CPU below 15% before each run. Delta version (`v`) and last checkpoint (`cp`) read from `_delta_log` in the spark container before and after each run. Counter matched sent rows exactly on every run.

  | Run | Delta before → after | Sent | Producer logs/s | End-to-end logs/s | Lag after last send |
  |---|---|---|---|---|---|
  | warm-up (discarded) | v31 cp30 → v33 cp30 | 30,800 | 1,018 | 240 | 98.2 s |
  | 1 | v33 cp30 → v35 cp30 | 36,800 | 1,226 | 309 | 89.0 s |
  | 2 | v35 cp30 → v37 cp30 | 52,200 | 1,739 | 829 | 33.0 s |
  | 3 | v37 cp30 → v40 cp40 | 54,800 | 1,824 | 802 | 38.2 s |
  | 4 | v40 cp40 → v42 cp40 | 30,000 | 993 | 282 | 76.4 s |
  | 5 | v42 cp40 → v44 cp40 | 36,600 | 1,211 | 479 | 46.1 s |

  - **Median 479 logs/s, range 282–829.** Not a valid comparison of identical runs: the producer's rate varied from 993 to 1,824 logs/s, so the input was not the same. End-to-end tracks producer rate (the two runs above 1,700 logs/s were the two fastest).
  - **Likely cause: host contention.** The producer runs on the Windows host, outside Docker, so its rate dropping means the laptop itself was busy. Docker Desktop returned "timed out dialing Hyper-V socket" twice during the series. This would also explain the earlier 700–1,300 spread.
  - **Claim we can make (replaces "700 to 1,300"):** roughly 300 to 1,300 logs/s end-to-end on a single laptop, `local[*]`, with redaction; not profiled. This laptop is too noisy to detect a regression smaller than about 3×.
- **Observability check (2026-10-12):** API, `/metrics`, Spark UI, Prometheus and Grafana endpoints returned healthy responses; Prometheus target `genai-log-analyzer-api` is up and the Grafana dashboard is provisioned.
- **Kafka → Spark → API → incident (2026-10-12, ticket dispatch off):** works. Run with a temporary Compose override outside the repo (`ENABLED_CONNECTORS=spark_candidates`, `ENABLED_ANALYZERS=simple_summary` so Gemini was not called, `INCIDENTS_DB=/app/data/e2e_incidents.sqlite3`). All ticket sinks are empty in `.env`, so `tickets` stayed at 0 rows and the API log had no errors.
  - Backlog: the new consumer group read the 298 old candidates from the start of the topic and created 21 incidents (one per source, grouped within 900 s).
  - Fresh window 1 (`--rate 300 --duration 30`, default 5% errors): Spark published **no** candidates. This is correct: most sources have a baseline of 3–5 errors per window, so a spike needs about 11 in one 60 s window, and the ~14 errors per source were split across a minute boundary.
  - Fresh window 2 (`--error-ratio 0.5`): Spark published candidates (window `13:01:00Z`, 110–136 errors per source, `reason=baseline`, severity `high`). The API consumed them (group lag 0) and the 20 sources' incidents took one more occurrence each (sum 278 → 298); incident count stayed 21 because they were grouped into existing incidents. Run tag was present in the incident details.
  - Brand-new incidents (same day, empty `e2e_incidents.sqlite3`, same override; consumer group offsets kept so the old backlog was not replayed): `--rate 300 --duration 30 --error-ratio 0.5` created **20 new `error_spike` incidents**, one per source, each with `occurrences=1` and the run tag in its details; `tickets` stayed at 0 and the API log had no errors. The e2e DB was then deleted and the API restored to its normal config.
  - Not checked: ticket creation (needs a ServiceNow/PagerDuty/webhook sink).
  - The five Compose services are left running.
- **ServiceNow + LLM check:** not run. There is no ServiceNow image or service in Docker or `docker-compose.yml`, so it needs a real instance (for example a free ServiceNow developer instance) and `SERVICENOW_INSTANCE`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD`. The README says ticketing is only unit-tested with fakes.
- **Findings A1, A3, E3, E5, F4, F5, G4, G5:** checked in an earlier session (the one that produced commits `dd2f5fe` and `25f015f`); results recorded here, not re-run.

  | Finding | Result |
  |---|---|
  | A1 cooldown 0 in running container | Confirmed; fixed by recreating the container (now 60) |
  | A3 count pinned to threshold | Refuted: no `clear()`, window trimmed with `popleft()` (`error_spike.py` ~77) |
  | E3 sync `.invoke()` in async | Refuted: uses `asyncio.to_thread` |
  | E5 silent `except: pass` | None found; `ip_intel.py:117` and `kafka_consumer.py:12` swallow errors without logging, **still to fix** |
  | F4 `/analyze` up to 6 LLM calls | Confirmed, **open** |
  | F5 LangSmith tracing on by default | Refuted: `.env.example` has `false` |
  | G4 `contains_pii` from trigger only | Refuted: `any()` over the window (~96) |
  | G5 99%+ precision claim | Confirmed; fixed in `COMPLIANCE.md` |
- **Open decision: candidate replay on a new consumer group.** `LogConsumer` uses `auto_offset_reset="earliest"` (`ingestion/kafka_consumer.py:53`) for both connectors, so a new `CANDIDATES_GROUP_ID` replays the whole `incident-candidates` topic (298 old candidates on 2026-10-12). Options: `latest` for the candidates consumer only (simple; candidates published while the API is down with no committed offset are lost), or drop candidates older than N minutes in `CandidateHandler` (keeps short outages; needs a chosen N). Not decided.
- **CI:** runs five test files, including `test_auth_rate_limit.py` (commit `7446b2e`). `test_format_profiles.py` and `test_ingest.py` exist but are not in CI.
- **Task path mismatch:** deployment webhook is `POST /events/deployments` (task says `POST /deployments`); `GET /deployments` matches.
- No tests for the Kafka connector, analyzers or the LLM path (per README).

## Next steps
1. ~~Brand-new incident through the Spark path~~ Done (see above); `data/e2e_incidents.sqlite3` deleted.
2. **Ticket creation, ServiceNow Personal Developer Instance only** (waiting for the PDI). Never use a Cisco ServiceNow instance. Put `SERVICENOW_INSTANCE`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD` in `.env` (gitignored) or the shell, never in the repo, `docker-compose.yml`, docs or commits. Test incidents only. Run with `gemini_triage` off unless the LLM check is the point.
3. ~~Benchmark with the agreed method~~ Run 2026-10-13 (see above); not a valid comparison because the producer rate varied. Before benchmarking again, make the input steady: use a `--rate` the host can hold (for example 800), and treat any run whose producer rate misses the target by more than 5% as invalid.
4. ~~A1–G5 findings check~~ Done (see table above). Still open from it: E5 (add logging at `ip_intel.py:117` and `kafka_consumer.py:12`) and F4 (`/analyze` up to 6 LLM calls).
5. Decide candidate replay: `auto_offset_reset=latest` for the candidates consumer, or drop candidates older than N minutes.
6. **Per-batch fixed cost (unprofiled).** Batch time doesn't scale with row count. Candidates: Delta write, trigger interval, startup. Check `logs`-stage task time vs scheduling delay in the Spark UI, and rerun with a larger trigger interval. Benchmark only on a quiet host at a sustainable `--rate` (e.g. 800).

