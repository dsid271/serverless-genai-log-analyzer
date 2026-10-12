# Decisions

Why things are the way they are. One short entry per decision, newest first. Add new entries at the top; don't rewrite old ones, add a new entry that supersedes them.

## 2026-10 Load tests use their own learned-PII DB
- Decision: set `LOADTEST_PII_DB=/app/data/loadtest_pii.sqlite3` before starting `api` and `spark` for load tests; the default is still `data/learned_pii.sqlite3`
- Why: the API's NER pass on synthetic logs wrote 54 rules into the real DB (5 of them approved, with 497 stored values), all with load-test run tags in the template
- Rejected: deleting the junk after each test (easy to forget, and an approved junk rule masks real messages)

## 2026-10 Benchmark method: median and range of repeated runs
- Decision: discard the first run after container start as warm-up; do 5 identical runs; report median and range; change one variable at a time and call a change real only if it exceeds the range
- Why: six runs of the same load gave 709 to 1,273 logs/s, and a change (stopping Prometheus and Grafana) looked like a 40% gain until the control run came out faster
- Rejected: reporting a single run

## 2026-10 Learned PII entities gated behind approval
- Decision: `PII_LEARNING=false` by default; entities go pending → `pii:admin` approves
- Why: NER over-triggers on syslog (`%BGP-5-ADJCHANGE`, "Config"); auto-promotion would learn false positives permanently
- Rejected: hashing alone (low-entropy values are dictionary-reversible; still personal data under GDPR)

## 2026-10 Spark output lives in a Docker volume, not `./data`
- Decision: Compose writes Delta tables and checkpoints to the `spark-data` volume
- Why: each batch writes many small files; on a host bind mount (measured on a OneDrive folder) lag was ~150 s vs ~50 s in a volume
- Rejected: keeping output in `./data` for easy browsing (too slow, and the repo has since moved off OneDrive to `C:\c\Dev`)

## 2026-10 Spark spikes judged against each source's own baseline
- Decision: rolling average (EWMA) of errors per window per source, in `spark/baseline.py`
- Why: a service that always logs 50 errors a minute should not alert, while a quiet one jumping from 2 to 12 should
- Rejected: one fixed error-count threshold for all sources

## 2026-10 API keys in SQLite, stored as a SHA-256 digest
- Decision: `api/key_store.py`; key format `gla_<key_id>_<secret>`; lookup by `key_id`, then constant-time compare
- Why: secrets are 256-bit random values, so a fast digest is enough; slow hashes like bcrypt exist for low-entropy passwords
- Rejected: YAML key file (replaced; `_load_keys` no longer exists)

## 2026-10 Kafka offsets committed only after a batch is stored
- Decision: `enable_auto_commit=False`; commit after `on_batch` succeeds; on failure, seek back and retry
- Why: a crash re-delivers the batch instead of losing it (at-least-once)
- Rejected: auto-commit (can lose logs that were polled but not yet stored)
- Cost: duplicates are possible after a crash

## 2026-10 No mock or null fallbacks; fail at startup
- Decision: components are injected through constructors; if the redactor can't be built, the API doesn't start
- Why: a silent fallback could store unredacted logs or hide a broken setup
- Rejected: degrading to a no-op redactor or mock store
- Exception: the Kafka connector retries in the background, so the API still starts when the broker is down (no data is at risk there)
