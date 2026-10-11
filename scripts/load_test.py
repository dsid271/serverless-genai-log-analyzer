"""Load generator: produce synthetic logs to Kafka and measure how fast the Spark job lands them.

  uv run python scripts/load_test.py --rate 5000 --duration 60

Sends --rate logs/s (0 = as fast as possible) for --duration seconds to --topic, then watches
the Spark UI (--spark-ui) until the `logs` query has processed every sent row (or --wait expires).
Reports the producer rate, end-to-end Spark throughput and the lag after the last send.
All names, emails and card numbers are fake. Each run is tagged; with --delta (a host path to
SPARK_DELTA_PATH) the rows of this run are also counted exactly in the table.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import random
import string
import time
import urllib.request

TEMPLATES = [
    ("INFO", "request handled path=/api/v1/orders/{n} status=200 in {ms}ms"),
    ("INFO", "cache hit key=session:{n}"),
    ("WARN", "slow query on orders took {ms}ms"),
    ("ERROR", "upstream timeout after {ms}ms calling inventory-svc"),
    ("ERROR", "payment declined for card 4111 1111 1111 1111 user {email}"),
    ("ERROR", "profile update failed for {name} ({email})"),
    ("CRITICAL", "db pool exhausted: {n} waiters"),
]
NAMES = ["Priya Raman", "Tomas Ruiz", "Mei Chen", "Ola Nordmann"]


def make_log(tag: str, sources: list, error_ratio: float, rng: random.Random) -> bytes:
    is_error = rng.random() < error_ratio
    pool = [t for t in TEMPLATES if (t[0] in ("ERROR", "CRITICAL")) == is_error]
    severity, template = rng.choice(pool)
    name = rng.choice(NAMES)
    msg = template.format(n=rng.randint(1, 99999), ms=rng.randint(5, 9000), name=name,
                          email=name.split()[0].lower() + "@example.com")
    return json.dumps({
        "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "severity": severity, "source": rng.choice(sources), "message": f"[{tag}] {msg}",
    }).encode()


async def produce(args, tag: str) -> tuple:
    from aiokafka import AIOKafkaProducer

    rng = random.Random(args.seed)
    sources = [f"svc-{i:02d}" for i in range(args.sources)]
    producer = AIOKafkaProducer(bootstrap_servers=args.bootstrap, linger_ms=20,
                                max_batch_size=1 << 20, compression_type=None)
    await producer.start()
    sent, start = 0, time.time()
    tick = 0.1
    try:
        while time.time() - start < args.duration:
            t0 = time.time()
            n = int(args.rate * tick) if args.rate else 5000
            futures = [await producer.send(args.topic, make_log(tag, sources, args.error_ratio, rng))
                       for _ in range(n)]
            await asyncio.gather(*futures)
            sent += n
            if args.rate:
                await asyncio.sleep(max(0.0, tick - (time.time() - t0)))
        await producer.flush()
    finally:
        await producer.stop()
    return sent, start, time.time()


def _get(url: str):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.load(r)


def _ui_time(value: str) -> float:
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%Z").replace(tzinfo=dt.timezone.utc).timestamp()


def landed_rows(ui: str, since: float) -> tuple:
    """(rows read by `logs` query stages completed since `since`, newest completion time in s)."""
    app = _get(f"{ui}/api/v1/applications")[0]["id"]
    rows, newest = 0, 0.0
    for s in _get(f"{ui}/api/v1/applications/{app}/stages?status=complete"):
        if not (s.get("description") or "").startswith("logs") or not s.get("completionTime"):
            continue
        done = _ui_time(s["completionTime"])
        if done < since:
            continue
        rows += int(s.get("inputRecords") or 0)
        newest = max(newest, done)
    return rows, newest


def count_tagged(path: str, tag: str) -> int:
    import pyarrow.compute as pc
    from deltalake import DeltaTable

    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    t = DeltaTable(path).to_pyarrow_table(partitions=[("date", "=", today)], columns=["message"])
    return pc.sum(pc.match_substring(t["message"], f"[{tag}]")).as_py() or 0


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--bootstrap", default="localhost:9092")
    p.add_argument("--topic", default="logs-raw")
    p.add_argument("--rate", type=int, default=2000, help="logs per second; 0 = as fast as possible")
    p.add_argument("--duration", type=float, default=30)
    p.add_argument("--sources", type=int, default=20)
    p.add_argument("--error-ratio", type=float, default=0.05)
    p.add_argument("--spark-ui", default="http://localhost:4040", help="Spark UI of the streaming job")
    p.add_argument("--delta", default="", help="optional host path of SPARK_DELTA_PATH, to count this run's rows")
    p.add_argument("--wait", type=float, default=180, help="max seconds to wait for Spark after sending")
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args()

    tag = "lt" + "".join(random.choices(string.ascii_lowercase, k=8))
    ui = args.spark_ui.rstrip("/")
    landed_rows(ui, time.time())   # fail fast if the Spark UI is unreachable
    print(f"run {tag}: producing to {args.topic} at {args.rate or 'max'} logs/s for {args.duration:.0f}s")
    sent, t_start, t_end = asyncio.run(produce(args, tag))
    print(f"produced {sent} logs in {t_end - t_start:.1f}s = {sent / (t_end - t_start):,.0f} logs/s")

    rows, newest, deadline = 0, 0.0, time.time() + args.wait
    while time.time() < deadline:
        previous = rows
        rows, newest = landed_rows(ui, t_start)
        if rows != previous:
            print(f"  +{time.time() - t_start:5.0f}s  rows processed since start: {rows}")
        if rows >= sent:
            break
        time.sleep(2)
    if not newest:
        print("no completed batches seen; is the spark container running?")
        return
    span = newest - t_start
    print(f"end-to-end: {min(rows, sent) / span:,.0f} logs/s over {span:.1f}s (first send -> last batch)")
    print(f"lag after last send: {max(0.0, newest - t_end):.1f}s")
    if args.delta:
        print(f"rows of this run in Delta: {count_tagged(args.delta, tag)}/{sent}")
    if rows < sent:
        print("not all rows processed within --wait; Spark is slower than the producer rate")


if __name__ == "__main__":
    main()
