"""Spark Structured Streaming job for high-volume logs.

  Kafka (logs-raw) -> format profile -> rule redaction (+ learned entities) -> pattern id
    -> Delta Lake, partitioned by date and source              (query "logs")
  Delta stream -> per-source error counts in event-time windows with a watermark
    -> windows at or above the threshold go to Kafka (incident-candidates)   (query "spikes")

The API consumes incident-candidates with the `spark_candidates` connector.
Run: python -m spark.streaming_job   (needs Java 17+; see Dockerfile.spark)
"""
from __future__ import annotations

import logging
import os

from spark.transform import COLUMNS, process_frames

logger = logging.getLogger("spark.streaming_job")


def _env(name: str, default: str) -> str:
    return os.getenv(name) or default


def build_session():
    import pyspark
    from pyspark.sql import SparkSession

    scala = _env("SPARK_SCALA_VERSION", "2.13")
    packages = [
        f"org.apache.spark:spark-sql-kafka-0-10_{scala}:{pyspark.__version__}",
        f"io.delta:delta-spark_{scala}:{_env('DELTA_SPARK_VERSION', '4.0.0')}",
    ]
    return (
        SparkSession.builder.appName("log-analyzer-stream")
        .master(_env("SPARK_MASTER", "local[*]"))
        .config("spark.jars.packages", ",".join(packages))
        .config("spark.jars.ivy", _env("SPARK_IVY_DIR", os.path.expanduser("~/.ivy2")))
        .config("spark.sql.extensions", "io.delta.sql.DeltaSparkSessionExtension")
        .config("spark.sql.catalog.spark_catalog", "org.apache.spark.sql.delta.catalog.DeltaCatalog")
        .config("spark.sql.shuffle.partitions", _env("SPARK_SHUFFLE_PARTITIONS", "8"))
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )


def processed_schema():
    from pyspark.sql.types import StructType, _parse_datatype_string

    schema = StructType()
    for name, kind in COLUMNS.items():
        schema = schema.add(name, _parse_datatype_string(kind))
    return schema


def normalized_logs(spark, bootstrap: str):
    from pyspark.sql import functions as F

    raw = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", bootstrap)
        .option("subscribe", _env("SPARK_LOG_TOPIC", _env("LOG_TOPIC", "logs-raw")))
        .option("startingOffsets", _env("SPARK_STARTING_OFFSETS", "latest"))
        .option("maxOffsetsPerTrigger", _env("SPARK_MAX_OFFSETS_PER_TRIGGER", "200000"))
        .option("failOnDataLoss", "false")
        .load()
    )
    logs = raw.select("value", F.col("timestamp").alias("kafka_ts")).mapInPandas(
        process_frames, schema=processed_schema())
    return (
        logs.withColumn("event_time", F.coalesce(F.try_to_timestamp("timestamp"), F.col("kafka_ts")))
        .withColumn("date", F.to_date("event_time"))
        .drop("kafka_ts")
    )


def spike_candidates(logs, threshold: int, window: str, watermark: str):
    """Per-source error counts per event-time window; rows at or above `threshold`."""
    from pyspark.sql import functions as F

    counts = (
        logs.filter(F.col("is_error"))
        .withWatermark("event_time", watermark)
        .groupBy(F.window("event_time", window).alias("w"), F.col("source"))
        .agg(
            F.count(F.lit(1)).alias("count"),
            F.sum(F.when(F.col("severity") == "CRITICAL", 1).otherwise(0)).alias("critical_count"),
            F.max(F.col("contains_pii").cast("int")).alias("pii"),
            F.approx_count_distinct("pattern_id").alias("patterns"),
            F.first("message", ignorenulls=True).alias("sample"),
        )
        .filter(F.col("count") >= threshold)
    )
    payload = F.struct(
        F.col("source"),
        F.date_format("w.start", "yyyy-MM-dd'T'HH:mm:ss'Z'").alias("window_start"),
        F.date_format("w.end", "yyyy-MM-dd'T'HH:mm:ss'Z'").alias("window_end"),
        F.col("count"),
        F.col("critical_count"),
        (F.col("pii") == 1).alias("contains_pii"),
        F.col("patterns"),
        F.col("sample"),
        F.lit(threshold).alias("threshold"),
    )
    return counts.select(F.col("source").alias("key"), F.to_json(payload).alias("value"))


def _ensure_table(spark, path: str) -> None:
    """The spikes query streams from the Delta table, so it must exist before data arrives."""
    if os.path.isdir(os.path.join(path, "_delta_log")):
        return
    from pyspark.sql.types import DateType, StructField, StructType, TimestampType

    fields = [f for f in processed_schema().fields if f.name != "kafka_ts"]
    schema = StructType(fields + [StructField("event_time", TimestampType()), StructField("date", DateType())])
    spark.createDataFrame([], schema).write.format("delta").partitionBy("date", "source").save(path)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    bootstrap = _env("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    delta_path = _env("SPARK_DELTA_PATH", "./data/delta-lake/logs_stream")
    checkpoints = _env("SPARK_CHECKPOINT_DIR", "./data/spark-checkpoints")
    trigger = _env("SPARK_TRIGGER", "10 seconds")

    spark = build_session()
    spark.sparkContext.setLogLevel(_env("SPARK_LOG_LEVEL", "WARN"))
    _ensure_table(spark, delta_path)

    (normalized_logs(spark, bootstrap).writeStream.queryName("logs").format("delta")
     .outputMode("append").partitionBy("date", "source")
     .option("checkpointLocation", os.path.join(checkpoints, "logs"))
     .trigger(processingTime=trigger).start(delta_path))

    spikes = spike_candidates(
        spark.readStream.format("delta").load(delta_path),
        threshold=int(_env("SPARK_SPIKE_THRESHOLD", _env("ERROR_SPIKE_THRESHOLD", "20"))),
        window=_env("SPARK_SPIKE_WINDOW", "60 seconds"),
        watermark=_env("SPARK_WATERMARK", "2 minutes"),
    )
    # "update" emits a window as soon as it crosses the threshold (and again as it grows);
    # the API connector raises one incident per (source, window_start).
    (spikes.writeStream.queryName("spikes").format("kafka")
     .outputMode(_env("SPARK_SPIKE_OUTPUT_MODE", "update"))
     .option("kafka.bootstrap.servers", bootstrap)
     .option("topic", _env("SPARK_CANDIDATES_TOPIC", "incident-candidates"))
     .option("checkpointLocation", os.path.join(checkpoints, "spikes"))
     .trigger(processingTime=trigger).start())

    logger.info("Streaming %s -> %s; spikes -> Kafka", bootstrap, delta_path)
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    main()
