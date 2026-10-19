# Multi-stage build with one target per component. Each component gets its own
# image and runs as its own container (see docker-compose.yml):
#   docker build --target api   -t genai-log-analyzer .        (default: last stage)
#   docker build --target spark -t genai-log-analyzer-spark .
#
# Layout: base -> <component>-builder (pip install into a venv) -> <component>
# The runtime stages copy only the finished venv, so pip caches and build
# leftovers stay out of the final images, and each image carries only its own
# dependencies (the Spark image has no spaCy/chromadb, the API has no Java).

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app


# ---- Spark: dependency build -------------------------------------------------
FROM base AS spark-builder

COPY requirements/spark.txt /tmp/requirements/spark.txt
RUN python -m venv /opt/venv \
    && python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r /tmp/requirements/spark.txt


# ---- API: dependency build ---------------------------------------------------
FROM base AS api-builder

COPY requirements/full.txt /tmp/requirements/full.txt
RUN python -m venv /opt/venv \
    && python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r /tmp/requirements/full.txt \
    && (python -m spacy download en_core_web_sm || true)


# ---- Spark: runtime (Structured Streaming job, local mode) -------------------
FROM base AS spark

ENV PYTHONPATH=/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-21-jre-headless procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=spark-builder /opt/venv /opt/venv
COPY . /app

CMD ["python", "-m", "spark.streaming_job"]


# ---- API: runtime (last stage, so a plain `docker build .` produces this) ----
FROM base AS api

COPY --from=api-builder /opt/venv /opt/venv
COPY . /app

ENV HOST=0.0.0.0
ENV PORT=8000

CMD ["sh", "-c", "uvicorn api.main:app --host ${HOST} --port ${PORT}"]
