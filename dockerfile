FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

ARG MODULE_SET=full

COPY requirements /app/requirements

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r /app/requirements/${MODULE_SET}.txt \
    && if [ "${MODULE_SET}" = "full" ]; then python -m spacy download en_core_web_sm; fi

COPY . /app

ENV HOST=0.0.0.0
ENV PORT=8000

CMD ["sh", "-c", "uvicorn api.main:app --host ${HOST} --port ${PORT}"]
