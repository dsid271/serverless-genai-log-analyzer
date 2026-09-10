#!/bin/sh
set -e

echo "== health =="
curl -s http://localhost:8000/ | python -m json.tool
echo

echo "== registered plugins =="
curl -s http://localhost:8000/plugins | python -m json.tool
echo

echo "== ingest 3 logs (2 with PII) =="
curl -s -X POST http://localhost:8000/ingest --json @demo_payload.json | python -m json.tool
echo

echo "== waiting for analyzers =="
sleep 4
echo

echo "== incident + attached analyses =="
curl -s http://localhost:8000/incidents | python -m json.tool