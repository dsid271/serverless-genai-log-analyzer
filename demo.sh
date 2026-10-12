#!/bin/sh
# Usage: API_KEY=<key> sh demo.sh   (API_KEY is only needed when ENABLE_AUTH=true)
# On Windows run it from Git Bash, not PowerShell.
set -e

# Send X-API-Key only when API_KEY is set.
api() {
  if [ -n "${API_KEY:-}" ]; then
    curl -s -H "X-API-Key: $API_KEY" "$@"
  else
    curl -s "$@"
  fi
}

echo "== health =="
api http://localhost:8000/ | python -m json.tool
echo

echo "== registered plugins =="
api http://localhost:8000/plugins | python -m json.tool
echo

echo "== ingest 3 logs (2 with PII) =="
api -X POST http://localhost:8000/ingest --json @demo_payload.json | python -m json.tool
echo

echo "== waiting for analyzers =="
sleep 4
echo

echo "== incident + attached analyses =="
api http://localhost:8000/incidents | python -m json.tool