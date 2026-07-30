#!/bin/sh
# Post-ingest checks: search, stats, optional context.
set -eu
OUT=/output
DB=/data/brolga.sqlite
mkdir -p "$OUT"

echo "lab demo starting" >&2
cd /data
brolga doctor
brolga stats --database "$DB" --output json >"$OUT/demo-stats.json"
brolga search --database "$DB" --output json --limit 20 >"$OUT/demo-search.json" || true
brolga search --database "$DB" --query 'status = active' --output json --limit 20 \
  >"$OUT/demo-search-query.json" 2>"$OUT/demo-search-query.err" || true
brolga sources --database "$DB" --output json >"$OUT/demo-sources.json" || true

echo "lab demo wrote artefacts under $OUT" >&2
ls -la "$OUT" >&2
