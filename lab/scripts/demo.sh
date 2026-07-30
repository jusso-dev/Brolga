#!/bin/sh
# Post-ingest proof: search, context packs, sources, checkpoints, plan.
set -eu
OUT=/output
DB=/data/brolga.sqlite
mkdir -p "$OUT" 2>/dev/null || true

echo "lab demo starting" >&2
cd /data

brolga doctor
brolga stats --database "$DB" --output json >"$OUT/demo-stats.json"
brolga search --database "$DB" --output json --limit 20 >"$OUT/demo-search.json" || true
brolga search --database "$DB" --query 'status = active' --output json --limit 20 \
  >"$OUT/demo-search-query.json" 2>"$OUT/demo-search-query.err" || true
brolga sources --database "$DB" --output json >"$OUT/demo-sources.json" || true
brolga quarantine --database "$DB" --output json >"$OUT/demo-quarantine.json" 2>/dev/null || true

# Context packs for the README journey address and related subjects.
brolga context ip 203.0.113.42 --database "$DB" --output json \
  >"$OUT/demo-context-ip.json" 2>"$OUT/demo-context-ip.err" || true
brolga context domain c2.example.net --database "$DB" --output json \
  >"$OUT/demo-context-domain.json" 2>"$OUT/demo-context-domain.err" || true
brolga context hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --database "$DB" --output json \
  >"$OUT/demo-context-hash.json" 2>"$OUT/demo-context-hash.err" || true

# Explain-plan does not need a database of records.
brolga explain-plan incident_triage --output json >"$OUT/demo-explain-plan.json" || true

# Checkpoint baseline for re-ingest / delta demos.
brolga checkpoint take lab-baseline --database "$DB" --output json \
  >"$OUT/demo-checkpoint.json" 2>"$OUT/demo-checkpoint.err" || true

echo "lab demo wrote artefacts under $OUT" >&2
ls -la "$OUT" >&2

# Hard fail if the demo journey IP has no pack at all (empty store).
if ! grep -q . "$OUT/demo-context-ip.json" 2>/dev/null; then
  echo "demo: missing context pack for 203.0.113.42 — did ingest-once run?" >&2
  exit 1
fi
