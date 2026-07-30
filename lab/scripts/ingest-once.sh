#!/bin/sh
# Ingest every enabled fixture file into the lab SQLite volume.
set -eu
OUT=/output
mkdir -p "$OUT"
DB=/data/brolga.sqlite

echo "lab ingest-once starting" >&2
brolga doctor || true

# Ingest local feed mounts (deterministic fixtures).
# Paths match lab/fixtures layout. Database is cwd-relative default on /data.
cd /data
status=0
for path in \
  /feeds/plain/iocs.txt \
  /feeds/csv/indicators.csv \
  /feeds/json/bundle.json \
  /feeds/stix/attack-snippet.json \
  /feeds/malformed/not-json.txt
do
  if [ -f "$path" ]; then
    base=$(basename "$path")
    echo "ingest $path" >&2
    if brolga ingest "$path" --database "$DB" --output json >"$OUT/ingest-${base}.json" 2>"$OUT/ingest-${base}.err"; then
      echo "ok $path" >&2
    else
      echo "fail-or-quarantine $path (see .err)" >&2
      # Malformed may fail intentionally; do not abort the batch.
      status=0
    fi
  fi
done

brolga stats --database "$DB" --output json >"$OUT/stats.json" || true
brolga quarantine --database "$DB" --output json >"$OUT/quarantine.json" 2>/dev/null || true
echo "lab ingest-once finished" >&2
exit "$status"
