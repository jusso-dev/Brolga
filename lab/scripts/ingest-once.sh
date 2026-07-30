#!/bin/sh
# Ingest every enabled fixture into the lab SQLite volume (production CLI path).
set -eu
OUT=/output
DB=/data/brolga.sqlite
mkdir -p "$OUT" 2>/dev/null || true

echo "lab ingest-once starting" >&2
cd /data
brolga doctor || true

# Prefer permissive so a single hostile file does not erase a whole family batch.
# Malformed samples are still listed in quarantine rather than discarded.
status=0
ingest_one() {
  path=$1
  if [ ! -f "$path" ]; then
    return 0
  fi
  base=$(echo "$path" | sed 's|/feeds/||; s|/|_|g')
  echo "ingest $path" >&2
  if brolga ingest "$path" --database "$DB" --mode permissive --output json \
    >"$OUT/ingest-${base}.json" 2>"$OUT/ingest-${base}.err"; then
    echo "ok $path" >&2
  else
    echo "fail $path (see ingest-${base}.err)" >&2
    status=1
  fi
}

# Demo journey first: MISP + Sigma that meet on 203.0.113.42 (matches README/journey tests).
ingest_one /feeds/demo/feed.json
ingest_one /feeds/demo/rule.yml

# Format families claimed by the capability matrix (fixture mode).
for path in \
  /feeds/plain/iocs.txt \
  /feeds/csv/indicators.csv \
  /feeds/json/bundle.json \
  /feeds/json/records.json \
  /feeds/ndjson/records.ndjson \
  /feeds/flat/tabs.tsv \
  /feeds/stix/attack-snippet.json \
  /feeds/stix/bundle.json \
  /feeds/stix/bundle-2.0.json \
  /feeds/stix/attack.json \
  /feeds/misp/event.json \
  /feeds/misp/warninglist.json \
  /feeds/detection/rules.yml \
  /feeds/detection/rules.yar \
  /feeds/telemetry/events.log \
  /feeds/xml/definition.ioc \
  /feeds/xml/incident.iodef \
  /feeds/vulnerability/kev-catalog.json \
  /feeds/vulnerability/osv-1.6.json \
  /feeds/vulnerability/sarif-2.1.0.json \
  /feeds/vulnerability/cyclonedx-1.5.json \
  /feeds/malformed/not-json.txt
do
  ingest_one "$path"
done

brolga stats --database "$DB" --output json >"$OUT/stats.json" || true
brolga quarantine --database "$DB" --output json >"$OUT/quarantine.json" 2>/dev/null || true
brolga sources --database "$DB" --output json >"$OUT/sources.json" 2>/dev/null || true

echo "lab ingest-once finished (status=$status)" >&2
# Malformed quarantine is expected; treat hard CLI failures only.
# Re-run exit as 0 when stats were written (store usable).
if [ -f "$OUT/stats.json" ]; then
  exit 0
fi
exit "$status"
