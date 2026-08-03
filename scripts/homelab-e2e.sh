#!/usr/bin/env sh
# One-shot operator smoke: build, doctor, ingest demo feeds, context, optional API.
# Requires Docker Compose v2. From repository root:
#   ./scripts/homelab-e2e.sh
set -eu
cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found" >&2
  exit 1
fi

mkdir -p feeds lab/output
if [ ! -f .env ]; then
  token=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  printf 'BROLGA_API_TOKEN=%s\n' "$token" >.env
  echo "wrote .env with BROLGA_API_TOKEN" >&2
fi
# shellcheck disable=SC1091
set -a
. ./.env
set +a

echo "== build ==" >&2
docker compose build

echo "== doctor ==" >&2
docker compose run --rm brolga doctor

echo "== ingest demo ==" >&2
# Prefer baked image paths (works on remote Docker contexts). Host drops use /feeds-host.
docker compose run --rm brolga ingest \
  /feeds/demo-stix.json /feeds/demo-sigma.yml --mode permissive

echo "== context ==" >&2
docker compose run --rm brolga context ip 203.0.113.42

echo "== api ==" >&2
docker compose --profile serve up -d brolga-api
# Health via Compose network (works for remote Docker contexts; host 127.0.0.1 may not).
i=0
while [ "$i" -lt 30 ]; do
  if docker run --rm --network brolga_default curlimages/curl:8.5.0 \
    -sf "http://brolga-api:8787/api/v1/health" >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 1
done
docker run --rm --network brolga_default curlimages/curl:8.5.0 \
  -s "http://brolga-api:8787/api/v1/health"
echo
docker run --rm --network brolga_default curlimages/curl:8.5.0 \
  -s -H "Authorization: Bearer ${BROLGA_API_TOKEN}" \
  "http://brolga-api:8787/api/v1/stats"
echo
echo "homelab e2e ok" >&2
