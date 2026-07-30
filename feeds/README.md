# Feeds drop directory

Bind-mounted read-only at **`/feeds-host`** (not `/feeds`) for the root `docker-compose.yml`
service. Image demo files stay at `/feeds/demo-misp.json` and `/feeds/demo-sigma.yml`.

```bash
# Demo (baked into the image — works with remote Docker contexts)
docker compose run --rm brolga ingest \
  /feeds/demo-misp.json /feeds/demo-sigma.yml --mode permissive

# Your own files (this directory → /feeds-host)
docker compose run --rm brolga ingest /feeds-host/your-bundle.json --mode permissive
```

Do not put credentials or live tokens in this tree.
