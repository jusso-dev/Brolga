# Host feed drop directory

Compose binds this directory at `/feeds-host` (and ships image demos at `/feeds`).

```bash
docker compose run --rm brolga ingest \
  /feeds/demo-stix.json /feeds/demo-sigma.yml --mode permissive
```

Put additional STIX or flat files in `./feeds` and ingest from `/feeds-host/…`.
