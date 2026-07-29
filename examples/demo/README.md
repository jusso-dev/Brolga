# Demo fixtures

Two files, deliberately small enough to read.

- `feed.json` — a MISP event with three attributes: an address, a domain, and a SHA-256.
- `rule.yml` — a Sigma rule naming the same address and domain.

They overlap on purpose. Ingesting both is what makes the demo show a graph rather than two
unrelated imports: the detection rule and the feed attribute meet at one observable, because both
canonicalise to the same identifier.

Nothing here is real. `203.0.113.42` is TEST-NET-3 and `example.net` is reserved for documentation,
so running the demo cannot resolve or contact anything.
