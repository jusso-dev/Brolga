# Storage backends

Brolga stores canonical records behind [`IntelligenceStore`](../crates/brolga-storage/src/store.rs).
Two backends implement that contract:

| Backend | Feature | Spec string |
| --- | --- | --- |
| SQLite | always | filesystem path (`brolga.sqlite`, `/data/brolga.sqlite`) |
| PostgreSQL | `postgres` on `brolga-storage` / `brolga-cli` | `postgres://…` or `postgresql://…` URL |

Open either form with [`OpenedStore::open`](../crates/brolga-storage/src/open.rs). Migration runs on
open. CLI example (postgres-enabled binary):

```bash
cargo build -p brolga-cli --features postgres
brolga search --database 'postgres://brolga@localhost/brolga' --query 'status = active'
```

## Schema migrations

Migration identifiers are a compatibility surface (ADR 0001 §6, ADR 0011):

- **Append-only.** New schema changes are new migration rows. Editing or reordering a released
  migration is a hard error on next open (checksum mismatch).
- **Same IDs for SQLite and PostgreSQL.** The SQLite SQL text is canonical for checksums;
  PostgreSQL applies a deterministic dialect transform at apply time.
- **Upgrade.** Opening a store applies pending migrations in order, each in its own transaction.
- **Rollback.** Reverse migrations are **not** provided. Recover by restoring a backup taken before
  the upgrade, or by creating an empty database and re-importing retained source evidence. Document
  backup ownership in your deployment runbook; Brolga does not delete volume data on restart.

### Operator checklist

1. Backup the SQLite file or take a PostgreSQL dump before upgrading the binary.
2. Deploy the new binary / image.
3. Start any command that opens the store (or `brolga doctor`) — migrations apply automatically.
4. If open fails with `MigrationChanged`, the binary and the database disagree about a released
   migration; do not force it. Restore the backup or investigate which build wrote the store.

## Shared contract tests

```bash
# SQLite contracts always run in the crate tests.
cargo test -p brolga-storage

# PostgreSQL contracts when a server is available:
BROLGA_POSTGRES_URL='postgres://brolga:secret@127.0.0.1:5432/brolga' \
  cargo test -p brolga-storage --features postgres --test postgres_contract
```

CI runs the PostgreSQL suite against a service container when the workflow is enabled.

## Safe query language

Human expressions compile to typed filters via `brolga-query` — never to SQL. Limits cover input
size, token count, AST depth, and result page size. See ADR 0011 and `brolga search --query`.
