# The `brolga` command-line interface

This describes what `v0.1.0` ships. Commands that arrive later are listed at the bottom; they exist
in the binary today and fail with a documented exit code rather than being hidden.

`ingest`, `stats`, `show`, `sources`, and `quarantine` are implemented. `context` is not, and exits `5`.

## Output contract

**stdout is the answer. stderr is everything else.**

The rule is absolute, and it is what makes `brolga ... | jq` work. A stray log line on stdout breaks
every pipeline that parses it, and it breaks it *intermittently* — only when the condition that
produces the message happens to occur. Commands are handed a stream pair rather than reaching for
`println!`, and the workspace lints deny `print_stdout` and `print_stderr` so the rule cannot be
broken by accident.

| Stream | Carries | Affected by `--quiet` |
| --- | --- | --- |
| stdout | The command's result, in the selected `--output` mode | No |
| stderr | Progress, warnings, errors, and structured logs | Commentary yes; **errors never** |

`--quiet` silences commentary. It never silences the result — a script reading an empty stdout would
take it as an empty *result* — and it never silences an error, because a silent failure is the one
thing worse than a noisy one.

### What is never written, on any stream, at any log level

- **Resolved secret values.** `brolga-config` holds references and never loads a value, so there is
  nothing to leak. The guarantee is structural, not a filter someone maintains. An end-to-end test
  sets a distinctive value in the process environment, references it from configuration, runs four
  commands at trace level, and asserts the value appears nowhere.
- **Source bodies.** Imported narrative is untrusted, often large, and frequently restricted.
  Diagnostics name a record by identifier; content is retrieved explicitly by a caller that decided
  to.

## Exit codes

Exit codes are a **compatibility surface** under
[ADR 0001](adr/0001-workspace-boundaries-and-public-interface-versioning.md) §6. Adding a code is a
compatible change; changing what an existing code means is breaking, because it silently changes
automation nobody will re-test. The values are pinned by a unit test.

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `success` | The command did what was asked |
| 1 | `failure` | An error with no more specific code |
| 2 | `usage` | The command line was not understood |
| 3 | `config_invalid` | Configuration could not be loaded or did not validate |
| 4 | `storage` | Storage could not be opened, migrated, read, or written |
| 5 | `not_implemented` | The command exists but this build does not implement it |
| 6 | `io` | A file or stream could not be read or written |
| 7 | `policy_denied` | Reserved — policy refused the operation |
| 8 | `cancelled` | Reserved — the operation was cancelled or timed out |

Read them from the binary you are actually running, rather than from this table:

```bash
brolga --output json exit-codes
```

`2` follows the long-standing Unix convention for a usage error and is what `clap` already emits, so
scripts that special-case it keep working.

The distinctions earn their keep. `storage` is usually transient and worth retrying; `config_invalid`
is not, and needs a human. `not_implemented` is a version mismatch, not an outage. Collapsing them
into `1` pushes that decision into log-scraping, which breaks the first time a message is reworded.

`7` and `8` are reserved and nothing emits them yet. Fixing the numbers now means the milestone that
needs them is not choosing them under pressure alongside the feature.

## Global options

| Option | Default | Notes |
| --- | --- | --- |
| `-c`, `--config <PATH>` | none | Repeatable. Later files override earlier ones. |
| `-o`, `--output <human\|json>` | `human` | How the *result* is rendered on stdout. |
| `--log-level <error\|warn\|info\|debug\|trace>` | `info` | Diagnostics on stderr. |
| `--log-format <text\|json>` | `text` | `json` emits one object per line. |
| `-q`, `--quiet` | off | Silences commentary only. |
| `--no-color` | off | `NO_COLOR` and a non-terminal stdout do the same. |

`BROLGA_LOG` overrides the log filter with a full `tracing` directive, for the cases a single level
cannot express.

Every option is global, so it may be given before or after the subcommand — which is where people
type it.

### Configuration layering

Files are applied lowest to highest, on top of Brolga's built-in defaults:

```bash
brolga --config /etc/brolga/site.yaml --config ./host.yaml config explain --changed-only
```

`config explain` reports which layer supplied each setting. A layer only has to state what it
changes.

## Commands

### `brolga init [PATH] [--force]`

Writes a starter configuration file, defaulting to `brolga.yaml`. Refuses to overwrite an existing
file unless `--force` is given: silently replacing an operator's configuration because a flag was
forgotten is not something a tool should do.

The generated file is minimal and commented rather than a dump of every setting — a generated file
that lists everything is one operators stop reading, and it goes stale the moment a default changes.
A test writes it and then loads it, because a starter file that does not validate is worse than none:
the failure looks like the operator's mistake.

### `brolga doctor`

Checks what an operator would otherwise discover one failure at a time: configuration files parse,
configuration validates, storage opens, migrations are current, records are countable.

Every check runs even after an earlier one fails. The point is a complete picture in one run.

Exits `0` when every check passes, `3` otherwise. Reports the run's correlation identifier.

### `brolga config validate`

Loads the configured layers and reports **every** problem, each naming the setting's dotted path.
An operator fixing one error per run is an operator running the tool six times to learn six things it
knew on the first.

Exits `0` with the configuration fingerprint, or `3` with diagnostics on stderr.

### `brolga config explain [--changed-only]`

Shows every resolved setting, its value, and which layer supplied it — the question an operator
actually has when a layered configuration surprises them. `--changed-only` narrows to what differs
from the defaults, which is usually the short and interesting list.

For a secret this prints the **reference** — the environment variable name or file path — because
that is all the configuration has ever held. Redacting the reference too would leave an operator
unable to see where a value is meant to come from, which is the thing this command exists to answer.

### `brolga config schema`

Prints the configuration JSON Schema. Point an editor at it and a typo is caught before anything
runs.

Works even when the configured files are broken, because a broken configuration is exactly when
somebody needs the schema.

### `brolga exit-codes`

Prints the registry above, from the build you are running.

## Commands that are declared but not implemented

| Command | Exits | Arrives in |
| --- | --- | --- |
| `brolga ingest` | `5` | `v0.2.0 — Core ingestion` |
| `brolga context` | `5` | `v0.4.0 — Compression engine` |

They are declared rather than hidden so that a script written against a later Brolga fails with a
message naming the milestone, instead of an unhelpful "unrecognised subcommand". They accept
arguments and act on none, so the failure is about the version rather than about the arguments.

What they never do is *appear* to work. `CONTRIBUTING.md` prohibits placeholders in production paths,
and a command that prints "done" and does nothing is the worst kind. Nothing is written to stdout,
the message goes to stderr, and the exit code is `5`.

## Examples

```bash
# Start from scratch.
brolga init
brolga config validate

# Check an installation end to end.
brolga --config /etc/brolga/site.yaml doctor

# See only what a deployment changed from the defaults.
brolga -c site.yaml -c host.yaml config explain --changed-only

# Machine-readable, safe to pipe.
brolga --output json config validate | jq -r .fingerprint

# Branch on the exit code.
if brolga --quiet config validate; then
  echo "configuration is good"
else
  case $? in
    3) echo "fix the configuration" ;;
    4) echo "storage problem — may be transient" ;;
    *) echo "unexpected failure" ;;
  esac
fi
```
