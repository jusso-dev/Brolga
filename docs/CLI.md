# The `brolga` command-line interface

This describes what `v0.1.0` ships. Commands that arrive later are listed at the bottom; they exist
in the binary today and fail with a documented exit code rather than being hidden.

`ingest`, `fetch`, `context`, `mcp`, `explain-plan`, `mapping`, `plugin`, `llm`, `export`, `stats`,
`show`, `sources`, `quarantine`, `search`, `neighbours`, `checkpoint`, and `completion` are
implemented.

`brolga completion <shell>` prints a completion script generated from **this build's** command tree,
so it can never advertise a command the binary does not have — which would be worse than no
completion, because a completion list reads as documentation.

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

## Output modes

`--output` selects how the *result* on stdout is rendered. It never changes what a command does,
and never changes the exit code.

| Mode | For | Schema version |
|---|---|---|
| `human` | Reading. Reflows whenever it reads better. | None — do not parse it |
| `json` | One pretty-printed document per invocation. | Yes |
| `yaml` | The same document as `json`, in YAML. | Yes |
| `jsonl` | One record per line, for streaming and for `while read`. | Yes, on every line |
| `table` | Aligned columns for the commands that are naturally tabular. | None |

### The schema version

Every machine-readable payload carries a `schema` field:

```console
$ brolga --output json search | jq -r .schema
brolga.cli.output/1.0
```

This is a versioned compatibility surface under [ADR 0001 §6](adr/0001-repository-charter.md).
Adding a field is a compatible change and does not move the version. Removing a field, renaming
one, or changing a type does.

Check it rather than assuming it. A consumer that has to guess whether a field moved has no way to
fail safely:

```bash
schema=$(brolga --output json search | jq -r .schema)
case "$schema" in
  brolga.cli.output/1.*) ;;
  *) echo "unsupported Brolga output schema: $schema" >&2; exit 1 ;;
esac
```

`human` and `table` deliberately carry no version, because they carry no promise. Parsing them is
how a script ends up depending on a column width.

### JSONL

`jsonl` streams the members of the collection rather than one object containing an array, so a
consumer can act on the first record without waiting for the last:

```console
$ brolga --output jsonl search --kind intrusion_set
{"_collection":"entities","id":"entity:8fd8cd7f-...","kind":"intrusion_set","name":"Bunyip Panda","schema":"brolga.cli.output/1.0","status":"active"}
```

Safe query language ([#55](https://github.com/jusso-dev/Brolga/issues/55), ADR 0011) compiles to the
same typed filter — never SQL:

```bash
brolga search --query 'kind = threat_actor and status = active'
```


The envelope field is `_collection`, not `kind`, because `kind` is a real field on an entity and an
envelope that overwrote it would silently corrupt the value you filter on.


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
| `-o`, `--output <human\|json\|yaml\|jsonl\|table>` | `human` | How the *result* is rendered on stdout. See [Output modes](#output-modes). |
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

### `brolga serve`

Runs the read-only HTTP API so other services can pull context. See [the API reference](API.md).

```bash
brolga serve --database brolga.sqlite                 # loopback, no token
BROLGA_API_TOKEN=… brolga serve --bind 0.0.0.0:8787   # reachable, token required
```

Binding an address reachable from another host without `BROLGA_API_TOKEN` set is refused at
startup, exit code 3.

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

## `brolga fetch`

Retrieve intelligence from a remote platform. Read-only: Brolga never publishes upstream, and the
transport has no method that sends a body — so read-only is structural rather than a default
somebody can flip.

Two protocols, as subcommands, because a TAXII collection identifier and a MISP instance name are
different things and one flat argument set would accept combinations that mean nothing.

```bash
brolga fetch taxii https://taxii.example.org \
    --collection 91a7b528-80eb-42ed-a74d-c6fbd5a26116

BROLGA_MISP_KEY=... brolga fetch misp https://misp.example.org --name reef-misp

BROLGA_OPENCTI_TOKEN=... brolga fetch opencti https://opencti.example.org
```

Discovery is attempted at `/taxii2/` and then `/taxii/`, so give the **base URL** rather than
either path. The version is agreed from the `Content-Type` the server answers with, not guessed
from the body: a 2.1 envelope and a 2.0 bundle are distinguishable most of the time, and a client
that is usually right about which protocol it speaks mis-paginates the rest of the time.

Omitting `--collection` reads every collection the server marks readable. Naming one the server
does not offer is an error rather than an empty run, because the operator has a typo or the wrong
server and a silent success hides both.

`--discover-only` lists what a server offers and stops, storing nothing.

### What it refuses, and how to permit it

Outbound requests run under the same network policy the rest of Brolga uses. By default:

| Refused | Flag to permit |
| --- | --- |
| Plaintext HTTP | `--allow-http` |
| Private, loopback, and link-local addresses | `--allow-private` |
| The cloud metadata address `169.254.169.254` | **no flag** |
| A redirect that downgrades HTTPS to HTTP | no flag |
| More than three redirect hops | no flag |

The metadata address has no flag on purpose. Enabling internal fetches is not the same request as
"let a feed read my instance credentials", and a flag that permitted it would eventually be pasted
out of a forum post. Redirects are followed by Brolga rather than by the HTTP agent, and every hop
is re-checked — an agent that follows them internally connects before any check runs, which makes
the whole control decorative.

A refusal exits `2` (usage) and a server failure exits `6` (I/O), because one is a decision to
revisit and the other is somebody else's outage. A storage failure exits `4` and a timeout `8`.

### `brolga fetch misp`

Reads **events** — which carry their attributes, tags, and galaxy clusters inline — and **warning
lists**. Sightings, taxonomies, and object templates are deliberately not fetched: the parser has no
mapping for them, so fetching them would spend an operator's rate limit to produce records that
quarantine.

`--name` is the instance's identity and half of every cursor key it owns, defaulting to the URL's
host. An instance that moves hostname keeps its name and does not resync from the beginning; two
instances are never merged, because "three sources agree" and "one source polled three times" are
different facts.

MISP's `restSearch` is normally a `POST` with a JSON body. Brolga uses MISP's equivalent
path-parameter `GET` form instead, so the transport keeps having no method that sends a body. The
cost: a filter set large enough to overflow a URL cannot be expressed this way. Brolga's filters are
a page size, a page number, and a high-water mark, so it does not come close.

### `brolga fetch opencti`

Polls `stixCoreObjects` incrementally and hands each object's own `toStix` rendering to the STIX
parser — the same parser, over the same shape, as every other STIX source. Re-deriving Brolga's
records from OpenCTI's GraphQL fields would be a second mapping that can disagree with the first.

An object OpenCTI cannot render as STIX is **counted, not skipped**, and appears in the run's
quarantined total. A half-imported page that said nothing would look identical to a whole one.

Every query is compiled into Brolga. There is no way to supply GraphQL on the command line or in
configuration, and no compiled-in operation is a mutation — a test walks all of them to check. See
[ADR 0006](adr/0006-a-closed-set-of-query-bodies.md) for why the transport gained a body-sending
method at all, and what replaced the guarantee it removed.

A redirect answering a query is refused rather than followed. Re-posting a body to a location a
server chose is how a query aimed at a configured endpoint ends up delivered somewhere else.

### Credentials

TAXII reads `BROLGA_TAXII_TOKEN`; MISP reads `BROLGA_MISP_KEY`; OpenCTI reads
`BROLGA_OPENCTI_TOKEN`. Never a flag. A credential on a command line is in the shell
history, in `ps` output, and in any process listing the machine keeps. The `Bearer ` prefix is
added if it is not already there.

```bash
BROLGA_TAXII_TOKEN=abc123 brolga fetch taxii https://taxii.example.org
BROLGA_MISP_KEY=abc123    brolga fetch misp  https://misp.example.org
```

No error message, log line, or stored record carries either credential. TAXII takes a `Bearer`
prefix, added if it is not already there; MISP takes the raw key, which is what it expects.

A MISP key is checked with one cheap `getVersion` call before any sync, so a wrong key fails
immediately rather than part way through a paginated run that has already written a cursor.

### Resuming

Each feed has a cursor keyed on `(connector, feed)` — `(taxii, <collection id>)` or
`(misp, <instance>/<feed>)`, and never on the URL, so a server that moves hostname is still the same
feed and does not restart from the beginning. A run sends the
stored `added_after` and, unless `--no-etag` is given, the stored `ETag`; a `304` costs a round trip
instead of a body.

**The cursor never moves ahead of stored data.** A page is fetched, ingested, and only then does the
cursor advance, both inside one transaction. A malformed page therefore leaves the cursor where the
last good page put it and the next run re-fetches that window — the reverse ordering would skip it
permanently and report nothing, because the following run would simply start after the gap.

A run stopped by `--max-pages`, by `--timeout-seconds`, or by a failure reports `partial` or
`failed` rather than a count that looks like success:

```
91a7b528…  4 page(s), 384 object(s), 372 stored, 12 quarantined — partial
```

`complete` and `not_modified` are the only statuses that mean the feed has nothing outstanding.

## `brolga explain-plan`

Show what a context profile will do, before it does it — with no store, no subject, and no
retrieval.

```bash
brolga explain-plan                    # every profile
brolga explain-plan incident_triage    # one profile's plan
```

```
findings        include  weight 50  (profile)
relationships   rank     weight 50  (default)
clusters        exclude  weight 50  (profile)
evidence        include  weight 50  (floor)
```

Every line says **why**, not only what. "Why did my pack not contain relationships?" has three
different fixes depending on whether the section was named by the profile, left to the default, or
held by the floor — and `include` alone distinguishes none of them.

### Profiles

One shipped profile per purpose the context API accepts: `incident_triage`, `threat_hunting`,
`malware_analysis`, `actor_research`, `vulnerability_prioritisation`, `executive_briefing`,
`detection_engineering`, `exposure_assessment`, `supply_chain_investigation`, `case_enrichment`,
and `raw_research`. All of them are ordinary editable profiles, not hard-coded behaviour.

A profile states, per section, one of:

| Preservation | Meaning |
| --- | --- |
| `required` | Always present, whatever a budget or a score says |
| `preferred` | Ranked against everything else, included if it fits |
| `excluded` | Never present |

**A hard rule is not a high score.** `required` is absolute: no budget and no ranking pass may drop
it. Expressing preservation as a very large weight is the obvious alternative and is wrong — a
weight competes, and something that competes eventually loses to a tighter budget or to a bigger
weight somebody adds later. An operator who says "always keep the markings" means always.

### The floor

`evidence`, `markings`, and `gaps` cannot be excluded by **any** profile. They are not content;
they are what makes content usable. A pack without evidence cannot be defended, one without
markings cannot be safely forwarded, and one without gaps reads as complete when it is not. An
operator optimising for size would reach for exactly these three.

A profile that tries fails to load, naming the section.

### What a profile cannot do

There is no field for a marking, a recipient, an authorisation, or a clearance. A profile selects
among things the caller is *already entitled to see*, so the worst a misconfigured one can do is ask
for less. A profile is the most-edited file in a deployment, and the most-edited file should not be
able to widen a policy decision.

There is also no expression, script, or callback — a profile is weights, lists, and numbers. A
profile that could compute would be a program running inside a configuration file, in a process
holding an intelligence database.

### Validation and fingerprints

An impossible profile fails **before retrieval**, not by producing a pack that honoured whichever
rule was evaluated last. Over-allocated budgets, inheritance cycles, unknown parents, unknown
section names, and out-of-range weights are all load-time errors, and validation reports *every*
problem rather than the first.

`fingerprint` identifies what a profile **does**, not what it says: renaming one does not change it,
and changing a rule does. That is what makes it useful for answering "has the plan changed since
this pack was built?".

## `brolga context`

What Brolga knows about one observable.

```bash
brolga context ip 203.0.113.42
brolga context domain evil.example.com --detail-level L2 --output json
```

The value is canonicalised before lookup, so the spelling you have is fine — `EXAMPLE.COM.` and
`example.com` reach the same record.

**The same pack the API serves.** Assembly lives in one place and every interface calls it. A CLI
that built its own pack would eventually disagree with the HTTP one, and the disagreement would
surface in front of an analyst comparing a terminal to a case file.

`--detail-level` takes `L0` through `L3`. `L4` and `L5` are refused here with a usage error rather
than accepted and failed later: they are reached by expanding a handle, and the handles are in the
pack's `handles` array.

In human mode the finding and the claims go to stdout and the gaps and exclusions go to stderr, so
`--quiet` silences the commentary without silencing the answer. In JSON mode the whole pack is one
object on stdout.

### Policy

A local run is a **stated identity**: `policy.recipient` says `local-operator`. Somebody running the
command holds the database file, so withholding TLP:RED from them would be theatre — but the grant
is visible in the output and goes through the same policy code the server uses, rather than skipping
the check.

That is why the identity is named rather than assumed: the network path cannot reach local-operator
access by simply not identifying itself.

## `brolga mcp`

Serves the Model Context Protocol over stdio, so an agent runtime can start Brolga as a subprocess.

```json
{"command": "brolga", "args": ["mcp", "--database", "/var/lib/brolga/brolga.sqlite"]}
```

JSON-RPC frames go on stdin and stdout, one per line. Everything meant for a human goes to stderr —
a diagnostic on stdout would be an unparseable frame on the agent's stream.

### Tools

| Tool | Answers |
| --- | --- |
| `brolga_context` | What is known about one observable, as a versioned context pack |
| `brolga_neighbours` | What is connected to an entity |
| `brolga_stats` | How many records of each kind the store holds |

**Intent tools, not a query surface.** An agent handed a query language composes questions nobody
designed the answers for — and the answers are what carry the evidence, the markings, and the gaps.
A tool returning rows would return them without any of that.

The list is deliberately short: every tool is backed by a capability that exists and is tested. A
tool that returned an empty result would be worse than an absent one, because an agent treats "no
results" as an answer.

### What an agent cannot reach

**Raw source objects.** `brolga_context` serves `L0`–`L3`. Asking for `L4` or `L5` is refused with
a code and a message saying to expand a handle instead — expansion is a policy decision per object,
and a tool that served source material would make one call cover an unbounded amount of somebody
else's licensed content.

**Anything that writes.** There is no mutation tool, and there is nothing upstream of Brolga an
agent can reach through it.

### Budgets and uncertainty

Every result states its budget — requested, returned, and whether it was exhausted — whether or not
it bit. An agent cannot tell a complete answer from a truncated one by counting, and will treat the
second as the first.

Packs keep their `gaps`, `exclusions`, and `policy` across the tool boundary. An agent acting on a
pack needs to know what it does not contain as much as what it does.

### Errors

Refusals are JSON-RPC errors with standard codes, not prose. An agent handed a sentence retries,
rephrases, and eventually reports something that did not happen.

One malformed frame is answered and the session continues, rather than the connection dropping and
the agent retrying the whole conversation.

## `brolga mapping`

Read a structured format nobody wrote a parser for, through a declarative mapping.

```bash
brolga mapping validate examples/mappings/acme-json.yml
brolga mapping explain  examples/mappings/acme-json.yml
brolga ingest feed.json --mapping examples/mappings/acme-json.yml
```

`validate` exits `0` only if the mapping would run. `explain` prints what it will do — and what the
engine refuses to do whatever the mapping says, which is the half that matters when the mapping came
from somewhere else. Neither reads a feed, opens a store, or touches a network.

An invalid mapping exits `3` (configuration invalid), not `2` (usage): the command line was fine and
the operator's file was not, and a script has to be able to tell the two apart.

## `brolga plugin`

Validate and explain a **plugin manifest** for the `brolga-plugin-sdk` / WIT ABI
(`brolga:plugin@0.1.0`). Manifest commands work in the default binary.

```bash
brolga plugin validate examples/plugins/parser-manifest.yml
brolga plugin explain  examples/plugins/parser-manifest.yml
```

`explain` always lists fixed refusals (no native `dlopen`, no FS/network without scoped grants,
policy extensions are advisory only, plugin output is untrusted). An invalid manifest exits `3`.

### Execution (`--features plugins`)

WebAssembly execution is off by default (ADR 0001 §3). Build with the feature to enable the host:

```bash
cargo build -p brolga-cli --features plugins
brolga plugin run examples/plugins/echo --extension parser --contract 1.0
brolga plugin run examples/plugins/exporter --extension exporter --contract 1.0
```

The package directory needs `manifest.yml` and usually `component.wasm`. The sandbox has empty host
imports (no WASI), fuel, and wall-clock caps. Guest errors print as failure exit codes.

Full author guide: [PLUGIN-DEVELOPMENT.md](PLUGIN-DEVELOPMENT.md).

## `brolga llm`

Optional language-model **proposals** (ADR 0010, [#49](https://github.com/jusso-dev/Brolga/issues/49)).
Default builds never call a model.

```bash
brolga llm status
# Propose requires a build with --features llm
cargo build -p brolga-cli --features llm
brolga llm propose 1.2.3.4 --evidence ./notes.txt --provider mock
```

| Subcommand | Default build | With `--features llm` |
| --- | --- | --- |
| `status` | Reports feature disabled | Reports feature enabled |
| `propose` | Exit `5` (not implemented) | Calls the named provider |

Providers: `mock` (no network), `disabled`, `ollama` / `llamacpp` (loopback OpenAI-compat HTTP),
`openai` (library path for remote + redistribute policy; CLI refuses a bare remote until configured).

Every proposal is **untrusted** and **unverified**. There is no tool channel on the wire.

### A mapping is data, not code

There is no expression evaluator, and that is the design rather than a limitation to be lifted later.
A mapping has **paths**, which select values, and **transforms**, which are a closed list of named
string operations. It cannot branch, loop, call anything, or name a transform this build does not
have — a mapping naming one fails to *load*, before a byte of feed data is read.

Everything is bounded and the bounds are stated in the file:

| Bound | Default | Ceiling this build enforces |
| --- | --- | --- |
| Records per document | 100,000 | 5,000,000 |
| Nodes per path evaluation | 100,000 | 5,000,000 |
| Path segments | — | 16 |
| Wildcards per path | — | 2 |
| Transforms per field | — | 8 |
| Transform output | — | 8 KiB |

A mapping may **lower** its own limits and never raise them. Exceeding a bound is an error, never a
truncated result — a partial answer silently understates a document, and a caller that could not tell
the difference would report a short answer as a complete one.

### What the paths deliberately cannot express

`a.b[0].c`, `items[*].value`, `@attribute` for XML, a header name or `[n]` for CSV. That is the whole
grammar.

Refused **by name**, so a pasted JSONPath expression says what to remove rather than matching
nothing: `..` (recursive descent — it walks a document of unknown depth, so its cost cannot be read
off the expression), `[?(…)]` (filter predicates — an expression language), `[a,b]` (unions),
`[1:3]` (slices), and `@.` (the current-node reference that predicates need).

### What a mapping cannot produce

One observable per record — the **subject** — and claims about it. Exactly one field must be marked
`subject: true`, and its target must be an observable.

A mapping cannot mint an entity or a relationship. An entity needs a canonical identity rule for its
kind, and letting a mapping create entities from arbitrary strings would put thousands of
near-duplicate hubs in the graph: `Acme Corp`, `ACME Corp.`, and `acme corp` as three actors. An
observable has a canonicaliser that makes identity a function of the value; an entity name does not.

### `--mapping` replaces the compiled parsers for that batch

The mapping becomes the only parser for the files in that invocation. A mixed batch of a STIX bundle
and an in-house CSV is two invocations.

That is deliberate. Registering the mapping alongside the compiled parsers was the first design and
it does not work: the registry resolves a tie below `certain` by parser identifier, and the permissive
flat JSON and delimited readers claim `strong` on anything JSON-shaped or comma-shaped — so a mapping
would lose to `brolga.flat.json` on an alphabetical accident. Losing silently to a generic reader is
the worst available outcome for an operator who named a mapping.

Detection still earns its place: a mapping declares its source shape, and a mapping pointed at the
wrong kind of file is **declined** and the ingest fails. The alternative is running paths that cannot
match and reporting a successful import of nothing.

### XML

The same reader every XML format in Brolga uses. Any `<!DOCTYPE>` is refused outright before parsing,
which closes the whole entity-expansion family, and a mapping cannot opt out of it.

## `brolga export formats` and `brolga context --format`

```bash
brolga export formats                                   # what each one costs you
brolga context ip 203.0.113.42 --format markdown        # a report
brolga context ip 203.0.113.42 --format stix > b.json   # a bundle for another platform
```

Thirteen formats. `--format` writes the bytes to stdout unchanged — nothing appended, wrapped, or
re-encoded, because an export is somebody else's input — and writes **what the format does not carry**
to stderr. A shell redirect therefore captures the artefact while the operator still learns what is
missing from it.

### Policy runs after the format is chosen, and that ordering is the point

Which capability an export needs depends on the format:

| Orientation | Formats | Needs |
| --- | --- | --- |
| `machine` | `json`, `compact`, `yaml`, `jsonl`, `csv`, `sarif` | `read` |
| `human` | `markdown`, `text`, `dot`, `sigma`, `hunt` | `read` |
| `agent` | `brief` | `read` |
| `interchange` | `stix`, `misp` | `redistribute` |

Reading your own pack as Markdown is a read. Producing a STIX bundle creates an artefact whose whole
purpose is to be handed to another platform, and that is redistribution. A gate placed before format
selection could not tell them apart, so it would have to demand the stronger capability for
everything — and an operator would be unable to read their own pack as text.

An export the identity may not have exits `6` (policy denied) and produces **no bytes**, not truncated
ones. See [ADR 0007](adr/0007-export-crate-boundary-and-the-policy-gate.md) for how the gate is made
unbypassable rather than merely present.

### Lossiness is declared, and the lossless claim is tested

| Level | Meaning |
| --- | --- |
| `lossless` | Round-trips to an equal pack. Tested by round-tripping. |
| `lossless_structural` | Every field survives; the container does not (JSONL). |
| `partially_lossless` | Some fields have nowhere to go. The export names them. |
| `compressed` | Items were condensed rather than dropped. |
| `derived` | Fields were *invented* — a DOT node's colour is this exporter's choice, not intelligence. |
| `narrative` | Prose. Faithful in meaning, not in structure; wording is not a compatibility surface. |

### What the formats refuse to do

- **CSV escapes every value against spreadsheet formula execution.** A cell reading
  `=cmd|'/c calc'!A0` runs when the file is double-clicked, the value came from a feed, and CSV exists
  to be opened in a spreadsheet. The cost is a visible `'` on a handful of cells, including making
  `-1` render as `'-1` — the rule has no "looks like a number" exception, because such an exception is
  one an attacker formats around.
- **Sigma emits no `logsource`, so the rule does not run.** Brolga does not know which of your log
  sources carries a field, and a guessed one either matches nothing — a silent false negative in a
  detection pipeline — or matches the wrong field. Complete it and review before deploying.
- **SARIF invents no file locations, and says when it does not apply.** A pack about a network
  indicator has no place in a source tree; it exports as a notification with
  `brolgaApplicable: false` rather than as a result a code-scanning tool would annotate.
- **MISP omits `Orgc`, object templates, and galaxy clusters,** each of which needs configuration
  shared with the receiving instance. Fabricating one attributes intelligence to an organisation or
  an actor Brolga has no basis to name. Events are exported unpublished, with distribution `0`.
- **STIX and MISP identifiers are derived from pack content, not generated.** Re-exporting an
  unchanged pack produces byte-identical output, so a consumer re-ingesting it creates no duplicates.
- **Nothing is pushed anywhere.** Export writes bytes. There is no code in Brolga that publishes to a
  SIEM or writes back to an upstream platform.
