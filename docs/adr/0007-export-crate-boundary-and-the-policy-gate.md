# ADR 0007 — The export crate boundary, and a policy gate that cannot be bypassed

- Status: accepted
- Date: 2026-07-30
- Milestone: `v0.8.0 — Exporters`
- Issue: [#54](https://github.com/jusso-dev/Brolga/issues/54)
- Amends: [ADR 0001](0001-workspace-boundaries-and-public-interface-versioning.md) §1, which names
  `brolga-export` as a crate introduced by the milestone that first needs it. Every other section of
  0001 stands, including §2's layering rule, which this record applies rather than changes.

## Context

`v0.8.0` requires thirteen export formats, and requires that "policy runs after format selection and
before bytes emit". Both halves matter, and the second is the one that decides the shape of the crate.

The obvious implementation is a function per format taking a `ContextPack`, with a policy check at
each call site. That works until somebody adds the fourteenth format and forgets the check — and the
failure is silent, because an export that skipped its policy decision produces valid bytes. Nothing
fails, nothing logs, and material leaves the process.

The ordering requirement makes the naive version worse rather than better. **Which capability an
export needs depends on the format chosen.** Rendering a pack as Markdown for the operator who asked
for it is a read. Rendering it as a STIX bundle produces an interchange artefact whose entire purpose
is to be handed to another platform, and that is redistribution — a different decision, under
different markings. A gate placed before format selection cannot distinguish them, so it would have
to demand the stronger capability for every export, and an operator would be unable to read their own
pack as text without redistribution rights.

## Decision

### 1. `brolga-export` is a new crate at layer 2

It may depend on `brolga-model`, `brolga-security`, and `brolga-config` (for the policy vocabulary),
and on nothing else first-party. In particular it does **not** depend on `brolga-storage`: an
exporter is given a pack and cannot reach a store, so there is no path by which an export could
retrieve material the pack's own policy decision did not cover.

Under ADR 0001 §2 that places it above `brolga-config` and `brolga-storage` (layer 1) and below
`brolga-core` (layer 2 in the original table). It sits beside `brolga-ingest`, `brolga-graph`, and
`brolga-connectors` as an adapter crate: it depends on canonical interfaces, and canonical types
never depend on STIX, MISP, SARIF, or any other vendor model.

### 2. The gate is a type, not a convention

An `Exporter` cannot be called with a `ContextPack`. It can only be called with a `Cleared`, and the
only way to construct a `Cleared` is `clear`, which performs the policy decision.

    pub fn clear<'pack>(
        pack: &'pack ContextPack,
        identity: &'pack PolicyIdentity,
        exporter: &dyn Exporter,
    ) -> Result<Cleared<'pack>, ExportError>;

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError>;

`Cleared`'s fields are private and it has no public constructor. There is no `emit(&ContextPack)` to
forget to guard, so a new exporter is gated by construction. Adding an unguarded path would mean
changing the trait signature, which a reviewer sees.

Note what `clear` takes: the *exporter*, not a capability. The capability comes from
`Exporter::capability`, which is defaulted on the exporter's declared orientation. An interchange
format therefore requires `Capability::Redistribute` unless its author deliberately overrides the
default — rather than requiring it only if its author remembered to say so.

### 3. Every exporter declares a version, an orientation, and a lossiness, and the trait defaults none of them

`ExportMetadata` has no `Default`. An exporter that did not state its lossiness would not compile.

`Lossiness::Lossless` is the only claim a test can falsify, and it is tested: every exporter claiming
it is round-tripped back to an equal pack. An exporter whose lossiness *requires* declared losses —
`PartiallyLossless`, `Compressed`, `Derived` — must return them non-empty, checked across the whole
registry rather than per format, so a new exporter is covered the moment it is registered.

### 4. An exporter is a pure function from a cleared pack to bytes

No filesystem, no network, no clock, no randomness, no template evaluation.

Each prohibition earns its place:

- **No template engine.** A template language is a program stored in a data file, evaluated in a
  process holding an intelligence database, over input that includes feed text. Every writer in the
  crate is hand-written Rust. The cost is that changing wording means changing code.
- **No clock or randomness**, so an export is deterministic. This is not only tidiness: the STIX and
  MISP exporters derive object identifiers from pack content, and a v4 UUID would make re-exporting
  an unchanged pack create a duplicate of everything on the receiving platform.
- **No filesystem or network**, so an exporter cannot emit a file it was not given, and cannot send
  what it was handed anywhere. #54's non-goal — no SIEM execution, no upstream write-back — is
  guaranteed by there being nothing to call, not by a rule.
- **No secrets**, because the pack is the whole input and a pack has never held a credential.

### 5. Untrusted text is escaped per target syntax, at the single point where it reaches the output

A pack quotes feeds. Every format whose output is a language gets one escaping function, and it is
the only route by which a value reaches the bytes:

| Format | Threat | Rule |
| --- | --- | --- |
| CSV | Spreadsheet formula execution on open | Prefix a leading `=`, `+`, `-`, `@`, tab, or CR with `'` |
| Markdown | Injected heading, link, image, code fence, raw HTML | Escape inline-active characters; neutralise newlines |
| DOT | Injected node, edge, or attribute | Escape `\` and `"`; render newline as `\n` inside the literal |
| Sigma YAML | Injected key, alias, anchor, or tag | Always double-quote, always escape |
| STIX pattern | Escaping the string literal | Escape `\` and `'` |

CSV is the one worth naming explicitly, because the fix looks cosmetic. A cell reading
`=cmd|'/c calc'!A0` executes when the file is double-clicked, the value came from a feed, and CSV
exists to be opened in a spreadsheet. The cost is a visible apostrophe in a handful of cells.

### 6. A format that does not fit says so rather than inventing a fit

Three cases, one rule:

- **SARIF** describes findings about a codebase. A pack about a network indicator has no location in
  anybody's source tree, so the exporter reports `brolgaApplicable: false` and emits a notification
  rather than results. Every result it does emit carries **no `locations` array**, which SARIF
  permits — a fabricated `src/main.rs:1` would draw an annotation on an unrelated line and train
  people to ignore annotations.
- **Sigma** emits a document with **no `logsource`**, so it does not run. Brolga does not know which
  of the operator's log sources carries a field, and a guessed one either matches nothing — a silent
  false negative in a detection pipeline — or matches the wrong field. The absence is stated in a
  comment a person reads and in `status: experimental`, which a rule-management tool reads.
- **MISP** omits `Orgc`, object templates, and galaxy clusters. Each needs configuration shared with
  the receiving instance, and fabricating any of them attributes intelligence to an organisation or
  an actor that Brolga has no basis to name.

## Alternatives rejected

**A policy check at each call site.** The failure mode is a silent one: a forgotten check produces
valid bytes and no error. Rejected in favour of a type that makes the check unforgettable.

**One capability for every export.** Simpler, and it makes an operator unable to read their own pack
as Markdown without redistribution rights. Rejected because it collapses a distinction that matters.

**Filtering the pack inside the exporter.** Considered and rejected: it would put a policy decision
in thirteen places, each of which could get it subtly differently, and it would make an exporter's
output depend on something other than its input.

**Emitting SARIF results with a synthesised location.** Rejected. A SARIF consumer acts on locations.

**Generating a runnable Sigma rule with a guessed log source.** Rejected. The failure is silent and
lands in a detection pipeline, which is the worst place for a silent failure.

## Consequences accepted

- **Thirteen hand-written writers.** No template engine means no way to add a format without writing
  Rust, and no way for a deployment to add one at all until the plugin ABI ([#46](https://github.com/jusso-dev/Brolga/issues/46))
  exists. Accepted: a plugin-supplied exporter is a different decision, and it will need its own gate.
- **`-1` renders as `'-1` in CSV.** The escaping rule has no exception for "looks like a negative
  number", because a rule with an exception is a rule an attacker formats around.
- **A Markdown export's wording is not a compatibility surface.** `Orientation::Human` says so. A
  consumer parsing prose is doing something the crate does not support.
- **Interchange formats need a stronger capability than most callers hold by default.** An
  `anonymous` identity cannot produce a STIX bundle. That is the intended behaviour and it will
  surface as a refusal rather than as an empty file.
