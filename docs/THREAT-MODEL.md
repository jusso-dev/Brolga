# Brolga threat model

Status: baseline for `v0.1.0`, covering every trust boundary named in
[docs/ARCHITECTURE.md](ARCHITECTURE.md).

This document states what Brolga assumes, what it defends against, and what it does not. The types
that make these controls enforceable live in `brolga-security`; where a control belongs to a
subsystem that does not exist yet, the boundary is listed with the issue that will implement it, so
that issue inherits a reviewed design rather than inventing one under deadline.

## What Brolga is, in security terms

Brolga reads intelligence published by other people — often *about* the people publishing similar
intelligence, and sometimes written by the adversary being described — and compiles it into context
that an analyst or an AI agent acts on.

Two consequences follow, and they shape everything below.

**Brolga's input is adversarial by default.** Not "possibly malformed": adversarial. A threat actor
who knows their infrastructure is being tracked has an incentive to publish content that changes
what a tracker concludes. Malformed input is the easy half of the problem.

**Brolga's output is acted on.** A context pack is read by an agent that may then block an address,
close an alert, or escalate an incident. Content that influences that decision without being
evidence is the highest-value attack against Brolga, and it does not require a memory-safety bug or
a parser flaw — only text.

## The properties Brolga defends

| # | Property | What breaking it looks like |
| --- | --- | --- |
| P1 | Imported content is data, never instructions | A feed's report text changes an agent's conclusion |
| P2 | Every canonical record traces to original evidence | A finding that cannot be justified or refuted |
| P3 | Handling restrictions survive every transformation | TLP:RED material in an unrestricted export |
| P4 | Untrusted input cannot exhaust the host | One hostile document ends the ingest |
| P5 | Brolga does not become a proxy into the operator's network | A feed URL reads the cloud metadata endpoint |
| P6 | Secrets do not appear in output, logs, or storage | A subscription token in a pasted issue report |
| P7 | Identical input produces identical output | A finding that cannot be reproduced or audited |

## Attackers

| Attacker | Controls | Wants |
| --- | --- | --- |
| **Hostile publisher** | Content of a feed, file, or upstream record Brolga imports | To change what Brolga concludes; to reach inside the network Brolga runs in; to exhaust it |
| **Compromised upstream** | Responses from a MISP, TAXII, or OpenCTI instance the operator trusts | Everything above, plus redirects to somewhere else |
| **Malicious plugin author** | A WebAssembly module an operator installs | Filesystem, network, other tenants' data, policy bypass |
| **Local unprivileged user** | Ability to run commands on the host | Secrets, restricted intelligence, the database |
| **Curious agent** | Requests to the MCP or HTTP interface | More than policy permits it to see |

## Out of scope, stated plainly

- **An operator who is malicious or fully compromised.** Brolga runs with their privileges; nothing
  here defends against the person configuring it.
- **Host and kernel compromise**, side channels, and physical access.
- **The correctness of intelligence Brolga imports.** Brolga preserves and attributes claims; it
  does not adjudicate them. A source that lies produces a faithfully recorded lie, and the
  provenance chain is what lets a human notice.
- **Availability of upstream systems.**
- **Cryptographic authenticity of imported content.** Content hashes give integrity and addressing,
  not authenticity. Signature verification would need key distribution that does not exist in this
  ecosystem; if that changes, it is a new control, not a reinterpretation of the hashes.

## Boundaries

Every boundary named in `docs/ARCHITECTURE.md`, with its controls and where they live.

### B1 — Imported content

**Crosses:** files, feed bodies, upstream records. Fully attacker-controlled.
**Threatens:** P1, P2, P4, P7.

| Control | Status |
| --- | --- |
| Narrative is typed `UntrustedText`, tagged `x-brolga-trust: untrusted` in the schema | **Implemented** — `brolga-model` |
| `TrustLevel::Untrusted` cannot be exposed for `Use::Instruction`; no laundering path exists | **Implemented** — `brolga-security::trust` |
| Untrusted text is delimited in model context, never concatenated into a prompt | Contract defined; enforcement with the interfaces ([#33](https://github.com/jusso-dev/Brolga/issues/33)) |
| Size, depth, record-count, and field-length bounds | **Implemented** — `brolga-security::limits` |
| Control characters rejected, including ESC — a stored ANSI sequence rewrites an operator's terminal when printed | **Implemented** — `brolga-model::text` |
| Observables validated with no arbitrary-string fallback | **Implemented** — `brolga-model::observable` |
| Malformed records quarantined, never silently dropped | [#10](https://github.com/jusso-dev/Brolga/issues/10) onward |

**Residual risk.** Delimiting is a mitigation, not a guarantee: no known technique makes a language
model perfectly ignore instructions embedded in quoted material. Brolga's real defence for P1 is
that deterministic logic makes the decisions and model providers are optional and disabled by
default. An operator who enables one accepts a risk this model cannot remove.

### B2 — Archives

**Crosses:** compressed containers. **Threatens:** P4.

| Control | Status |
| --- | --- |
| Output size, entry count, per-entry size, and nesting depth bounds | **Implemented** — `ArchiveLimits` |
| Expansion **ratio** checked *during* decompression | **Implemented** — `ArchiveLimits::ratio_permits` |
| Entry paths rejected for traversal and absolute paths | [#10](https://github.com/jusso-dev/Brolga/issues/10) |

**Why the ratio.** A 42 KiB zip file can expand to petabytes. Every absolute size involved is
unremarkable, so a size limit on the archive is not a control. The limit has to be on the output
relative to the input, and it has to be enforced while decompressing — checking afterwards means the
damage already happened.

### B3 — XML

**Crosses:** STIX 1.x, TAXII 1.x, and several detection formats. **Threatens:** P4, P5, P6.

| Control | Status |
| --- | --- |
| External entity resolution off | **Implemented** — `XmlLimits::allow_external_entities = false` |
| Entity expansion off | **Implemented** — `XmlLimits::allow_entity_expansion = false` |
| Depth, element-count, attribute-length bounds | **Implemented** — `XmlLimits` |
| DTD processing refused | [#52](https://github.com/jusso-dev/Brolga/issues/52) |

**Why switches rather than hard-coded `false`.** They are fields so that a future parser wanting to
change one must do it visibly, in a diff someone reviews, rather than by quietly passing a different
reader configuration. XXE turns a document into a file-read and a network request *as Brolga*;
entity expansion is billion-laughs. Neither has an in-band mitigation, which is why both default off
and no threat-intelligence format requires them.

### B4 — Declarative mappings

**Crosses:** operator-authored mapping documents. **Threatens:** P1, P4.

| Control | Status |
| --- | --- |
| Configuration is data only — no expression, template, include, or command | **Implemented** — `brolga-config` |
| Unknown fields rejected rather than ignored | **Implemented** — `deny_unknown_fields` everywhere |
| YAML anchors and aliases rejected before parsing | **Implemented** — `brolga-config::load` |
| Document size and depth bounds | **Implemented** — 256 KiB, depth 32 |
| Mapping language remains non-Turing-complete | [#47](https://github.com/jusso-dev/Brolga/issues/47) |

**Why anchors are rejected.** Alias expansion is unbounded: billion-laughs in YAML is about a
kilobyte of text expanding to gigabytes, so a size limit does not catch it, and the parser exposes no
expansion cap. Brolga's configuration has no use for anchors, so they are refused outright.

**Recorded exposure.** `serde_yaml_ng` pulls in `unsafe-libyaml`, a transliteration of the C library
containing substantial `unsafe`. Brolga's own crates forbid `unsafe`; a dependency is a different
question, and this is the maintained option with an acceptable licence. The mitigation is ordering —
bounded size and no alias expansion mean the parser sees a small, flat-ish document. Revisit if a
pure-Rust YAML parser with serde integration becomes viable.

### B5 — Connector URLs and responses

**Crosses:** URLs from configuration and, later, from intelligence data. **Threatens:** P5, P6, P4.

| Control | Status |
| --- | --- |
| Scheme allow-list — `http`, `https` only | **Implemented** — `NetworkPolicy::permits_scheme` |
| Plaintext HTTP refused by default | **Implemented** |
| **Resolved address** checked immediately before connecting, every request and every redirect | Design **implemented**; enforcement in [#44](https://github.com/jusso-dev/Brolga/issues/44) |
| Loopback, private, link-local, multicast, unspecified, reserved refused by default | **Implemented** — `AddressCategory` |
| Cloud metadata refused **even when private addresses are allowed** | **Implemented** |
| Redirects bounded; HTTPS→HTTP downgrade refused | **Implemented** |
| Response body size and request timeout bounds | **Implemented** — `ResponseLimits` |
| Upstream connectors read-only | [#40](https://github.com/jusso-dev/Brolga/issues/40) onward |

**Why the address, not the host name.** Checking a URL fails three ways, all routinely exploited:
DNS (`evil.example` resolves to `169.254.169.254`), redirects (the URL checked is not the URL
fetched), and rebinding (public when checked, private when connected). The only reliable boundary is
the resolved address at connect time, on every request including each redirect.

**Why cloud metadata is a separate switch.** An operator enabling internal fetches for an on-premises
MISP almost never means "and also let a feed read my instance credentials". Collapsing the two would
make that the default consequence of a reasonable configuration change.

### B6 — Local CLI and API callers

**Crosses:** command lines, requests. **Threatens:** P3, P6.

| Control | Status |
| --- | --- |
| No secret value in configuration — references only | **Implemented** — `brolga-config::secret` |
| Secrets and source bodies never logged, at any level | **Implemented** — verified end to end against the binary |
| stdout carries results; diagnostics go to stderr | **Implemented** — `brolga-cli` |
| Database paths reject `..` and NUL | **Implemented** — `brolga-config`, `brolga-storage` |
| Authentication and authorisation for network access | [#33](https://github.com/jusso-dev/Brolga/issues/33) onward |
| Policy evaluated before selection and before export | [#33](https://github.com/jusso-dev/Brolga/issues/33) |

**Assumption.** A local caller already has the operator's privileges. Brolga does not defend the
database against a user who can read the file; the controls here are against *accidental* exposure —
a secret in a log, a restricted record in an export — not against a local adversary.

### B7 — Network MCP and HTTP callers

**Crosses:** intent-level tool calls and API requests. **Threatens:** P3, P6.
**Status:** entirely [#33](https://github.com/jusso-dev/Brolga/issues/33) onward. The baseline it
inherits: bind locally by default, no network listener without explicit configuration, policy
evaluated before selection, markings enforced on every response, and no raw source object returned
by default.

### B8 — Plugins

**Crosses:** third-party WebAssembly. **Threatens:** every property.
**Status:** [#45](https://github.com/jusso-dev/Brolga/issues/45) onward. The baseline it inherits:
no filesystem, no network, no ambient capability by default; bounded memory, fuel, and wall-clock
time using `ResourceLimits` and `CancellationToken`; no policy decisions delegated to a plugin; and
a plugin's output classified `TrustLevel::Untrusted`, because a plugin processes untrusted input and
its output is derived from it.

### B9 — Exporters

**Crosses:** canonical records leaving Brolga. **Threatens:** P3, P2, P6.
**Status:** [#54](https://github.com/jusso-dev/Brolga/issues/54). The baseline it inherits: policy
evaluated before export, not after; markings carried into the exported representation or the export
refused; lossiness declared rather than silent; and `SensitiveText` never emitted unless policy
explicitly permits it.

### B10 — Optional model providers

**Crosses:** intelligence content leaving the operator's control. **Threatens:** P1, P3, P6, P7.
**Status:** [#49](https://github.com/jusso-dev/Brolga/issues/49). The baseline it inherits: disabled
by default and outside deterministic behaviour; no data sent without explicit configuration *and*
policy approval; generated content always labelled and always citing evidence — `GeneratedContent`
already cannot be constructed without it; and model output classified `TrustLevel::Untrusted`,
because a model that read untrusted input may repeat it.

## Cross-cutting controls

**Memory safety.** `#![forbid(unsafe_code)]` in every first-party crate, enforced by the workspace
lint table. An exception requires its own ADR. Two dependencies contain substantial `unsafe` —
`unsafe-libyaml` (B4) and bundled SQLite — and both are recorded rather than assumed away.

**Panics.** A panic on hostile input is a denial of service. The workspace denies `unwrap_used`,
`expect_used`, `panic`, `indexing_slicing`, `as_conversions`, and the lossy-cast family in
production code, so reaching for one is a build failure rather than a review finding. Property tests
feed arbitrary bytes to every deserialiser and assert no panic.

**Cancellation.** One token per request, passed down, inherited by children. A per-call timeout
cannot bound a request: each call restarts its own clock, so a sixty-second budget becomes sixty
seconds *per step*. Deadlines are absolute instants for the same reason, and a child cannot extend
its parent's.

**Determinism (P7).** Identifiers are derived, never random or clock-based. Fingerprints exclude
timestamps. Canonicalisation is idempotent under property test. A finding that cannot be reproduced
cannot be audited.

**Supply chain.** Licence, advisory, ban, and source checks across five target triples on every
build; crates.io only; committed lockfile; `--locked` builds; dated expiring exceptions in
`deny.toml` rather than ad-hoc suppression. This is not decoration: the gate found RUSTSEC-2026-0009
on its first run and an MSRV-incompatible build script shortly after.

## Security regression test plan

Every control above is a test, and a control without one is an intention.

| Layer | What it covers | Where |
| --- | --- | --- |
| Unit | Each limit's boundaries, both sides; each classification rule; each address category | `brolga-security` |
| Property | Arbitrary bytes into every deserialiser: reject or accept, never panic, never mangle | `brolga-model/tests/property.rs` |
| Hostile-input | Named attacks with their real payloads — billion laughs, zip-bomb ratios, XXE switches, `'; DROP TABLE`, `../` traversal, `::ffff:127.0.0.1`, `169.254.169.254`, prompt injection | Per crate |
| Integration | Injection and traversal end to end against a real database | `brolga-storage/tests/integration.rs` |
| End-to-end | A secret canary in the process environment, absent from both streams at trace level | `brolga-cli/tests/binary.rs` |
| Supply chain | Licences, advisories, bans, sources, on every build | CI |

**Rules for this suite.** A test names the attack it prevents, not the function it calls, so its
purpose survives a refactor. A fix for a security defect lands with a test that fails without it.
Tests are never weakened to make a build pass — [#61](https://github.com/jusso-dev/Brolga/issues/61)
forbids it explicitly, and a weakened security test is worse than a deleted one because it still
reports success.

**Planned additions:** fuzzing for every parser ([#56](https://github.com/jusso-dev/Brolga/issues/56)),
mock-server connector tests including redirect-to-internal and rebinding
([#44](https://github.com/jusso-dev/Brolga/issues/44)), plugin sandbox escape attempts
([#48](https://github.com/jusso-dev/Brolga/issues/48)), and policy-bypass tests for every interface
([#33](https://github.com/jusso-dev/Brolga/issues/33)).

## Maintaining this document

Amend it in the same pull request as the change, not afterwards. A boundary added without an entry
here is a boundary nobody reviewed.

A feature that needs to weaken a control in this model needs an ADR: what is being relaxed, why no
alternative works, what compensates, and who reviewed it. "The default was inconvenient" is not a
justification, and the fact that a control is a *field* rather than a constant is what forces that
conversation to happen in a diff.
