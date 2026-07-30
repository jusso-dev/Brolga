# ADR 0010 — Optional LLM proposal providers, disabled by default

- Status: accepted
- Date: 2026-07-30
- Milestone: `v0.7.0 — Extension system`
- Issue: [#49](https://github.com/jusso-dev/Brolga/issues/49)
- Amends: [ADR 0001](0001-workspace-boundaries-and-public-interface-versioning.md) §1 (new crate)
  and §3 (`llm` feature names a real subsystem).
- Records: **model output is never authoritative**; proposals stay `TrustLevel::Untrusted` until
  deterministic validation or explicit operator approval.

## Context

Threat model B10 and the architecture plan keep language-model providers optional, off by default,
and outside deterministic core behaviour. Generated narrative must cite evidence
([`GeneratedContent`](../../crates/brolga-model/src/provenance/evidence.rs) already refuses empty
citations). What was missing is a crate boundary and a call path that cannot fire by accident.

## Decision

### 1. New crate: `brolga-llm` (layer 2)

| Crate | Responsibility | May depend on (first-party) |
| --- | --- | --- |
| `brolga-llm` | Provider trait, proposal + approval types, prompt templates, transfer policy, optional OpenAI-compatible HTTP adapters | `brolga-model`, `brolga-security`, `brolga-config` |

It does **not** depend on storage, ingest, graph, or connectors. Callers that persist proposals do so
above this crate. HTTP uses `ureq` only behind the `http` feature, which workspace feature `llm`
enables.

### 2. Default path makes no model call

- Default features empty: no HTTP client, no network types required to compile.
- [`DisabledProvider`](../../crates/brolga-llm/src/provider.rs) is the only provider available without
  `http`; every `propose` returns a structured error naming the feature/config required.
- CLI commands that would call a model require `--features llm` and explicit provider configuration.

### 3. Remote transfer needs policy *and* network allowlisting

Before any request leaves the process:

1. Identity must hold `Capability::Redistribute` when the endpoint is not loopback (local Ollama /
   llama.cpp on loopback may use `Read` only — the content still does not leave the machine).
2. Markings on cited evidence must allow the transfer under the same decision function as export
   (ADR 0007's gate pattern: check before bytes leave).
3. [`NetworkPolicy`](../../crates/brolga-security/src/network.rs) must permit the resolved address
   immediately before connect (SSRF baseline from ADR 0005).

A missing step is a hard error, not a log line.

### 4. Proposals are unverified until upgraded

Every successful model call produces a [`Proposal`](../../crates/brolga-llm/src/proposal.rs) whose
`ApprovalState` is `Unverified`. Only deterministic validation or an operator approval moves it
forward. Model text is never used as a `TrustLevel::Internal` instruction.

### 5. Prompt templates are versioned data

Templates carry `id` + `version`. Changing wording without bumping version is a bug: provenance
must say which template produced a proposal. Injection fixtures are tested as data that cannot
change policy or invoke tools — the provider API has no tool channel.

## Consequences

- Deterministic tests never need a model; they use `DisabledProvider` or an in-process mock.
- Enabling `llm` widens the dependency graph with TLS; that is intentional and opt-in.
- Residual risk: a misconfigured allowlist still sends *untrusted proposals* only — never silent
  merges into confidence or attribution.
