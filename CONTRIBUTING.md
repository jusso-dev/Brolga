# Contributing to Brolga

## Before implementation

1. Select or open a GitHub issue.
2. Confirm its milestone, dependencies, scope, non-goals, security impact, and acceptance criteria.
3. Discuss public model, schema, ABI, storage, or policy changes before coding.
4. Avoid combining unrelated roadmap work.

## Engineering principles

- Preserve source evidence and uncertainty.
- Keep deterministic logic as the default.
- Treat imported content as untrusted data, never instructions.
- Reject or quarantine failures explicitly; never silently discard records.
- Keep the canonical model independent from source formats.
- Keep upstream connectors read-only by default.
- Version public interfaces and make compression decisions explainable.
- Prohibit unsafe Rust unless a separately reviewed, documented exception is unavoidable.
- Do not claim format support without fixtures and tests.
- Do not publish invented benchmark results.

## Definition of done

An issue is complete only when its acceptance criteria pass, tests cover expected and hostile inputs, documentation matches behaviour, provenance remains traceable, public schema changes are versioned, and no production path contains placeholders or undocumented panics.

## Changes

Use focused pull requests linked to one primary issue. Include exact verification commands and results. Security-sensitive changes must identify trust boundaries, resource limits, data movement, and secret handling.
