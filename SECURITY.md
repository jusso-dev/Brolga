# Security Policy

## Reporting

Do not disclose suspected vulnerabilities in public issues.

Use [GitHub private vulnerability reporting](https://github.com/jusso-dev/Brolga/security/advisories/new). Include affected revision, impact, reproduction steps, and any suggested mitigation. Do not include live credentials, restricted intelligence, or third-party personal data.

No stable release exists yet. Security fixes will target the default branch until supported release lines are published.

## Security posture

Brolga's planned security baseline includes:

- `#![forbid(unsafe_code)]` in every Rust crate
- bounded parsing, decompression, traversal, recursion, storage, connector, plugin, and context-generation operations
- no filesystem or network access for WebAssembly plugins by default
- no external data transfer without explicit connector or model-provider configuration and policy approval
- policy enforcement before output generation
- separate retention of untrusted originals and canonical records
- append-only structured audit events for security-relevant changes
- read-only upstream integrations by default

Planning issues track implementation and verification of these controls. This document does not claim controls exist before their linked issues close.

## Threat model

[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) records what Brolga assumes, which boundaries it
defends, what it deliberately does not defend, and the residual risks. Read it before proposing a
change that relaxes a limit or a default — the security-relevant defaults are fields rather than
constants precisely so that relaxing one happens in a diff somebody reviews.
