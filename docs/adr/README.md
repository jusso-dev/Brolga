# Architecture decision records

An ADR records a decision that constrains later work: crate boundaries, dependency direction,
public interface versioning, security contracts, storage layout, algorithm identity, and any
exception to a project-wide prohibition.

## Index

| ADR | Title | Status | Issue |
| --- | --- | --- | --- |
| [0001](0001-workspace-boundaries-and-public-interface-versioning.md) | Cargo workspace boundaries and public interface versioning | accepted (§4 amended by 0002; §1 amended by 0003–0005 and 0007–0010) | [#2](https://github.com/jusso-dev/Brolga/issues/2) |
| [0002](0002-raise-msrv-to-1-88-for-a-security-advisory.md) | Raise the MSRV to 1.88.0 to take a security fix | accepted | [#9](https://github.com/jusso-dev/Brolga/issues/9) |
| [0003](0003-ingestion-crate-boundary-and-parser-panic-policy.md) | The ingestion crate boundary, and how a parser is stopped from panicking | accepted | [#11](https://github.com/jusso-dev/Brolga/issues/11) |
| [0004](0004-graph-crate-boundary.md) | The graph crate boundary | accepted | [#20](https://github.com/jusso-dev/Brolga/issues/20) |
| [0005](0005-connector-crate-boundary-and-outbound-network-policy.md) | The connector crate boundary, and how an outbound fetch is constrained | accepted (§5 amended by 0006) | [#44](https://github.com/jusso-dev/Brolga/issues/44) |
| [0006](0006-a-closed-set-of-query-bodies.md) | A closed set of query bodies, for GraphQL sources | accepted | [#43](https://github.com/jusso-dev/Brolga/issues/43) |
| [0007](0007-export-crate-boundary-and-the-policy-gate.md) | The export crate boundary, and a policy gate that cannot be bypassed | accepted | [#54](https://github.com/jusso-dev/Brolga/issues/54) |
| [0008](0008-plugin-sdk-and-wit-abi.md) | The plugin SDK crate boundary, and a WIT ABI that cannot smuggle host access | accepted | [#46](https://github.com/jusso-dev/Brolga/issues/46) |
| [0009](0009-capability-limited-wasm-plugin-host.md) | A capability-limited WebAssembly plugin host | accepted | [#48](https://github.com/jusso-dev/Brolga/issues/48) |
| [0010](0010-optional-llm-proposal-providers.md) | Optional LLM proposal providers, disabled by default | accepted | [#49](https://github.com/jusso-dev/Brolga/issues/49) |
| [0011](0011-postgresql-backend-and-safe-query-language.md) | PostgreSQL backend and safe query language | accepted | [#55](https://github.com/jusso-dev/Brolga/issues/55) |

## Rules

- One decision per record. Number sequentially; never renumber.
- Status is `proposed`, `accepted`, `superseded by NNNN`, or `rejected`.
- An accepted ADR is not edited to change its decision. Write a new ADR that supersedes it, and
  update the old record's status line and this index.
- Record rejected alternatives and the consequences accepted, not only the choice made.
- Any exception to a project-wide prohibition — unsafe code, a denied licence, a network call in a
  default build — requires its own ADR. A code comment is not sufficient.
