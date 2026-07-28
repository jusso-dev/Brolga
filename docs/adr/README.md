# Architecture decision records

An ADR records a decision that constrains later work: crate boundaries, dependency direction,
public interface versioning, security contracts, storage layout, algorithm identity, and any
exception to a project-wide prohibition.

## Index

| ADR | Title | Status | Issue |
| --- | --- | --- | --- |
| [0001](0001-workspace-boundaries-and-public-interface-versioning.md) | Cargo workspace boundaries and public interface versioning | accepted (§4 amended by 0002) | [#2](https://github.com/jusso-dev/Brolga/issues/2) |
| [0002](0002-raise-msrv-to-1-88-for-a-security-advisory.md) | Raise the MSRV to 1.88.0 to take a security fix | accepted | [#9](https://github.com/jusso-dev/Brolga/issues/9) |

## Rules

- One decision per record. Number sequentially; never renumber.
- Status is `proposed`, `accepted`, `superseded by NNNN`, or `rejected`.
- An accepted ADR is not edited to change its decision. Write a new ADR that supersedes it, and
  update the old record's status line and this index.
- Record rejected alternatives and the consequences accepted, not only the choice made.
- Any exception to a project-wide prohibition — unsafe code, a denied licence, a network call in a
  default build — requires its own ADR. A code comment is not sufficient.
