# Governance

## Current Stage

This project is in single-maintainer, pre-community stage. There is one
maintainer ([@IceMasterT](https://github.com/IceMasterT)), no formal governance
board, and no steering committee. That is appropriate for the project's current
size and maturity, and it is stated clearly here so contributors know what to
expect.

## Decision Making

The maintainer makes all final decisions about direction, API shape, release
timing, and whether to accept a contribution.

For significant changes -- anything that touches the wire format, the
conformance fixture set, or the project's positioning relative to MCP/A2A --
the maintainer will open a GitHub Issue before deciding, to give the community
a window to raise concerns or provide context. That window will be at least
seven days for non-urgent changes.

Day-to-day decisions (bug fixes, documentation, minor SDK improvements) do not
require community input first.

## Versioning Policy

The wire version `7h3/0.1` is frozen. Interoperating implementations can rely
on it not changing. A new wire version designation (e.g. `7h3/0.2`) would be
introduced in a new package major version and coexist with `7h3/0.1` for a
migration period.

The TypeScript API is pre-1.0. Minor version bumps may include breaking API
changes. Breaking changes will be documented in the changelog with migration
notes. The `1.0.0` release will signal API stability.

The Python and Rust SDKs track the TypeScript wire behavior. Their own version
numbers are independent of the npm package version.

## Path to Co-Maintainership

There is no automatic path to co-maintainership based on contribution count.
The relevant factors are:

- Sustained engagement over multiple months
- Demonstrated familiarity with the threat model (replay attacks, malleability,
  cross-runtime canonicalization edge cases)
- Good judgment in the review of other contributors' PRs
- Willingness to own the security disclosure process

If you are interested, open a conversation in Discussions rather than raising
it in a PR.

## Standards Body Adoption

If this project is accepted into a standards body or foundation, this governance
document will be replaced by whatever governance model that body requires.
Community input will be sought before any such transition.

---

Last reviewed: 2026-06-05  
Maintainer: [@IceMasterT](https://github.com/IceMasterT) / tech@mysms.promo
