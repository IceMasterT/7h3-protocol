# AIP Versioning Policy

## Protocol versions

- Protocol version is declared in `header.version` (for example `aip/0.1`).
- New major protocol versions must not silently alter canonicalization or signature semantics.
- Backward-incompatible wire or verification changes require a new minor/major protocol tag.

## Compatibility rules

- Patch releases: bug fixes only, no wire-format or canonicalization changes.
- Minor releases: additive changes only (new optional fields/capabilities, no required-field breakage).
- Major releases: allowed to remove or alter semantics with explicit migration documentation.

## Signature profile policy

- Supported profiles are explicitly declared by `signature.alg`.
- Adding a new signature profile is a minor release only if existing profiles continue to verify unchanged.
- Removing a profile requires a major release.

## SDK versioning

- TypeScript, Python, and Rust SDKs follow semver independently.
- Conformance fixture changes require SDK conformance updates in the same release train.

## Release evidence requirements

- Conformance suites (TS/Python/Rust) pass.
- Bench regression checks attached for performance-sensitive changes.
- Migration guide updated for any behavior change that impacts consumers.
