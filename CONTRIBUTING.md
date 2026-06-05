# Contributing to @7h3/protocol

Thanks for your interest. This document covers how to run tests, submit changes,
and understand what is and is not open for modification.

## Prerequisites

- Node.js 20+
- Python 3.10+ (for Python conformance tests)
- Rust stable toolchain (for Rust conformance tests)

Install Node dependencies:

```bash
npm install
```

## Running Tests

**TypeScript unit and integration tests:**

```bash
npm test
```

**Cross-runtime conformance tests:**

```bash
npm run conformance:python   # runs sdk/python/tests via unittest
npm run conformance:rust     # runs cargo test in sdk/rust/
```

All three test suites must pass before a PR is mergeable.

## The Wire Version is Frozen

`aip/0.1` is the current wire version, and **it is frozen**. This means:

- The envelope schema (field names, types, required fields) cannot change
- The canonicalization algorithm cannot change
- The intent vocabulary (`tool_call`, `tool_result`, `message`, `error`) cannot change

Any change to these would silently break cross-runtime interoperability and
require a new wire version designation. If you believe a wire-level change is
necessary, open an issue first to discuss versioning strategy before writing code.

The TypeScript API (types, builder functions, SDK surface) is pre-1.0 and may
evolve on minor version bumps. Deprecation notices will be included in the
changelog when possible.

## Conformance Fixtures

The canonical fixture set lives at `conformance/aip_v0_1.json`. If your PR adds
or changes any signing behavior, canonicalization detail, or replay-safety logic,
you must update this fixture file with vectors that cover the new behavior.

Fixtures are the source of truth for cross-runtime verification. A PR that
changes signing logic without updating fixtures will be rejected.

## Submitting a Pull Request

1. Fork the repo and create a branch with a descriptive name
   (`fix/nonce-validation`, `feat/ed448-profile`, etc.)
2. Make your changes and ensure all three test suites pass
3. Update `conformance/aip_v0_1.json` if signing behavior changed
4. Open a PR against `main` with a clear description of:
   - What the change does
   - Why it is needed
   - Any trade-offs or alternatives you considered
5. Reference any related issues in the PR description

Keep PRs focused. A single PR that mixes unrelated changes is harder to review
and slower to land.

## Security Findings

Do not open GitHub Issues for security vulnerabilities. Follow the process in
[SECURITY.md](SECURITY.md) instead.

---

Maintainer: [@IceMasterT](https://github.com/IceMasterT)
