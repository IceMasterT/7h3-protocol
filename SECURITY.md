# Security Policy

## Reporting a Vulnerability

Please do not open a GitHub Issue for security findings. Use coordinated disclosure instead.

**Send private reports to:** tech@mysms.promo  
**Subject line:** `[7h3 Security] <brief description>`

### What to include

A useful report contains:

- A clear description of the vulnerability and which component it affects
- Steps to reproduce, ideally as a minimal test case or fixture
- Your assessment of the impact (confidentiality, integrity, availability, scope)
- The affected versions (check `package.json` version and the wire version `7h3/0.1`)
- Any suggested fix or mitigation you have in mind (optional but appreciated)

Reports that include a conformance vector demonstrating the issue are especially
helpful and make the triage process faster.

## Response Timeline

| Event | Target |
|---|---|
| Acknowledgement | 48 hours |
| Triage and severity assignment | 5 business days |
| Patch for critical/high severity | 14 days from confirmation |
| Patch for medium/low severity | 60 days from confirmation |
| Public disclosure | After patch is released and verified |

We ask that reporters hold off on public disclosure until a patch is available.
If the 14-day critical window is going to slip, we will contact you to agree on
an extended timeline or coordinated partial disclosure.

## Scope

The following are in scope:

- Envelope signing and verification (`src/`, `sdk/python/`, `sdk/rust/`)
- Canonicalization logic and determinism guarantees
- Replay-safety (nonce and timestamp validation)
- Wire format parsing in all runtimes (TypeScript, Python, Rust, Go)
- Intent vocabulary validation
- The gateway and its policy enforcement (`src/gateway.ts`)
- Step-up approval, provenance claims and payment mandates
  (`src/approval.ts`, `src/provenance.ts`, `src/mandate.ts`)
- HTTP Message Signatures, Web Bot Auth and DPoP
  (`src/httpMessageSignatures.ts`, `src/webBotAuth.ts`, `src/dpop.ts`)
- MCP hardening: tool pinning and signed SSE (`src/mcpToolPinning.ts`, `src/mcpSse.ts`)
- Agent identity, attestation and the key log
  (`src/agentIdentity.ts`, `src/attestation.ts`, `src/keyLog.ts`, `src/keyInfra.ts`)

The threat model, with the controls for each threat and what is not covered, is in
[`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md). Approval, provenance, mandates, RFC 9421,
DPoP, MCP hardening and the identity modules are TypeScript only.

Out of scope: third-party dependencies (report those upstream), benchmark
scripts, and documentation typos.

## Audit Status

No independent third-party security audit has been performed on this codebase,
and none is planned — this is an unfunded open-source project. Verification instead
relies on what an open codebase can offer:

- Cross-runtime conformance vectors (TypeScript / Python / Rust / Go must agree
  byte-for-byte on canonicalization and signatures)
- Published standards vectors: the RFC 9421 Ed25519 and HMAC signatures are reproduced
  byte for byte, the RFC 9449 example proof verifies as received, and RFC 8785 and
  did:key examples are reproduced
- Fuzz harnesses run in CI on every push (decode + tamper-detection); the modules added
  since have hostile-input unit tests rather than fuzz harnesses
- Mutation testing of security controls: each check is removed and the suite must fail
- The signing core is a single file per runtime with zero runtime dependencies. The
  modules built on top of it are larger and TypeScript only, so "small enough to read in an
  afternoon" no longer describes the whole package, only that core
- A CycloneDX SBOM per npm package, generated in CI (`npm run sbom`), which also checks the
  zero-runtime-dependency claim

The protocol design has been reviewed by the maintainer against known attack
classes for signed messaging systems (replay, malleability, timing oracles,
cross-runtime canonicalization divergence). Independent review is welcome and
will be credited below; reproductions of conformance vectors that reveal
edge-case signing or deserialization behavior are treated as high-value
contributions. If a security firm ever wants to audit an open protocol pro
bono, the door is open: tech@mysms.promo.

## Checklist for Security-Sensitive Changes

Before merging any change to signing, canonicalization, replay handling, or
wire parsing, confirm:

- [ ] Conformance vectors updated (`conformance/7h3_v0_1.json` and, if the
      binary codec is affected, `conformance/7h3_v0_1_binary.json`)
- [ ] Fuzz harnesses run (`npm run fuzz:ts`, `npm run fuzz:ts:decode`,
      `npm run fuzz:ts:verify`; `npm run fuzz:rust:decode` and
      `npm run fuzz:rust:canonicalize` for wire-format or canonicalization changes)
- [ ] Cross-SDK tests pass (`npm run conformance:python`, `npm run conformance:rust`,
      plus the root `npm test`)
- [ ] Dependency audit reviewed (`npm audit` in the root, `cloudflare/`,
      `mcp-server/`, `sdk/pq/`, and `sdk/threshold/`)

## Hall of Thanks

Researchers who report valid, confirmed vulnerabilities will be acknowledged
here (with their permission).

_No entries yet._

---

Maintainer: [@IceMasterT](https://github.com/IceMasterT)  
Package: `@7h3/protocol`  
License: Apache-2.0
