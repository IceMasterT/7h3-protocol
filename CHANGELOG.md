# Changelog

All notable changes to `@7h3/protocol` are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed
- **License changed from MIT to Apache-2.0.** AIP is a wire protocol meant for independent implementation; Apache-2.0 §3 supplies the express patent grant and patent-retaliation clause that MIT lacks, and it is the license foundations hosting protocol work expect. Releases up to and including `0.1.2` remain available under MIT — that grant is irrevocable and is not being withdrawn. Apache-2.0 applies from `0.1.3` onward.
- `scripts/prepare-aip-package.ts` — publishable manifest now declares `Apache-2.0`, and copies `LICENSE` and `NOTICE` into the tarball
- `sdk/rust/Cargo.toml` — `license` now `Apache-2.0`; `include` extended with `LICENSE` and `NOTICE` so they reach crates.io
- `mcp-server/package.json` — `license` now `Apache-2.0`; `NOTICE` added to `files`

### Added
- `LICENSE` — full Apache-2.0 text, verbatim. The repository previously declared MIT in package metadata and prose but shipped no license text at all, in any package.
- `NOTICE` — attribution notice required to propagate under Apache-2.0 §4(d)
- Per-package `LICENSE` and `NOTICE` copies in `sdk/rust/`, `sdk/python/`, and `mcp-server/`, each of which publishes as an independent artifact

### Downstream note
Apache-2.0 is incompatible with GPLv2-only code (GPLv3 is unaffected). Projects vendoring an AIP SDK into a GPLv2-only codebase should pin `0.1.2`.

---

## [0.1.2] — 2026-06-05

### Added
- `SECURITY.md` — coordinated vulnerability disclosure process, 48h acknowledgement / 14-day critical patch SLA, Hall of Thanks
- `CONTRIBUTING.md` — test commands, wire-freeze policy, conformance fixture update requirement, PR workflow
- `GOVERNANCE.md` — LF Minimum Viable Governance style: single-maintainer stage, decision process, co-maintainership path
- `.github/dependabot.yml` — weekly npm and GitHub Actions dependency updates; non-security updates grouped to reduce noise
- `.github/workflows/scorecard.yml` — OpenSSF Scorecard workflow (activates when Actions billing is restored)
- `.github/workflows/publish.yml` — provenance-enabled npm publish workflow for both `@7h3/protocol` and `@7h3/protocol-mcp` (activates when Actions billing is restored)
- `src/protocolFuzz.advanced.test.ts` — 8 property-based fuzz tests via fast-check: wire decoder resilience (never throws on arbitrary input), canonicalization determinism (field-order invariant), replay cache uniqueness properties

### Changed
- README: added Ed25519 production recommendation with code snippet; added Security section linking to SECURITY.md
- `docs/MCP_WRAPPER.md`: added HMAC vs Ed25519 comparison table and Ed25519 `wrapMcpServer` example
- `mcp-server`: updated `aip_wrap_mcp_server` tool description to guide toward Ed25519 for production; HMAC boilerplate now includes a production upgrade comment

### Fixed
- README: corrected overstated fuzz status (now accurately notes property-based tests exist; formal fuzzing campaign still not done)

---

## [0.1.1] — 2026-06-05

### Fixed
- Published package was missing 21 individual `.d.ts` module files — only `index.d.ts` was included, causing TS2305 errors in any consumer using NodeNext or bundler moduleResolution. All 22 declaration files now ship with the package.
- `scripts/prepare-aip-package.ts`: copy all `.d.ts` files from `dist/aip/` instead of only `index.d.ts`

### Added
- `@7h3/protocol-mcp@0.1.0` — MCP server installable into Claude Code (`claude mcp add aip -- npx @7h3/protocol-mcp`). Five tools: `aip_generate_secret`, `aip_generate_keypair`, `aip_wrap_mcp_server`, `aip_sign`, `aip_verify`

---

## [0.1.0] — 2026-06-01

### Added

**Core protocol (`aip/0.1`)**
- `createEnvelope` / `signEnvelopeHmac` / `signEnvelopeEd25519` — envelope construction and signing over a deterministic canonical form (fixed key order).
- `verifyEnvelopeHmac` / `verifyEnvelopeEd25519` — tamper-evident verification via real WebCrypto (no hand-rolled crypto).
- `validateEnvelope` — structural + TTL + clock-skew validation with typed diagnostics.
- `receiveEnvelope` — full receive pipeline: validate → verify → replay-check, composable via `ReceiveEnvelopeOptions`.
- Wire formats: `json`, `compact` (minified), `binary` (MessagePack); encode/decode via `encodeEnvelope` / `decodeEnvelope`.
- Polyglot parity: shared conformance fixture set (`conformance/aip_v0_1.json`) proves byte-identical signatures across TypeScript, Python (`aip7h3`), and Rust (`aip7h3`).

**Replay protection**
- `InMemoryReplayCache` — single-process `(sender, messageId, nonce)` uniqueness window with TTL.
- `DistributedReplayCache` — wraps any `DistributedReplayStore`; routes batch ops through `reserveMany` when available.
- `createRedisReplayStore` — atomic `SET NX PX` reserve over a client-agnostic `RedisLikeClient` interface; batch pipeline via `reserveMany`; `errorBehavior: 'fallback' | 'reject' | 'allow'` with graceful degradation to local store and `onDegraded` hook.
- `InMemoryRedisLikeClient` — reference implementation for tests (no Redis dep required).

**Fleet-wide key revocation**
- `InMemoryRevocationStore` — single-process; supports time-bounded `untilMs`.
- `createRedisRevocationStore` — cached reads (`cacheTtlMs` default 5 s), **fail-closed default** (`errorBehavior: 'reject'`), serves stale cache during Redis outage.
- `withRevocationCheck` — wraps any `SignatureResolver`; revoked key returns `undefined` → verification fails.

**MCP hardening wrapper**
- `wrapMcpServer` — sign + replay-protect an existing MCP handler with zero handler changes; enforces recipient binding (cross-server relay defense).
- `wrapMcpClient` / `createMcpClientCodec` — sign outbound requests; enforce sender binding (response-spoof defense) and correlation binding (response-substitution defense); replay protection on by default.
- Demo: `npm run aip:mcp:wrap` — proves tampered and replayed requests rejected.

**Transport adapters**
- `serveMcpOverStdio` / `createStdioMcpClient` — newline-delimited; in-order sequential chain prevents response interleaving.
- `createHttpMcpHandler` / `createHttpMcpClient` — `node:http` handler + `fetch` client; supports `binary` wire format.
- No new runtime dependencies (uses `node:readline`, `node:http`, `node:stream`, global `fetch`).

**Key management & policy**
- Key rotation support (`keyRotation`), runtime policy (`runtimePolicy`, `policyEnforcer`), telemetry feedback hooks.
- Framework adapters (`frameworkAdapters`), agent adapter (`agentAdapter`), MCP gateway (`mcpGateway`).

### Documentation
- `docs/THREAT_MODEL.md` — full threat coverage matrix.
- `docs/DISTRIBUTED_REPLAY.md` — Redis store setup, `errorBehavior` table, operational guidance.
- `docs/KEY_REVOCATION.md` — revocation store setup, cache TTL tuning.
- `docs/MCP_WRAPPER.md` — threat coverage table, server + client usage, transport examples.

### Test coverage
- 123 tests / 22 test files — all green.
- Live-Redis integration test (`redisIntegration.test.ts`) — auto-skips if no server present.
- Python conformance: `conformance:python`.
- Rust: `conformance:rust` (7 tests).

---

[0.1.0]: https://github.com/IceMasterT/7h3-protocol-aip/releases/tag/v0.1.0
