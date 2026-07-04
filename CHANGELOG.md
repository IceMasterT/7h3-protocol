# Changelog

All notable changes to `@7h3/protocol` are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## v0.5.3

### Changed

- Internal type-quality sweep: eliminated every `any` from production `src/`
  (typed `WebSocketLike` listeners, structural `BufferCtorLike`, `unknown`
  casts), zeroed out ESLint (62 → 0) and `tsc --noEmit` (40 → 0). No behavior
  change; all 395 tests pass.
- Supply-chain hardening: all GitHub Actions pinned to commit SHAs, gitleaks
  secret-scan workflow, `tsc` + fuzz-smoke CI gates, CODEOWNERS,
  CODE_OF_CONDUCT, branch protection on `main`.
- Spec: RFC §5.1 now makes nonce entropy normative (CSPRNG, ≥96 bits;
  timestamp / `Math.random()` nonces forbidden).

## v0.5.2

### Security

- **Rust: constant-time HMAC verification** — `verify_canonical_payload_hmac` previously
  compared base64 strings with `==`, leaking matching-prefix length as a timing oracle.
  Now decodes the signature and uses `hmac::Mac::verify_slice` (constant-time). Brings
  Rust in line with TypeScript (`subtle.verify`) and Python (`hmac.compare_digest`).
- **Cryptographically secure nonces** — TypeScript `createEnvelope` used `Math.random()`
  for nonce/messageId defaults; the Rust envelope helper used a timestamp-only nonce
  (`n-<ms>`, zero entropy, collides within the same millisecond). Both now use CSPRNG
  output: new exported `randomHex()` (Web Crypto) in TS and `random_nonce()`
  (`getrandom`) in Rust. Capability token, key rotation, and audit log IDs also moved
  off `Math.random()`.

### Fixed

- CI/publish workflows referenced nonexistent scripts (`build:aip`/`package:aip`) and
  the old `dist/npm-aip` output path — corrected to `build:protocol`/`package:protocol`
  and `dist/npm-protocol`.
- `SECURITY.md`/`GOVERNANCE.md` still cited the pre-rebrand wire version `aip/0.1` and
  the removed `src/aip/` path — corrected to `7h3/0.1` and current paths.
- Repository URLs pointed at the old `7h3-protocol-aip` repo name across package
  manifests and docs; Cargo `documentation` link fixed to `docs.rs/protocol-7h3`.

### Added

- `LICENSE` file (MIT) — previously declared in manifests but missing from the repo.

### Removed

- Stale compiled `src/protocol.js` (drift risk next to `protocol.ts`).
- `bench-results/` JSON artifacts untracked and gitignored.

Wire format unchanged: `7h3/0.1` envelopes signed by v0.5.1 verify under v0.5.2 and
vice versa.

## v0.5.0

### New features

**Feature 1 — Distributed Redis replay cache**
- RedisReplayStore: atomic SET NX PX prevents cross-instance replay attacks
- ClusterRedisReplayStore: queries all Redis Cluster nodes
- InMemoryReplayStore improvements
- Go SDK: InMemoryReplayStore + RedisReplayStore (inject-your-client)
- Python SDK: RedisReplayStore using redis-py

**Feature 2 — End-to-end encryption (X25519 + ChaCha20-Poly1305)**
- sealEnvelope / openEnvelope: encrypt body before signing, verify before decrypting
- generateX25519KeyPair: ephemeral key pairs for forward secrecy
- Zero new dependencies: Node.js built-in crypto.ecdh + crypto.createCipheriv('chacha20-poly1305')
- Python SDK: X25519 + ChaCha20-Poly1305 via cryptography package
- Go SDK: crypto/ecdh + golang.org/x/crypto/chacha20poly1305

**Feature 3 — Capability tokens and delegation chains**
- issueCapabilityToken: scoped, time-bounded, cryptographically signed credentials
- delegateCapabilityToken: sub-delegate with equal or narrower scope
- verifyCapabilityChain: verify full A→B→C delegation chain
- Gateway integration: x-7h3-capability header accepted alongside signatures
- tokenMatchesScope: glob path matching

**Feature 4 — Streaming message signing**
- SignedStreamWriter / SignedStreamReader: per-chunk HMAC + final Ed25519
- signStream / verifyStream: convenience wrappers for arrays
- WebSocket integration: createSignedWebSocketStream / receiveSignedWebSocketStream
- Tampering detected mid-stream on the failing chunk

**Feature 5 — Prometheus metrics + OpenTelemetry**
- Protocol7h3Metrics: counters and histograms for all verification events
- renderPrometheusText: zero-dep Prometheus exposition format
- createMetricsMiddleware: serve /metrics endpoint
- CLI: 7h3 gateway --metrics-port N
- setOtelProvider / withVerificationSpan: optional OTel tracing

**Feature 6 — Post-quantum signatures (ML-DSA) — @7h3/protocol-pq**
- generatePqKeyPair: ML-DSA-65 and ML-DSA-87 keypairs
- signEnvelopePq / verifyEnvelopePq: same envelope format, alg: 'ML-DSA-65'
- Python SDK: Dilithium2/3/5 via dilithium-py
- Separate package to keep @7h3/protocol at zero runtime deps

**Feature 7 — CBOR binary wire format**
- encodeCbor / decodeCbor: zero-dep deterministic CBOR (RFC 8949)
- encodeEnvelopeCbor / decodeEnvelopeCbor: compact numeric-key encoding (~40% smaller)
- HTTP binding: Content-Type: application/7h3-cbor support
- Go SDK: EncodeEnvelopeCBOR / DecodeEnvelopeCBOR

**Feature 8 — M-of-N threshold signatures (BLS12-381) — @7h3/protocol-threshold**
- generateBlsKeyPair: BLS12-381 keypairs
- signEnvelopeBls: partial signature from one participant
- aggregateSignatures: combine M-of-N partial sigs into one
- verifyThresholdEnvelope: single verify call on aggregated sig
- splitPrivateKey / reconstructPrivateKey: Shamir Secret Sharing over BLS scalar field
- Separate package (@7h3/protocol-threshold) using @noble/curves

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

[0.1.0]: https://github.com/IceMasterT/7h3-protocol/releases/tag/v0.1.0
