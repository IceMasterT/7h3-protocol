# Changelog

All notable changes to `@7h3/protocol` are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
