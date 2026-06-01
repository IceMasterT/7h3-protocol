# @7h3/protocol — Independent Examination (updated 2026-06-01)

**Original examination:** 2026-05-31 · **Updated:** 2026-06-01 (post-extraction, post-publish)  
**Reviewer stance:** Independent audit — claims split into **Verified** (ran it / read the code) vs **Asserted** (repo says so, unverified).  
**Repo:** `github.com/IceMasterT/7h3-protocol-aip` · local `/media/artiq/DATA/7h3-protocol`  
**Package:** `@7h3/protocol@0.1.0` · live on npm · MIT

---

## 0) TL;DR

AIP is a **cryptographic hardening envelope for MCP and A2A traffic** — per-message signing, TTL-bounding, and replay-checking that those protocols don't provide natively. It is now extracted, published, and public. The engineering is real. The market gap is real and publicly acknowledged. The first meaningful risk is adoption, not implementation.

---

## 1) What shipped

### Core protocol (`aip/0.1`)
- `protocol.ts` — envelope model, deterministic canonicalization (fixed key order), HMAC-SHA256 / Ed25519 signing and verification over real WebCrypto. Key handles LRU-cached.
- `protocolTransport.ts` — wire encode/decode (`json` / `compact` / `binary`), full receive pipeline (validate → canonicalize → verify → replay-check), batch/session transport with bounded-concurrency and telemetry hooks.
- `protocolBinary.ts` — MessagePack binary wire codec (highest-throughput lane).
- `protocolReplay.ts` — `InMemoryReplayCache` (`(sender, messageId, nonce)` uniqueness window + TTL); `DistributedReplayCache` wrapping any `DistributedReplayStore`.
- `keyRotation.ts`, `protocolCapabilities.ts`, `protocolAgent.ts` — key lifecycle, capability negotiation, agent identity.
- `runtimePolicy*.ts` + `policyEnforcer.ts` + `policyTelemetryFeedback.ts` — declarative transport/retry/safety policy with telemetry-driven feedback.
- `mcpGateway.ts`, `frameworkAdapters.ts`, `agentAdapter.ts` — JSON-RPC gateway runtime, LangChain/LlamaIndex/JSON-RPC bridges.

### Distributed stores (production gap — now closed)
- `redisClient.ts` — `RedisLikeClient` interface (client-agnostic; no Redis npm dep) + `InMemoryRedisLikeClient` reference impl.
- `replayStores.ts` — `createRedisReplayStore`: atomic `SET NX PX` reserve, `reserveMany` batch pipeline, `errorBehavior: 'fallback' | 'reject' | 'allow'`, `onDegraded` observability hook. Default: degrade-to-local, never silent.
- `revocation.ts` — `InMemoryRevocationStore`; `createRedisRevocationStore` (cached reads, **fail-closed default**); `withRevocationCheck` wraps any `SignatureResolver` — one line to add fleet-wide revocation to any verify path.

### MCP hardening wrapper (production gap — now closed)
- `mcpWrapper.ts` — `wrapMcpServer` / `wrapMcpClient` / `createMcpClientCodec`. Wire message is a signed AIP envelope carrying JSON-RPC in `body.content`; handler receives plain JSON-RPC (zero app changes).
  - **Recipient binding** — server rejects envelopes not addressed to `selfAgentId` (cross-server relay defense).
  - **Sender binding** — client accepts responses only when `sender === peerAgentId` (response-spoof defense).
  - **Correlation binding** — client enforces `correlationId === request messageId` (response-substitution defense).
  - **Replay on by default** — `InMemoryReplayCache` injected if none supplied.
- `mcpTransports.ts` — `serveMcpOverStdio` / `createStdioMcpClient` (newline-delimited, in-order sequential chain); `createHttpMcpHandler` / `createHttpMcpClient` (`node:http` + global `fetch`, `binary` mode). No new runtime dependencies.

### Polyglot parity
- Python SDK (`sdk/python`, `from aip7h3 import …`)
- Rust SDK + gateway (`sdk/rust`, `use aip7h3::…`)
- Shared conformance fixtures (`conformance/aip_v0_1.json`) drive byte-identical signature verification across all three runtimes.

### Governance scaffolding
`docs/`: THREAT_MODEL, KEY_MANAGEMENT_POLICY, CLOCK_SKEW_POLICY, DISTRIBUTED_REPLAY, KEY_REVOCATION, MCP_WRAPPER, TELEMETRY, PERF_REGRESSION_POLICY, VERSIONING_POLICY, MIGRATION_GUIDE, RELEASE_GATE. Benchmark harnesses, release dashboard generator, canary planner.

---

## 2) Auditor's ledger

### ✅ Verified (ran it / read the code)

**123 tests pass across 22 files in ~924ms.** (`npx vitest run`, 2026-06-01). Real coverage: envelope conformance, negative/malformed corpus, fuzz/property tests, replay cache (in-memory + distributed + batch), key rotation, transport, binary codec, gateway, policy, revocation, MCP wrapper (round-trip, tamper-reject, replay-reject, recipient/sender/correlation binding), stdio transport (PassThrough streams), HTTP transport (real `http.Server` on ephemeral port).

**Real cryptography.** `protocol.ts` uses `crypto.subtle` — genuine HMAC-SHA256 and Ed25519 (PKCS8/SPKI import, base64url encoding). Not hand-rolled.

**Deterministic canonicalization is real.** Fixed key order (not recursive sort), explicit `body`-then-`header` layout. This is what makes cross-language parity *provable*, not just asserted.

**Genuine tri-language parity.** Python `unittest` and Rust `cargo test` both driven by the same JSON fixture set. Signatures verified against the same known vectors in all three runtimes.

**Redis stores work.** Live-Redis integration test (`redisIntegration.test.ts`): replay reserve via `SET NX PX` and revocation round-trip both confirmed against a real server. Test auto-skips if no server present — no false passes.

**Infinite-recursion bug in fallback chain caught by TDD before shipping.** `createRedisReplayStore` with default `errorBehavior:'fallback'` initially created a fallback store that also tried to create its own fallback. Fixed by passing `{ errorBehavior: 'reject' }` to the inner store. The test suite caught this before it shipped.

**MCP wrapper security bindings all independently tested.** Each binding (recipient, sender, correlation, replay-default) has its own test that verifies rejection of the specific attack it defends against.

**Honest threat model.** Lists remaining open risks (see §6). That candor is a credibility asset.

**Published and public.** `@7h3/protocol@0.1.0` on npm. `github.com/IceMasterT/7h3-protocol-aip` public. 12 GitHub topics set.

### ⚠️ Asserted (treat as marketing until independently reproduced)

- Benchmark numbers are from one dev machine with no external methodology audit. Read them as "comfortably adequate," not headline performance.
- Python and Rust SDKs share the conformance fixture but the Python Ed25519 path requires the `cryptography` package (skipped if absent). Rust integration is straightforward but has not been published to crates.io.
- No third-party security audit. For a cryptographic protocol, a formal audit or at minimum an external reproduction of conformance vectors is the credibility step this hasn't cleared yet.

> Precedent from this workspace: a self-reported "95/100" on a separate project was independently re-scored to ~22. The discipline here is better (green suite, shared fixtures, honest risk listing), but the rule stands — believe the test run; discount self-graded readiness claims.

---

## 3) Architecture

### Receive pipeline (core)

```
wire bytes ──▶ decode (json | compact | binary)
           ──▶ validate envelope shape + policy (version, ids, ttl, clock-skew)
           ──▶ canonicalize (fixed key order, body→header layout)
           ──▶ verify signature (HS256 | Ed25519) via key/secret resolver
                   └──▶ withRevocationCheck (optional, wraps resolver)
           ──▶ replay-cache check (sender, messageId, nonce) + TTL window
                   └──▶ InMemoryReplayCache  (single-node)
                   └──▶ DistributedReplayCache → RedisReplayStore (fleet-wide)
           ──▶ accept ──▶ app handler
```

### MCP wrapper pipeline

```
JSON-RPC request
    ──▶ createEnvelope (sender=client, recipient=server, content=json-rpc)
    ──▶ signEnvelope
    ──▶ [transport: stdio newline / HTTP POST]
    ──▶ wrapMcpServer receives WireEnvelope
    ──▶ receiveEnvelope (full pipeline above)
    ──▶ recipient binding check (recipient === selfAgentId)
    ──▶ handler(plain json-rpc)  ←─ zero app changes
    ──▶ signEnvelope(response, correlationId=request.messageId)
    ──▶ [transport]
    ──▶ wrapMcpClient decodeResponse
    ──▶ sender binding (sender === peerAgentId)
    ──▶ correlation binding (correlationId === request.messageId)
    ──▶ returns plain JSON-RPC response
```

**Envelope structure:** `header{version, messageId, timestampMs, ttlMs, sender, recipient?, nonce}` + `body{intent, content, capability?, correlationId?}` + optional `signature{alg, keyId, value}`.  
**Intents:** `PING / PONG / CAPS / TASK / RESULT / ERROR` — a deliberately minimal verb set.

This is a textbook-correct message-security design: validate → canonicalize → verify → replay → accept. Nothing exotic, everything in the right order.

---

## 4) Performance — honest read

Quick-profile benchmarks (single dev machine, 2026-05-31):

| Metric | Value | Interpretation |
|---|---|---|
| Canonicalization | ~1.07M ops/s | Near-zero overhead |
| Compact codec (encode+decode) | ~0.98M ops/s | Near-zero overhead |
| Sign + verify (HMAC-SHA256) | ~38.3k ops/s | **Binding ceiling** |
| In-process E2E | ~50k ops/s, p99 ~4.7ms (c=100) | Protocol overhead only |
| Open-loop adaptive HTTP | ~10.2k ops/s, p99 ~13.4ms, 0% drop | Transport-bound, not protocol-bound |

The crypto sign+verify path (~38k/s/core) is the binding constraint. ~10k/s sustained over HTTP is honest and production-adequate for an agent control plane. This is not a "millions of messages/second" story, and the repo doesn't claim it — it explicitly distinguishes adaptive/sustainable throughput from firehose stress numbers. Market as **"predictable, signed, replay-safe throughput,"** never as raw speed.

---

## 5) Best use case

**Lead with:** a drop-in cryptographic trust layer for MCP-mediated tool calls and multi-agent traffic — especially any flow where tool calls trigger real side effects (writes, payments, actions).

AIP is at its best when:
- 2+ agents or services are exchanging messages,
- tool calls cause side effects that must not be replayed or tampered with,
- you need tamper-evidence, replay-safety, and an audit trail,
- you run a polyglot stack (TS orchestrator + Rust gateway + Python workers) and need signatures to match across all three.

**Runnable entry point:** `npm run aip:mcp:wrap` — demonstrates tampered and replayed requests rejected in under 30 seconds.

**Where not to use it:** single-process prototypes, no trust boundary, exploratory prompt UX. The repo says this itself.

---

## 6) Market positioning

The competitive landscape (verified 2026-05-31) strongly favors a **complement-not-compete** posture:

- **MCP** (Anthropic): JSON-RPC messages sent unsigned, no replay protection. Open issues requesting per-message signing. Community spec **MCPS** proposes a signing + nonce envelope as a backward-compatible layer. ~8.5% of MCP servers use OAuth.
- **A2A** (Google, v1.2): Signed Agent Cards authenticate the identity card for domain verification — **not** per-message task traffic.

AIP implements exactly the missing layer for both. The gap is not a niche opinion — it's in NSA guidance, in public GitHub issues, and in active community proposals. The positioning writes itself:

> **"The signing-and-replay layer your agent protocol forgot."**  
> Sign, TTL-bound, and replay-protect every MCP/A2A message — with byte-identical verification across TypeScript, Python, and Rust.

Do **not** position AIP as a competing agent protocol. Position it as the hardening envelope / trust middleware those protocols lack natively. The moat is "works today, polyglot, already tested, MIT."

**Standardization risk:** MCPS or MCP itself may standardize this natively. That is the primary time-sensitivity argument. AIP's edge is "running in prod now," not "only possible solution."

---

## 7) Shipped state vs original plan

The original examination identified four blockers and five execution steps. Current status:

| Item | Status |
|---|---|
| Protocol never published / `private:true` / version `0.0.0` | ✅ `@7h3/protocol@0.1.0` live on npm |
| Esolang-branded name buries the protocol | ✅ Extracted to `7h3-protocol-aip`; npm `@7h3/protocol` |
| In-memory replay cache insufficient for multi-node | ✅ `createRedisReplayStore` — atomic `SET NX PX`, batch pipeline, graceful degradation |
| No revocation/expiry enforcement layer | ✅ `createRedisRevocationStore` + `withRevocationCheck` — fail-closed, cached |
| No MCP integration artifact | ✅ `wrapMcpServer` / `wrapMcpClient` + stdio + HTTP transport adapters |
| Repo public and discoverable | ✅ Public, 12 topics, GitHub release v0.1.0 |

**What the original plan identified as gaps that were then built before launch — not retrofitted.** That sequence (design → TDD → ship) is why the shipped state is consistent.

---

## 8) Open risks (carry forward)

- **Adoption is the only live risk.** An unadopted protocol's value is ~0 regardless of implementation quality. First real users matter more than a seventh benchmark run. The MCP wrapper is the fastest path to "I protected my MCP server this afternoon."
- **No independent security audit.** For a signing protocol, a third-party crypto review is the credential that converts skeptics. Particularly: the canonicalization algorithm (fixed-key-order scheme) and the nonce/TTL window assumptions deserve an external read.
- **No formal fuzz campaign** on parser boundaries (wire decode, envelope validation). Reproducible fuzz corpus welcome.
- **Distributed stores require an available Redis control plane.** Operators own HA and clock synchronization. Documented in `docs/DISTRIBUTED_REPLAY.md`; runtime degradation is observable via `onDegraded` hook.
- **Wire version `aip/0.1` is frozen.** Any break to the envelope schema, canonicalization algorithm, or intent vocabulary is a major version bump. The TypeScript API is pre-1.0 — minor version may bring breaking changes.
- **Python and Rust packages not yet published** (PyPI, crates.io). Polyglot claim is verifiable via the shared conformance fixture, but `pip install` and `cargo add` don't work yet.
- **Standardization race.** MCPS or MCP native signing could absorb the niche. Speed of community adoption is the hedge.

---

## 9) Bottom line

The engineering shipped clean: 123 tests green, real cryptography, genuine tri-language parity, four MCP security bindings all independently tested, distributed stores with graceful degradation, and a live-Redis integration test confirming the round-trip. The original examination's two core diagnoses — *mis-packaged* and *mis-positioned* — have both been addressed. The protocol is now a real, installable, documented, public artifact with honest caveats.

The question is no longer "is this good enough to release?" It is "can it earn enough adoption that the standardization window doesn't close first?" That is a distribution and community problem, not an engineering problem. The MCP wrapper is the lever: it gives any developer a same-afternoon path from "interesting" to "running in my stack."

---

### Sources (competitive landscape, verified 2026-05-31)

- MCP lacks per-message auth/integrity: https://github.com/google/mcp/issues/32
- State of MCP Security 2026 (unsigned messages, no replay, MCPS proposal): https://nimblebrain.ai/blog/state-of-mcp-security-2026/
- MCP Security Checklist 2026: https://www.networkintelligence.ai/blogs/model-context-protocol-mcp-security-checklist/
- NSA MCP security guidance: https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf
- "MCP is dead, long live MCPS" (per-message signing + nonce replay envelope): https://dev.to/razashariff/mcp-is-dead-long-live-mcps-5ddp
- A2A Signed Agent Cards (card-level, not per-message): https://cloud.google.com/blog/products/ai-machine-learning/agent2agent-protocol-is-getting-an-upgrade
- A2A protocol overview: https://a2a-protocol.org/latest/
