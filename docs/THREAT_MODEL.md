# 7h3 Protocol threat model

Last reviewed: 2026-09-30 (internal, AI-assisted). This is **not** an independent audit.
See [Verification evidence](#verification-evidence) for what backs each claim, and
[What this does not protect against](#what-this-does-not-protect-against) for the limits.

Update this document whenever a module is added; the tables in
[Threats and controls](#threats-and-controls) are meant to have a row for every one.

## Scope

In scope: everything the `@7h3/protocol` package and its sibling packages do.

| Layer | Modules |
|---|---|
| Message signing and transport | `protocol.ts`, `protocolTransport.ts`, `protocolReplay.ts`, `replayStores.ts`, `httpBinding.ts`, `wsBinding.ts`, `grpcBinding.ts`, `queueBinding.ts`, `webhookBinding.ts`, `encryption.ts`, `stream.ts` |
| Gateway and policy | `gateway.ts`, `routePolicy.ts`, `rateLimiter.ts`, `signedResponse.ts`, `auditLog.ts`, `cloudflare/` |
| Authority | `capability.ts`, `approval.ts`, `provenance.ts`, `mandate.ts`, `actionBinding.ts` |
| Standards interop | `httpMessageSignatures.ts`, `webBotAuth.ts`, `dpop.ts`, `jose.ts` |
| MCP | `mcpWrapper.ts`, `mcpTransports.ts`, `mcpGateway.ts`, `mcpToolPinning.ts`, `mcpSse.ts`, `mcp-server/` |
| Identity and keys | `agentIdentity.ts`, `attestation.ts`, `keyLog.ts`, `keyInfra.ts`, `keyRegistry.ts`, `keyRotation.ts`, `revocation.ts` |
| Browser agents | `sdk/webmcp/` |
| Other runtimes | `sdk/python`, `sdk/rust`, `sdk/go`, `sdk/browser`, `sdk/pq`, `sdk/threshold` |

**Status by runtime.** The signed envelope, canonicalization, replay and conformance
vectors are implemented in TypeScript, Python, Rust and Go and must agree byte for byte.
Approval, provenance, mandates, RFC 9421, Web Bot Auth, DPoP, MCP tool pinning, signed SSE,
Agent Cards, `did:key`, attestation and the key log are **TypeScript only**. A deployment
that needs them in another language does not have them.

## System model and adversaries

```
 agent ──signed message──▶ [ gateway ] ──verified request──▶ upstream service
   │                            │  ▲
   │  key lookup                │  │ approvals, attestations, key log, revocation
   ▼                            ▼  │
 key registry / key log    approvers, attesters, replay & ledger stores
```

Trust boundaries: the network between every pair of components; the model that
drives an agent; every piece of content an agent reads; every MCP server and tool
description; the operator of any registry, log or attester.

Adversaries considered:

1. **Network attacker**: reads, modifies, drops, reorders and replays traffic.
2. **Malicious or compromised agent**: holds a valid key and tries to exceed its authority.
3. **Content author**: controls text the agent reads (an email, a web page, a tool result) and tries to steer the agent (prompt injection).
4. **Malicious MCP server**: ships benign tool descriptions, then changes them, or hides instructions in them.
5. **Token thief**: obtains an access token or a captured request from a log, a prompt or a proxy.
6. **Malicious registry, log or attester operator**: tries to substitute a key or vouch for a bad build.
7. **Malicious or careless approver**: a human who approves what they should not.
8. **Resource exhauster**: sends oversized, deeply nested or numerous inputs.

## Assets

Message integrity and authenticity; agent identity and the key that represents it;
freshness; the authority an agent holds (scopes, spend, approvals); the integrity of
what a model reads (tool descriptions); the integrity of the key registry and its
history; money; the audit trail.

## Assumptions

- Private keys are generated, stored and provisioned securely by the deployment. 7h3 does not protect a key that has been stolen.
- Clocks are roughly synchronized (default tolerance 30 seconds).
- Replay, revocation, approval and spend state lives in a store that is correctly provisioned, available and, for anything multi-instance, **shared and atomic**. The in-memory defaults are per process.
- The platform's WebCrypto and `node:crypto` are correct.
- Humans who approve actions actually review what they approve.

## Threats and controls

### Message integrity, authenticity and freshness

| Threat | Controls | Notes |
|---|---|---|
| Tampering in transit | Ed25519 or HMAC-SHA256 over a deterministic canonical form; verification before acceptance | Cross-runtime conformance vectors |
| Replay | TTL plus nonce dedup (`protocolReplay`, `replayStores`); default in-memory cache; shared store for multi-instance | An in-memory store does not span instances or restarts |
| Replay-key collision | Composite keys are `encodeURIComponent`-escaped (fixed 2026-06) | |
| Impersonation | Verification material resolved by `(keyId, sender)`; per-route `allowedSenders` | |
| Algorithm confusion, downgrade | Explicit `alg` in the signature object; the verifier requires the resolved algorithm to match | Same rule in RFC 9421, DPoP and Agent Card verification: the algorithm comes from the trusted key, never the message |
| Non-finite or huge time values defeating TTL | `validateEnvelope` rejects them; TTL capped at 24 h | |
| Eavesdropping | X25519 + ChaCha20-Poly1305 sealed envelopes with forward secrecy; signature verified before decryption | |
| Stream tampering | Per-chunk HMAC + final Ed25519 (`stream.ts`) | |
| Quantum attack on signatures | ML-DSA via `sdk/pq` | Optional package |

### Gateway

| Threat | Controls | Notes |
|---|---|---|
| Path traversal, encoded or double-encoded `..` | One normalization (`normalizeGatewayPath`) used for both policy matching and forwarding; anything that escapes the root or does not settle is refused | |
| Spoofed trust headers reaching the upstream | Caller-supplied `x-7h3-sender`, `-verified`, `-approved-by`, `-trust`, `-approval` and `dpop` are dropped before forwarding (any case) | Fixed 2026-09; before that a caller could send `x-7h3-verified: true` on an unauthenticated route |
| Bypass via the alternative auth path | Capability-token authentication goes through the same `allowedSenders`, rate-limit and approval checks | |
| Misconfiguration that silently allows | `createProductionGateway` refuses `defaultPolicy != 'deny'` or a missing replay store; approval, `http-signature` and `dpop` policies without their configuration throw at construction | |
| Rate abuse by spoofing IPs | Limits are keyed by verified sender identity | |
| Audit log tampering | Ed25519-signed, hash-chained entries; `verifyAuditChain` detects modification, deletion and reordering | |

### Authority: what an agent may do

| Threat | Controls | Notes |
|---|---|---|
| Agent exceeds its scope | Scoped, expiring capability tokens; delegation can only narrow (scope, TTL, depth) and this is re-checked on every hop at verification | |
| Agent tricked into a damaging action inside its scope | Step-up approval (`approval.ts`): a named approver countersigns one action, bound to agent, method, normalized path and body hash; at most 10 minutes; single use; no self-approval; a failed presentation does not consume the grant | The approver must actually look. See non-goals |
| Untrusted content drove the action | Provenance claims (`provenance.ts`): signed trusted/untrusted labels bound to the action; a route can require approval only when inputs were untrusted; a missing or invalid claim counts as untrusted | Does not detect injection; the label comes from the agent runtime's taint tracking and is only as good as that |
| Approval reused elsewhere | Bound to subject, action digest, expiry and a single-use store; the grant is stripped before forwarding | |
| Agent overspends | Payment mandates (`mandate.ts`): payer-signed intent, merchant-signed cart, agent-signed payment; recomputed totals, digest-bound carts, merchant, category and per-purchase limits, a cumulative ceiling through an atomic idempotent ledger, human approval above a threshold | The default ledger is per process; a replicated processor needs an atomic store |

### MCP

| Threat | Controls | Notes |
|---|---|---|
| Rug pull: a server changes a tool's description after approval | `mcpToolPinning.ts`: digest of everything the model reads, signed pin sets bound to a server, `guardMcpClient` filters `tools/list` and refuses `tools/call` for changed or unpinned tools, re-verifying when stale | A change is not seen until the next verification (`maxListAgeMs`); `0` verifies every call |
| Hidden instructions in a description (invisible, tag, bidi and control characters) | Scanner refuses such tools even if pinned; scans nested schema text and property names | Does not judge visible text: a poisoned description written in plain sight is caught only because it differs from the pin a human approved |
| Tool shadowing (two tools, one name) | Both blocked | |
| SSE stream tampering, gaps, reordering, splicing, truncation | `mcpSse.ts`: per-event signature, signed stream id, strict sequence, replay cache, signed end event | No `Last-Event-ID` resume: a reconnect must open a new stream |
| Relay to another server, response substitution | Recipient, sender and correlation binding in `mcpWrapper` | |

### Standards interop

| Threat | Controls | Notes |
|---|---|---|
| A valid RFC 9421 signature that covers too little | The verifier states the required components and refuses anything less; body binding via `Content-Digest`; `@query` required when a query exists; freshness bound; single-use nonces; only the first matching signature is verified | Identity-only Web Bot Auth signatures (`@authority` alone) prove who, not what, and are refused by the gateway default |
| Stolen OAuth access token | DPoP (`dpop.ts`): proof bound to method, URL, token hash and the key the token is bound to; single-use `jti`; server nonces | Token issuance (binding) is outside this library |
| SSRF through `Signature-Agent`, `jku` or key discovery | The verifier never fetches these; the caller supplies `resolveKey`/`resolveKeys` behind an allow-list; `fetchKeyDirectory` is https-only with a fixed path, no redirects, bounded size | |
| Downgrade of an unbound token on a DPoP route | A token with no key binding is refused | |

### Identity and keys

| Threat | Controls | Notes |
|---|---|---|
| Key discovery steered at an internal host (SSRF via the unverified `sender` field) | `createHttpKeyRegistry` refuses IPs, `localhost`, internal-style names, ports, paths and credentials; no redirects; bounded size and cache; `allowedDomains` | Fixed 2026-09. A public-looking name can still resolve to a private address: set `allowedDomains` |
| Valid Agent Card copied onto an attacker's host | `expectedOrigin` pinning: the card must declare an endpoint on the origin it was fetched from | |
| Unsigned or tampered Agent Card | Any change invalidates the signature; an unsigned card is never trusted | |
| `did:key` treated as proof of who someone is | Documented: it proves key possession only; must be paired with an allow-list | |
| Right key, wrong software | Attestation (`attestation.ts`): a trusted attester signs "agent, key, measurements"; digest allow-lists; bound to one agent and one key; `createAttestedKeyRegistry` yields keys only for attested agents and fails closed | Does not verify hardware evidence; exactly as trustworthy as the attester |
| Registry silently swaps a key | Key log (`keyLog.ts`): signed hash chain, enforced rules (a revoked key never returns), signed checkpoints, `logExtendsCheckpoint` catches a re-signed rewrite, `checkpointsConflict` is transferable evidence of equivocation | Tamper-evident, not tamper-proof; linear verification; split views need checkpoint exchange |
| Compromised key keeps working | Revocation store consulted on the verify path (fail closed); key rotation with overlap | Depends on the store's availability |

### Denial of service and resource exhaustion

| Threat | Controls |
|---|---|
| Oversized or deeply nested input | Size limits on headers, proofs, cards, SSE events, key documents and directories; bounded parse depth and counts in structured-field, JWS and tool-scan code; decoders never throw on garbage (fuzzed) |
| Cache and store growth from attacker-chosen keys | Bounded caches; `MemoryReplayStore` fails closed at capacity instead of evicting live keys |
| Expensive verification | In most verifiers, structural, coverage and freshness checks run before signature verification; nonces, approvals and single-use proofs are consumed only for otherwise valid requests |

### Supply chain

| Threat | Controls | Notes |
|---|---|---|
| Malicious dependency | Zero runtime dependencies in the core package; a small surface in `sdk/pq`, `sdk/threshold` and `mcp-server`; Dependabot updates, each checked against the tests and builds before merging | |
| Tampered release | npm provenance attestations on publish; GitHub Actions pinned by commit SHA; secret scanning (gitleaks) in CI | |
| Unknown component inventory | A CycloneDX SBOM is generated in CI and attached to releases | npm packages only; the Python SDK has no runtime dependencies and the Rust crate's dependencies are in `Cargo.lock` |

## What this does not protect against

- **Prompt injection is not detected.** Nothing inspects content. Provenance labels and approvals limit the damage of a tricked agent; they do not stop it being tricked, and a provenance label is only as honest as the runtime that produced it. A model must never be allowed to write its own label.
- **A stolen private key.** Whoever holds it is the agent until it is revoked.
- **A compromised endpoint.** An agent host that is fully compromised can request approvals, present valid provenance and sign anything its key allows.
- **A careless approver.** An approval is only as good as the human's review.
- **A malicious operator who is not being watched.** A registry, log or attester operator can publish a bad key or vouch for a bad build; the key log makes that visible to monitors, it does not prevent it.
- **Hardware attestation.** SGX, SEV-SNP, TDX and TPM evidence is not verified by 7h3.
- **Traffic analysis and availability attacks** beyond the resource limits above.
- **Side channels** beyond constant-time signature verification.
- **Correctness of a third party's protocol.** Where the Web Bot Auth draft's own published vector for a dictionary-form `Signature-Agent` disagrees with RFC 9421 (see `docs/HTTP_MESSAGE_SIGNATURES.md`), this implementation follows the RFC, so a signer that reproduces the draft's listed vector will be rejected.

## Verification evidence

| Claim | Evidence |
|---|---|
| Canonicalization and signatures agree across runtimes | `conformance/*.json` vectors, exercised by TypeScript, Python, Rust and Go |
| RFC 9421 implemented correctly | Reproduces the RFC's Ed25519 (B.2.6) and HMAC (B.2.5) signatures byte for byte; exact signature bases for B.2.1, B.2.2 and Figure 1; reproduces the Web Bot Auth draft's Ed25519 vector A.2.1 and its JWK thumbprint |
| DPoP implemented correctly | Reproduces the RFC 9449 example JWK thumbprint and `ath`; the RFC's example proof verifies as received |
| JCS implemented correctly | RFC 8785's sample, its UTF-16 sorting example and all 22 Appendix B number samples |
| `did:key` implemented correctly | The did:key specification's example round-trips and derives the X25519 key its DID document lists |
| Parsers do not crash | TypeScript fuzz harnesses (`fuzz/`, decoder and verifier) run in CI on every push (`npm run fuzz:ts`). Rust `cargo-fuzz` targets exist in `sdk/rust/fuzz` but are not run in CI. The new modules have no dedicated fuzz harness: their coverage is hostile-input unit tests |
| Security checks actually bite | Each new security control was mutation-tested: the check was removed and the suite had to fail. Survivors were either closed with a new test or recorded as equivalent (redundant defense in depth). This found real gaps, for example a missing unsigned-envelope injection test and a cache that survived a key rotation |
| Overall | 1,108 TypeScript tests plus 106 Python, 35 Go and 31 Rust |

Not done: an independent third-party audit (see `SECURITY.md`), and formal verification.
The internal review of 2026-06-05 (`SECURITY_REVIEW_2026-06-05.md`) predates most of the
modules above and was performed by the same AI assistant that co-developed parts of the code.

## Remaining risks (open)

- Approval, provenance, mandates, RFC 9421, DPoP, MCP hardening and the identity modules exist only in TypeScript.
- Replay, revocation, approval, nonce and spend state depends on a correctly provisioned shared store; the in-memory defaults do not span instances or restarts. The default `SpendLedger` is atomic only within one process.
- The key log is linear-time and single-operator, and split-view detection needs an exchange of checkpoints that nothing in the library performs.
- An attestation's trust is exactly the attester's.
- No third-party cryptographic audit.

## Required production mitigations

- Keep signature verification on in production; use `createProductionGateway`.
- Deploy shared stores (`createRedisReplayStore`, a shared approval and nonce store, an atomic `SpendLedger`) for anything horizontally scaled or restarted.
- Wire a shared revocation store (`createRedisRevocationStore` + `withRevocationCheck`) and enforce key rotation, expiry and revocation.
- Set `allowedDomains` on `createHttpKeyRegistry`, an allow-list in every `resolveKey`/`resolveKeys` that can fetch, and `expectedOrigin` when verifying Agent Cards.
- Require approval on routes that can spend, delete or send, and produce provenance labels from the agent runtime's own data-flow tracking, never from the model.
- Pin MCP tools from a reviewed pin set and keep `maxListAgeMs` short where descriptions matter.
- Hold on to a key-log checkpoint and exchange checkpoints with other relying parties if you rely on the log to detect a malicious operator.
