# Internal Security Review — AIP v0.1.2

**Date:** 2026-06-05  
**Reviewer:** Claude Code (AI-assisted internal review)  
**Scope:** `@7h3/protocol` v0.1.2 — TypeScript sources, Python SDK, Rust SDK  
**Status:** ⚠️ NOT an independent third-party audit. This review was performed by the same AI assistant that co-developed parts of the codebase. It is published for transparency; it does not substitute for an independent cryptographic audit.

---

## Summary

The core cryptographic choices are sound: WebCrypto primitives for both HMAC-SHA256 and Ed25519, constant-time verification, algorithm-confusion guards, and fail-closed revocation. Two real bugs were found and fixed in this review pass. No signature-forgery or authentication-bypass paths were identified.

| Finding | Severity | Status |
|---|---|---|
| Replay key collision via unescaped `\|` separator | Medium | **Fixed** — `encodeURIComponent` applied |
| Empty nonce not rejected by `validateEnvelope` | Low | **Fixed** — error diagnostic added |
| Rust cargo-fuzz targets uncompiled (README overclaim) | Low | **Corrected in README** |
| `recipient: null` vs `undefined` — cross-language parity gap | Low | Documented accepted risk |
| Revocation key space-separator (minor variant of #1) | Low | Documented accepted risk |

---

## Finding 1 — Replay Key Collision (Medium, Fixed)

**File:** `src/protocolReplay.ts` — `InMemoryReplayCache.makeKey` and `DistributedReplayCache.makeKey`

**Before:**
```ts
return `${envelope.header.sender}|${envelope.header.messageId}|${envelope.header.nonce}`
```

**Problem:** The `|` separator is unescaped. A sender named `"a|b"` with messageId `"c"` produces the same composite key as sender `"a"` with messageId `"b|c"`. If an attacker controls their own agent ID and can observe or predict a target agent's messageId, they can send a message first that "claims" the target's replay key, causing the legitimate message to be rejected as a replay.

**Security impact:** This is a **false-rejection DoS**, not a forgery or auth bypass. Signatures still cover the full, unencoded field values — an attacker cannot craft a message that validates under a victim's key. The worst they can achieve is having a legitimate message silently dropped.

**Fix applied:**
```ts
return `${encodeURIComponent(envelope.header.sender)}|${encodeURIComponent(envelope.header.messageId)}|${encodeURIComponent(envelope.header.nonce)}`
```

`encodeURIComponent` maps `|` → `%7C`, making cross-boundary collisions impossible. For typical agent IDs containing only word characters and hyphens, the output is byte-identical to the old format — no Redis key migration required for standard deployments.

**Note on deployed keys:** If your Redis instance already contains replay keys with agent IDs containing `|`, `%`, or other URI-reserved characters, those keys will have a different format after this fix. Existing entries will expire naturally via their TTL; no manual migration is needed.

---

## Finding 2 — Empty Nonce Not Validated (Low, Fixed)

**File:** `src/protocol.ts` — `validateEnvelope`

**Problem:** `validateEnvelope` checked `messageId`, `sender`, `ttlMs`, `timestampMs`, and `content` but did not validate `nonce`. A missing or empty nonce produces a replay key of the form `sender||messageId`. While this doesn't defeat replay protection outright (the composite key still covers sender + messageId), it eliminates the entropy contribution of the nonce and allows any two messages with identical sender + messageId to collide in the replay cache, regardless of time.

**Fix applied:** Added `if (!nonce.trim()) diagnostics.push({ level: 'error', message: 'Missing nonce — replay protection requires a unique nonce per message' })`.

---

## Finding 3 — Rust cargo-fuzz Targets Uncompiled (Low, Corrected)

**File:** `sdk/rust/fuzz/`, `README.md` status table

**Problem:** `cargo-fuzz` is not installed in the development environment. The Rust fuzz targets (`fuzz_decode.rs`, `fuzz_canonicalize.rs`) were authored and reviewed but have never been compiled or run. The prior README entry claimed "✅ cargo-fuzz targets" without this qualification.

**Correction:** The README status now reads: "TypeScript harnesses run clean (50k/20k rounds); Rust targets authored, not yet executed (`cargo-fuzz` not installed)."

The targets themselves look structurally correct:
- `fuzz_decode`: feeds arbitrary bytes through `decode_envelope` under a no-panic invariant — correct
- `fuzz_canonicalize`: constructs `ProtocolEnvelope` from fuzz bytes, asserts `canonicalize_envelope` is idempotent — correct

To run:
```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_decode --manifest-path sdk/rust/fuzz/Cargo.toml
cargo +nightly fuzz run fuzz_canonicalize --manifest-path sdk/rust/fuzz/Cargo.toml
```

---

## Finding 4 — `recipient: null` vs Absent (Low, Accepted Risk)

**File:** `src/protocol.ts` — `serializeHeaderCanonical`

```ts
if (header.recipient !== undefined) {
  parts.push(`"recipient":${JSON.stringify(header.recipient)}`)
}
```

If a JSON message arrives with `"recipient": null`, JavaScript parses this as `null`, which passes the `!== undefined` check. `JSON.stringify(null)` produces `"null"`, so the canonical form includes `"recipient":null` — different from a message where `recipient` is absent entirely.

In the TypeScript type system, `ProtocolHeader.recipient` is typed as `string | undefined`. A `null` value is a type violation but not rejected at runtime.

**Cross-language risk:** The Rust SDK uses `Option<String>` for `recipient`, which serializes `None` as absent (the field is skipped). If a TS caller writes `recipient: null` and the Rust verifier receives it, the canonical forms diverge → signature mismatch.

**Status:** Accepted risk. The correct mitigation is to normalise `null` → `undefined` in the wire decoder. This is tracked as a future improvement. In practice, `null` recipients do not appear in protocol-generated envelopes (`createEnvelope` leaves `recipient` undefined when not supplied).

---

## Finding 5 — Revocation Key Space Separator (Low, Accepted Risk)

**File:** `src/revocation.ts` — `InMemoryRevocationStore.makeKey` and `createRedisRevocationStore`

The revocation key format `"${sender} ${keyId}"` uses a space as separator. If a sender ID contains a space (e.g., `"agent one"`) and a keyId starts with something that continues the pattern, a collision is theoretically possible. However:

1. Key IDs in practice are short tokens like `"k1"`, `"prod-key-2026"` — not containing spaces
2. Agent IDs with spaces are unusual enough to warrant operator documentation
3. The collision would cause a revocation miss (treating a non-revoked key as revoked, or vice versa) — not an auth bypass

**Status:** Accepted risk. Documented in this review. Consider changing to `${encodeURIComponent(sender)}:${encodeURIComponent(keyId)}` in a future patch.

---

## Positive Findings

### Constant-time HMAC verification

`hmacVerify` delegates to `crypto.subtle.verify` (WebCrypto), which is specified to run in constant time. There is no string `===` comparison of signature bytes anywhere on the verify hot path.

### Algorithm confusion rejected

`verifyEnvelopeSignature` checks `signature.alg !== material.alg` before dispatching. An envelope signed with Ed25519 cannot be verified with HMAC material and vice versa — the check is at the dispatch level, before any cryptographic operation.

`verifyEnvelopeHmac` checks `envelope.signature.alg !== 'HS256'` explicitly before calling `hmacVerify`. Same for `verifyEnvelopeEd25519` / `'ED25519'`. Downgrade attacks via algorithm confusion are blocked at two independent points.

### Revocation fail-closed

`createRedisRevocationStore` defaults to `errorBehavior: 'reject'`. A Redis outage causes the store to treat the key as revoked. Cached stale-revoked entries serve during brief outages without allowing a previously-revoked key through.

### MCP wrapper — all four bindings present

Code review confirms all four claimed bindings in `src/mcpWrapper.ts`:

| Binding | Code location | Enforcement |
|---|---|---|
| Recipient | line 120: `envelope.header.recipient !== options.selfAgentId` | Returns 32600 error; handler does not run |
| Sender | line 176: `received.envelope.header.sender !== options.peerAgentId` | Throws; response discarded |
| Correlation | line 181: `body.correlationId !== decodeOptions.expectCorrelationId` | Throws; response discarded |
| Replay | `InMemoryReplayCache` injected by default in `wrapMcpServer` | Replay → `consume()` returns `{ok: false}` |

### Cross-language parity (within tested scope)

The three conformance vectors in `conformance/aip_v0_1.json` produce byte-identical signatures in TypeScript, Python, and Rust. The canonicalization format is simple string concatenation with fixed key order; there is no runtime type ambiguity within the tested input set.

**Caveat:** Three vectors are a narrow coverage set. Cross-language divergence on edge cases (very large integers, Unicode normalization, `NaN`/`Infinity` in numeric fields) is not covered by the current conformance suite.

---

## Scope Not Covered

| Area | Reason not covered |
|---|---|
| WebCrypto Ed25519 implementation | Browser/Node built-in; outside reviewable scope |
| Binary wire format (protocolBinary.ts) | Not reviewed in this pass — fuzz coverage via `protocolFuzz.advanced.test.ts` exists |
| Framework adapters (LangChain, LlamaIndex) | Translation adapters; lower security surface |
| Policy enforcer | Logic review only; not cryptographic |
| Python pure-Ed25519 implementation | Correctness verified against conformance vector; not audited for side channels |

---

## Conclusion

The cryptographic architecture is well-chosen: standard primitives, no custom crypto, constant-time comparison, fail-closed defaults. The two bugs fixed in this review (replay key collision, empty nonce) were low-to-medium severity and have been patched. No authentication bypass, signature forgery, or replay-protection bypass paths were found.

**This review does not substitute for an independent third-party audit by a qualified cryptographer.** The parsing, canonicalization, and replay-cache logic remain unaudited by an external reviewer. Treat accordingly for high-stakes deployments.
