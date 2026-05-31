# 7h3 Protocol

**AIP — the Aurelion Interaction Protocol.** A deterministic, signed, replay-safe messaging layer for AI-to-AI and agent-to-agent traffic, with byte-identical verification across **TypeScript, Python, and Rust**. Wire version: `aip/0.1`.

> The signing-and-replay layer your agent protocol forgot.

---

## Why this exists

As of 2026, the dominant agent protocols still leave the message itself unprotected:

- **MCP** sends JSON-RPC messages **unsigned**, with **no replay protection** — parameters can be altered in transit and valid messages replayed indefinitely.
- **A2A** added *Signed Agent Cards*, but that signs the *identity card* for domain verification — **not** the per-message task traffic.

7h3 Protocol fills exactly that gap: it signs, TTL-bounds, and replay-checks **every message** — a hardening envelope you put *around* MCP/A2A traffic, not a competitor to them.

Use it when your agents trigger real side effects (writes, payments, tool calls) and you need tamper-evidence, replay-safety, and auditability.

## Guarantees

- **Authentic** — HMAC-SHA256 (HS256) or **Ed25519** signatures over a canonical payload (real WebCrypto, not hand-rolled).
- **Deterministic** — fixed-key-order canonicalization, so signatures match byte-for-byte across TS/Python/Rust.
- **Replay-resistant** — `(sender, messageId, nonce)` uniqueness window + TTL/clock-skew enforcement.
- **Polyglot** — one shared conformance fixture set proves parity across all three runtimes.

## Quick start (TypeScript)

```ts
import {
  createEnvelope, signEnvelopeHmac, verifyEnvelopeHmac, validateEnvelope,
} from '@7h3/protocol'

const secret = 'shared-secret'
const envelope = await signEnvelopeHmac(
  createEnvelope({ sender: 'planner', recipient: 'worker', intent: 'TASK', content: 'do-the-thing' }),
  secret,
)

const diagnostics = validateEnvelope(envelope)        // shape / TTL / version checks
const ok = await verifyEnvelopeHmac(envelope, secret) // tamper + auth check
// → replay-check downstream via the transport's InMemoryReplayCache (or a shared store)
```

## Install

```bash
npm install @7h3/protocol
```

Python and Rust SDKs live under `sdk/python` (`from aip7h3 import …`) and `sdk/rust` (`use aip7h3::…`).

## Status & honest scope

- ✅ 87-test core suite green (TS); real HMAC + Ed25519; genuine TS/Python/Rust conformance parity.
- ⚠️ The in-memory replay cache is single-node — use the distributed-cache interface (`docs/DISTRIBUTED_REPLAY.md`) with a shared store for horizontal scale.
- ⚠️ No built-in key revocation/expiry enforcement layer yet (see `docs/THREAT_MODEL.md` for the full open-risk list).
- Not yet independently security-audited. Reproductions welcome.

## Docs

Architecture, threat model, key management, benchmarking methodology, and release governance live in [`docs/`](./docs). Independent examination: [`docs/PROJECT_EXAMINATION_2026-05-31.md`](./docs/PROJECT_EXAMINATION_2026-05-31.md).

## License

MIT.
