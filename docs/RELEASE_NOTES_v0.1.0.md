# v0.1.0 — First public release

> **The signing-and-replay layer your agent protocol forgot.**

MCP sends JSON-RPC unsigned. A2A signs the identity card, not the traffic.  
`@7h3/protocol` puts a signed, TTL-bounded, replay-checked AIP envelope around every message — without touching your handler.

## What's included

**Core AIP (`aip/0.1`)**  
Real WebCrypto HMAC-SHA256 + Ed25519 over a deterministic canonical form. Byte-identical signatures in TypeScript, Python, and Rust via a shared conformance fixture.

**Distributed replay protection**  
Redis-backed `SET NX PX` atomic reserve. Client-agnostic (`RedisLikeClient`) — works with ioredis, node-redis, or any adapter. Graceful degradation to local store on Redis outage; `onDegraded` hook for observability.

**Fleet-wide key revocation**  
Cached reads, fail-closed default. Wraps any `SignatureResolver` — one line to add revocation to an existing verify path.

**MCP hardening wrapper**  
Drop `wrapMcpServer` around your handler. Add `wrapMcpClient` on the caller. Four threat bindings enforced out of the box:

| Binding | Defends against |
|---|---|
| Recipient | Cross-server replay |
| Sender | Response spoofing |
| Correlation | Response substitution |
| Replay (default on) | Duplicate execution |

**Transport adapters**  
`serveMcpOverStdio` + `createHttpMcpHandler` — real transports, no new npm deps.

## Install

```bash
npm install @7h3/protocol
```

## Quick demo

```bash
git clone https://github.com/IceMasterT/7h3-protocol
cd 7h3-protocol && npm install
npm run aip:mcp:wrap   # proves tamper + replay rejection
```

## Honest caveats

- No independent security audit yet — reproductions and findings welcome.
- Distributed stores require a Redis (or equivalent) control plane; operators own HA and clock sync.
- Wire version `aip/0.1` is stable; the TypeScript API is pre-1.0 (minor version may bring breaking changes).

## License

MIT.
