# 7h3 Protocol — Claude Code Guide

## What this repo is

**7h3 Protocol** is a cryptographic signing, replay protection, and encryption layer for AI agent messages. Wire version `7h3/0.1` (immutable — never change it).

Key properties:
- Ed25519 asymmetric signing or HMAC-SHA256 shared-secret
- Canonical JSON (alphabetical keys) — byte-identical across all SDKs
- Replay protection via nonce + TTL
- X25519 + ChaCha20-Poly1305 end-to-end encryption
- ML-DSA (NIST FIPS 204) post-quantum signatures
- BLS12-381 M-of-N threshold signatures
- Cloudflare Workers native (Web Crypto only, zero deps)
- 542 tests across TypeScript, Python, Rust, Go, Browser
- WebMCP: capability-scoped, receipted `document.modelContext` tools (`sdk/webmcp/`)

## MCP Tools (install once, use in every session)

Install the MCP server so you have live tools:

```bash
claude mcp add 7h3-protocol -- npx -y @7h3/protocol-mcp
```

Or add to `.claude/settings.json` in any project:

```json
{
  "mcpServers": {
    "7h3-protocol": {
      "command": "npx",
      "args": ["-y", "@7h3/protocol-mcp"]
    }
  }
}
```

### Available tools

| Tool | What it does |
|---|---|
| `7h3_generate_keypair` | Generate Ed25519 keypair (PKCS8/SPKI, base64url) |
| `7h3_generate_secret` | Generate 32-byte HMAC secret |
| `7h3_sign` | Sign a test envelope for debugging/fixtures |
| `7h3_verify` | Verify an envelope signature + TTL + shape |
| `7h3_scaffold` | Generate integration code for a framework (see below) |
| `7h3_mcp_config` | Get install config for Claude Code, Cursor, Opencode, Grok |
| `7h3_wrap_mcp_server` | Generate boilerplate to wrap an MCP handler with 7h3 |

### Scaffold any framework

```
7h3_scaffold framework="webmcp" sender="shop.example"
7h3_scaffold framework="cloudflare-worker" sender="agent@example.com" signingMethod="ed25519"
7h3_scaffold framework="nextjs" sender="agent@example.com"
7h3_scaffold framework="express" sender="agent@example.com"
7h3_scaffold framework="hono" sender="agent@example.com"
7h3_scaffold framework="fastify" sender="agent@example.com"
7h3_scaffold framework="claude-code"
```

## Critical constraint

**`7h3/0.1` is the wire version — never change it.** It is immutable. Changing it breaks all peer agents.

## Key files

```
src/protocol.ts         — core types, signing, verification, canonicalization
src/gateway.ts          — HTTP reverse-proxy gateway
src/httpBinding.ts      — verifyHttpEnvelope() for any HTTP framework
src/encryption.ts       — X25519 + ChaCha20-Poly1305 E2E encryption
src/capability.ts       — scoped capability token delegation chains
src/stream.ts           — per-chunk HMAC + Ed25519 stream signing
src/replayStores.ts     — ReplayStore interface + Redis + in-memory
src/telemetry.ts        — Prometheus metrics + OpenTelemetry
cloudflare/src/         — Cloudflare Workers gateway + middleware
cloudflare/DEPLOY.md    — Cloudflare deployment guide
sdk/webmcp/             — @7h3/protocol-webmcp (signed WebMCP tools)
sdk/pq/                 — @7h3/protocol-pq (ML-DSA post-quantum)
sdk/threshold/          — @7h3/protocol-threshold (BLS M-of-N)
mcp-server/src/         — @7h3/protocol-mcp MCP server
bin/7h3.ts              — CLI: keygen, sign, verify, gateway, keys serve
```

## Quick-start: add 7h3 to a project

```typescript
import { createEnvelope, signEnvelopeEd25519, verifyEnvelopeEd25519,
         generateEd25519KeypairBase64Url } from '@7h3/protocol'

const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()

// Sign
const envelope = createEnvelope({ sender: 'agent@example.com', intent: 'TASK', content: 'hello' })
const signed = await signEnvelopeEd25519(envelope, privateKey, 'k1')

// Verify
const ok = await verifyEnvelopeEd25519(signed, publicKey)
```

## Running tests

```bash
npm test                    # all 542 tests
npm run conformance:python  # cross-SDK conformance
npm run conformance:rust    # Rust SDK
```
