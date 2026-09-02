# Install: TypeScript / Node.js

```bash
npm install @7h3/protocol
```

Zero runtime dependencies. Pure Web Crypto, so the same build runs in Node,
Cloudflare Workers, Deno, Bun and the browser.

**Requires** Node.js ≥ 20 (CI runs on 22).

## Generate keys

```bash
npx 7h3 keygen --output keys.json
```

Store the private key as `P7H3_PRIVATE_KEY`; never commit it. Share the public
key with peers.

## Sign and verify

```ts
import {
  createEnvelope,
  signEnvelopeEd25519,
  verifyEnvelopeEd25519,
  generateEd25519KeypairBase64Url,
} from '@7h3/protocol'

const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()

const envelope = createEnvelope({
  sender: 'agent@example.com',
  recipient: 'peer@example.com',
  intent: 'TASK',
  content: JSON.stringify({ task: 'process order #42' }),
  ttlMs: 60_000,
})

const signed = await signEnvelopeEd25519(envelope, privateKey, 'k1')
await verifyEnvelopeEd25519(signed, publicKey)   // → true (a plain boolean)
```

HMAC works the same way via `signEnvelopeHmac` / `verifyEnvelopeHmac` when you
have a shared secret rather than a keypair.

## Verify an incoming HTTP request

```ts
import { verifyHttpEnvelope } from '@7h3/protocol/http'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'

const keyRegistry = createStaticKeyRegistry({
  'peer-agent@example.com': process.env.PEER_PUBLIC_KEY!,
})

const result = await verifyHttpEnvelope(headers, { keyRegistry })
if (!result.ok) return new Response(result.reason, { status: 401 })
```

Works in any framework that can hand you a plain headers object — Express,
Hono, Fastify, Next.js middleware, Workers.

```bash
npx 7h3 add --framework nextjs   # or express, hono, fastify, cloudflare-worker
```

## Validation

`validateEnvelope` returns diagnostics rather than throwing:

```ts
const diagnostics = validateEnvelope(envelope)
// → [{ level: 'error', message: 'ttlMs exceeds maximum allowed 86400000 ms' }]
```

It enforces the wire version, presence of messageId / sender / nonce, that
`timestampMs` and `ttlMs` are finite, the 24h TTL ceiling (`MAX_TTL_MS`), a 30s
future-timestamp ceiling (`MAX_CLOCK_SKEW_MS`), and expiry.

## Subpath exports

| Import | Provides |
|---|---|
| `@7h3/protocol` | Core: envelopes, signing, verification, canonicalization |
| `@7h3/protocol/http` | `verifyHttpEnvelope`, `signHttpEnvelope` |
| `@7h3/protocol/gateway` | `createGateway`, `createProductionGateway` |
| `@7h3/protocol/key-registry` | Static and caching key registries |
| `@7h3/protocol/replay` | `ReplayStore`, Redis and in-memory stores |
| `@7h3/protocol/capability` | Capability tokens and delegation chains |
| `@7h3/protocol/encryption` | X25519 + ChaCha20-Poly1305 |
| `@7h3/protocol/stream` | Per-chunk signed streaming |
| `@7h3/protocol/webhook`, `/queue`, `/ws`, `/grpc` | Transport bindings |
| `@7h3/protocol/cbor` | Deterministic CBOR codec |
| `@7h3/protocol/telemetry` | Prometheus + OpenTelemetry |

## Next

- Put a verifying proxy in front of an existing service → **[Cloudflare](./cloudflare.md)** or **[Docker](./docker.md)**
- Give browser agents tools → **[WebMCP](./webmcp.md)**
