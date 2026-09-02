# 7h3 Protocol — AI Agent Guide

> For GPT Codex, Opencode, Grok Builder, and other AI coding agents

## What this repo is

**7h3 Protocol** is a cryptographic signing and replay-protection layer for AI agent messages. It has TypeScript, Python, Rust, and Go SDKs, a Cloudflare Workers gateway, and 478 tests.

Wire version: `7h3/0.1` — **never change this string** (breaking for all peers).

---

## When asked to "add 7h3 to this project"

### 1. Install the package

```bash
npm install @7h3/protocol        # TypeScript / JavaScript
pip install 7h3-protocol         # Python
# Cargo.toml: protocol-7h3 = "0.5"
# go.mod: github.com/IceMasterT/7h3-protocol/sdk/go v0.5.0
```

### 2. Generate a keypair (one-time)

```bash
npx 7h3 keygen --output keys.json
# Store privateKey as env var P7H3_PRIVATE_KEY — never commit it
# Share publicKey with peers
```

### 3. Sign outgoing messages

```typescript
import { createEnvelope, signEnvelopeEd25519 } from '@7h3/protocol'

const envelope = createEnvelope({
  sender: 'my-agent@example.com',
  recipient: 'target@example.com',
  intent: 'TASK',
  content: JSON.stringify({ task: 'process order #42' }),
  ttlMs: 60_000,
})
const signed = await signEnvelopeEd25519(envelope, process.env.P7H3_PRIVATE_KEY!, 'k1')

// Send:
fetch('/api/endpoint', {
  headers: { 'x-7h3-envelope': JSON.stringify(signed) },
})
```

### 4. Verify incoming messages

```typescript
import { verifyHttpEnvelope } from '@7h3/protocol/http'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'

const keyRegistry = createStaticKeyRegistry({
  'peer-agent@example.com': process.env.PEER_PUBLIC_KEY!,
})

// In any HTTP handler:
const result = await verifyHttpEnvelope(headers, { keyRegistry })
if (!result.ok) return new Response('Unauthorized', { status: 401 })
```

---

## Framework integration snippets

### Cloudflare Worker

```typescript
import { createGateway } from '@7h3/protocol/gateway'
import { KvKeyRegistry, KvReplayStore } from './cloudflare/src'

export default {
  async fetch(request: Request, env: Env) {
    const gateway = createGateway({
      upstream: env.UPSTREAM_URL,
      keyRegistry: new KvKeyRegistry(env.KEY_REGISTRY),
      replayStore: new KvReplayStore(env.REPLAY_STORE),
      defaultPolicy: 'deny',
    })
    const req = { method: request.method, path: new URL(request.url).pathname,
                  headers: Object.fromEntries(request.headers) }
    const result = await gateway.verify(req)
    if (!result.ok) return new Response(result.reason, { status: result.status })
    return fetch(env.UPSTREAM_URL + new URL(request.url).pathname)
  }
}
```

### Next.js middleware (`middleware.ts`)

```typescript
import { NextRequest, NextResponse } from 'next/server'
import { verifyHttpEnvelope } from '@7h3/protocol/http'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'

const registry = createStaticKeyRegistry({ 'agent@example.com': process.env.AGENT_PUBLIC_KEY! })

export async function middleware(req: NextRequest) {
  const headers = Object.fromEntries(req.headers)
  const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
  if (!result.ok) return NextResponse.json({ error: result.reason }, { status: 401 })
  return NextResponse.next()
}
export const config = { matcher: '/api/:path*' }
```

### Express

```typescript
import { verifyHttpEnvelope } from '@7h3/protocol/http'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'
const registry = createStaticKeyRegistry({ 'agent@example.com': process.env.AGENT_PUBLIC_KEY! })

app.use(async (req, res, next) => {
  const result = await verifyHttpEnvelope(req.headers as Record<string, string>, { keyRegistry: registry })
  if (!result.ok) return res.status(401).json({ error: result.reason })
  next()
})
```

### Hono

```typescript
import { createMiddleware } from 'hono/factory'
import { verifyHttpEnvelope } from '@7h3/protocol/http'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'
const registry = createStaticKeyRegistry({ 'agent@example.com': process.env.AGENT_PUBLIC_KEY! })

export const auth7h3 = createMiddleware(async (c, next) => {
  const headers = Object.fromEntries(c.req.raw.headers)
  const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
  if (!result.ok) return c.json({ error: result.reason }, 401)
  await next()
})
```

### Fastify

```typescript
import { verifyHttpEnvelope } from '@7h3/protocol/http'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'
const registry = createStaticKeyRegistry({ 'agent@example.com': process.env.AGENT_PUBLIC_KEY! })

fastify.addHook('preHandler', async (request, reply) => {
  const result = await verifyHttpEnvelope(request.headers as Record<string, string>, { keyRegistry: registry })
  if (!result.ok) return reply.code(401).send({ error: result.reason })
})
```

---

## Advanced features

### E2E encryption (X25519 + ChaCha20-Poly1305)

```typescript
import { generateX25519KeyPair, sealEnvelope, openEnvelope } from '@7h3/protocol/encryption'

const recipientKeys = await generateX25519KeyPair()
const sealed = await sealEnvelope(envelope, recipientKeys.publicKey)
const decrypted = await openEnvelope(sealed, recipientKeys.privateKey)
```

### Capability token delegation

```typescript
import { issueCapabilityToken, delegateCapabilityToken, verifyCapabilityChain } from '@7h3/protocol/capability'

const token = await issueCapabilityToken({ subject: 'agent-b', scope: '/api/payments/**',
  issuerPrivateKey, issuerId: 'root-agent', maxDelegations: 2, ttlMs: 300_000 })
const delegated = await delegateCapabilityToken(token, { subject: 'agent-c',
  scope: '/api/payments/process', delegatorPrivateKey, delegatorId: 'agent-b' })
```

### Post-quantum (ML-DSA)

```typescript
import { generatePqKeyPair, signEnvelopePq, verifyEnvelopePq } from '@7h3/protocol-pq'

const keys = await generatePqKeyPair('ML-DSA-65')
const signed = await signEnvelopePq(envelope, keys.privateKey, 'ML-DSA-65')
```

### Stream signing (LLM output)

```typescript
import { SignedStreamWriter, SignedStreamReader } from '@7h3/protocol/stream'

const writer = new SignedStreamWriter({ privateKey, sender: 'llm@example.com' })
for (const token of tokens) { const chunk = await writer.writeChunk(token); send(chunk) }
const finalChunk = await writer.finalize(); send(finalChunk)
```

---

## Cloudflare Workers deployment

```bash
cd cloudflare
npm install
npm run setup        # generates keypair, creates KV namespaces, sets secret
# Edit wrangler.toml: set UPSTREAM_URL
npm run deploy:staging
npm run deploy:production
```

---

## Key invariants (never violate)

1. **`version` field is always `"7h3/0.1"`** — immutable wire version
2. **Canonical JSON** — keys alphabetically sorted, no absent optional fields
3. **Nonces are unique per message** — replay store rejects duplicates
4. **TTL must be > 0** — expired messages are rejected
5. **privateKey is PKCS8 base64url, publicKey is SPKI base64url** — not raw bytes

---

## CLI reference

```bash
npx 7h3 keygen                       # generate Ed25519 keypair
npx 7h3 sign --private-key <k> --sender <id> --payload '{"x":1}'
npx 7h3 verify --public-key <k> --envelope '<json>'
npx 7h3 gateway --upstream http://localhost:3001 --port 8080 --require ed25519
npx 7h3 keys serve --public-key <k> --port 9000
```
