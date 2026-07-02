# 7h3 Protocol — Cloudflare Workers Deployment

## What this deploys

A Cloudflare Worker that acts as a cryptographic gateway in front of any upstream service. Every inbound request must carry a valid `x-7h3-envelope` header with an Ed25519-signed 7h3 Protocol envelope. Unsigned requests are rejected with HTTP 401/403.

```
Caller ──[x-7h3-envelope]──▶ 7h3 Gateway Worker ──[clean request]──▶ Upstream
         Ed25519 signed         verify + strip                          your service
```

## Prerequisites

- Cloudflare account with Workers enabled
- `wrangler` CLI logged in: `npx wrangler login`
- Node.js 18+

---

## First-time setup (one command)

```bash
cd cloudflare
npm install
npm run setup
```

This generates an Ed25519 keypair, creates two KV namespaces, patches `wrangler.toml`, and stores the private key as a Wrangler secret. Takes about 30 seconds.

---

## Manual setup

### 1. Generate a gateway keypair

```bash
cd ..
npx tsx bin/7h3.ts keygen
# prints: publicKey, privateKey (keep private key secret)
```

### 2. Create KV namespaces

```bash
wrangler kv:namespace create KEY_REGISTRY
wrangler kv:namespace create REPLAY_STORE
wrangler kv:namespace create KEY_REGISTRY --preview
wrangler kv:namespace create REPLAY_STORE --preview
```

Copy the IDs into `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "KEY_REGISTRY"
id = "<your-key-registry-id>"
preview_id = "<your-key-registry-preview-id>"

[[kv_namespaces]]
binding = "REPLAY_STORE"
id = "<your-replay-store-id>"
preview_id = "<your-replay-store-preview-id>"
```

### 3. Set the upstream URL

In `wrangler.toml`:

```toml
[vars]
UPSTREAM_URL = "https://your-service.workers.dev"
GATEWAY_SENDER = "gateway@your-domain.com"
DEFAULT_POLICY = "deny"
```

### 4. Store the private key as a secret

```bash
wrangler secret put GATEWAY_PRIVATE_KEY
# paste the base64url private key when prompted
```

### 5. Register trusted agent public keys

```bash
wrangler kv:key put --namespace-id <KEY_REGISTRY_ID> \
  "7h3:pk:my-agent@example.com" "<base64url-ed25519-spki-pubkey>"
```

---

## Deploy

```bash
npm run deploy:staging     # test first
npm run deploy:production  # go live
```

---

## Using as middleware in an existing Worker

If you already have a Cloudflare Worker and want to add 7h3 verification without a separate proxy:

```typescript
import { create7h3Middleware } from './cloudflare/src/middleware'

interface Env {
  KEY_REGISTRY: KVNamespace
  REPLAY_STORE: KVNamespace
  GATEWAY_PRIVATE_KEY?: string
  GATEWAY_SENDER?: string
  DEFAULT_POLICY?: string
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const mw = create7h3Middleware(env)
    const check = await mw.verify(request)
    if (!check.ok) return check.response  // 401/403

    // verified — check.sender has the agent's identity
    return new Response(`Hello, ${check.sender}!`)
  }
}
```

---

## Key discovery endpoint

The gateway automatically exposes `GET /.well-known/7h3-keys` — returns all registered public keys as JSON. Callers can use this to verify they're talking to the right gateway.

```bash
curl https://your-gateway.workers.dev/.well-known/7h3-keys
# {"keys":{"gateway@your-domain.com":"<pubkey>"},"version":"7h3/0.1"}
```

---

## Replay protection

Nonces are stored in Cloudflare KV with TTL expiry equal to the envelope's `ttlMs`. This prevents replay attacks across all Worker instances globally.

**Race window:** KV has strong consistency within a datacenter but ~60ms eventual consistency globally. For zero-race-window protection, uncomment the Durable Object binding in `wrangler.toml` and switch to `DurableReplayStore` in `worker.ts`. Requires Paid Workers plan.

---

## Sending signed requests (callers)

```typescript
import { createEnvelope, signEnvelopeEd25519, generateEd25519KeypairBase64Url } from '@7h3/protocol'

const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()

const envelope = createEnvelope({
  sender: 'my-agent@example.com',
  recipient: 'gateway@your-domain.com',
  intent: 'TASK',
  content: JSON.stringify({ query: 'hello' }),
})

const signed = await signEnvelopeEd25519(envelope, privateKey)

await fetch('https://your-gateway.workers.dev/api/chat', {
  method: 'POST',
  headers: {
    'x-7h3-envelope': JSON.stringify(signed),
    'content-type': 'application/json',
  },
  body: JSON.stringify({ query: 'hello' }),
})
```
