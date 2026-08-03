# 7h3 Protocol — Gateway Quick-Start

The 7h3 gateway is a verifying HTTP reverse proxy.  It sits in front of your
service, intercepts every request, checks that the 7h3 envelope header carries
a valid Ed25519 (or HMAC) signature from a known sender, enforces per-route
policies and rate limits, optionally signs upstream responses, then forwards
clean HTTP to your application.

---

## 1. Install

```bash
npm install @7h3/protocol
```

The published package ships a compiled CLI (`bin/7h3.js`), so `npx 7h3` works
with no extra setup. Running the CLI from a source checkout (`bin/7h3.ts`)
instead requires `tsx`, which is listed as a dev dependency:

```bash
npm install -g tsx          # only needed to run bin/7h3.ts from source
```

The Docker image (see §4) runs the compiled `bin/7h3.js` directly and does not
need `tsx` at all.

---

## 1.5. Production Safety

Two footguns to know before you deploy:

- **`defaultPolicy` defaults to `'allow'`.** If you don't set it, requests to
  any route that doesn't match one of your `policies` are forwarded upstream
  **without signature verification**. Production configs must set
  `defaultPolicy: 'deny'` explicitly.
- **Replay protection requires a shared `replayStore`.** Without one, the
  gateway still verifies signatures and TTL, but nonce reuse is only deduped
  in an in-memory cache scoped to a single instance — it does not survive a
  restart, and it does nothing at all across multiple instances (e.g. a
  Workers isolate that rebuilds the gateway on every request, or more than
  one replica behind a load balancer).

Use `createProductionGateway()` instead of `createGateway()` to turn both of
these into deploy-time errors instead of silent runtime gaps:

```ts
import { createProductionGateway } from '@7h3/protocol/gateway'

const gateway = createProductionGateway({
  upstream: 'http://internal-api:3000',
  keyRegistry: registry,
  defaultPolicy: 'deny',   // throws if omitted or set to 'allow'
  replayStore,             // throws if omitted — use Redis/KV/Durable Object
})
```

See `cloudflare/DEPLOY.md` for the KV replay-store race-window caveat and the
Durable Object option for atomic replay checks.

---

## 2. In-Process Middleware

Drop the gateway into an existing Express (or any Node.js `http`) server in
three lines:

```ts
import express from 'express'
import { createGateway } from '@7h3/protocol/gateway'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'
import { RedisReplayStore } from '@7h3/protocol/replay'

const app = express()

const registry = createStaticKeyRegistry({
  'agent@example.com': process.env.AGENT_PUBLIC_KEY!,
})

const gateway = createGateway({
  upstream: 'http://internal-api:3000',
  keyRegistry: registry,
  defaultPolicy: 'deny',
  replayStore: new RedisReplayStore(redisClient), // required in production — see section 1.5
})

// Verify every request before it reaches your routes
app.use(async (req, res, next) => {
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(req.headers)) {
    if (typeof v === 'string') headers[k] = v
    else if (Array.isArray(v)) headers[k] = v[0]
  }
  const outcome = await gateway.verify({ method: req.method, path: req.path, headers })
  if (!outcome.ok) return res.status(outcome.status).json({ error: outcome.reason })
  res.locals.sender = outcome.sender
  next()
})
```

---

## 3. Gateway Mode (CLI / Standalone Proxy)

### 3a. Generate a keypair

```bash
7h3 keygen --output keys.json
```

This writes a JSON file with `publicKey` and `privateKey` (both base64url-encoded
Ed25519 SPKI/PKCS8).  Store `privateKey` in a secret; share `publicKey` with
the agents that will call your service.

### 3b. Start the gateway

```bash
7h3 gateway \
  --upstream http://localhost:3000 \
  --public-key <base64url-SPKI> \
  --port 8080 \
  --require ed25519
```

Full options:

| Flag | Default | Description |
|---|---|---|
| `--upstream <url>` | _(required)_ | Upstream service URL |
| `--port <n>` | `8080` | Port to listen on |
| `--require ed25519\|none` | `ed25519` if `--public-key` is set, else `none` | Signature mode |
| `--public-key <key>` | — | Ed25519 SPKI public key (base64url) |
| `--sign-responses` | `false` | Sign every proxied response |
| `--private-key <key>` | — | Private key for response signing |
| `--sender <id>` | — | Sender ID attached to signed responses |

---

## 4. Docker

```bash
# Bring up the gateway + example upstream
docker compose up --build

# Test with a health probe (no signature required)
curl http://localhost:8080/health

# Generate keys, then call a signed route
7h3 keygen --output keys.json
PRIV=$(jq -r .privateKey keys.json)
PUB=$(jq -r .publicKey keys.json)

ENVELOPE=$(7h3 sign --private-key "$PRIV" --sender agent@example.com --payload '{"q":"hello"}')
curl -H "x-7h3-envelope: $ENVELOPE" http://localhost:8080/api/hello
```

To enable response signing, pass environment variables to the gateway service
in `docker-compose.yaml`:

```yaml
environment:
  GATEWAY_PRIVATE_KEY: <your-private-key>
  GATEWAY_SENDER: gateway@my-service.example.com
```

---

## 5. Config Reference (YAML)

See `7h3.example.yaml` for a fully-annotated configuration file.

| Field | Type | Default | Description |
|---|---|---|---|
| `upstream` | string | _(required)_ | Upstream base URL |
| `port` | number | `8080` | Listening port |
| `sender` | string | — | Gateway sender identity for signed responses |
| `sign_responses` | boolean | `false` | Sign every proxied response |
| `default_policy` | `allow` \| `deny` | `allow` | Behaviour when no route policy matches — **set to `deny` in production**, see §1.5 |
| `keys.private_key` | string | — | Gateway Ed25519 private key (base64url PKCS8) |
| `keys.registry` | map | `{}` | `senderID → publicKey` (base64url SPKI) |
| `policies[].path` | glob string | _(required)_ | Route glob (`**` crosses slashes) |
| `policies[].require` | `ed25519` \| `hmac` \| `any` \| `none` | _(required)_ | Signature algorithm |
| `policies[].allowed_senders` | string[] | _(all)_ | Allowlist of sender IDs |
| `policies[].rate_limit.requests` | number | — | Max requests in window |
| `policies[].rate_limit.window_ms` | number | — | Sliding window in ms |
| `policies[].sign_response` | boolean | — | Per-route response signing override |

---

## 6. Client-Side Signing

Agents calling a 7h3-protected gateway must attach a signed 7h3 envelope to
every request.  Use the TypeScript SDK:

```ts
import { createEnvelope, signEnvelopeEd25519 } from '@7h3/protocol'
import { attachEnvelopeToHeaders } from '@7h3/protocol/http'

async function signedFetch(url: string, body: string, privateKey: string) {
  const envelope = createEnvelope({
    sender: 'agent@example.com',
    recipient: 'gateway@my-service.example.com',
    intent: 'REQUEST',
    content: body,
    ttlMs: 60_000,
  })

  const signed = await signEnvelopeEd25519(envelope, privateKey)
  const headers = attachEnvelopeToHeaders(signed, {})   // adds x-7h3-envelope

  return fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body,
  })
}
```

The gateway validates the envelope header, verifies the Ed25519 signature
against the sender's registered public key, checks replay protection, and only
then forwards the request to the upstream service.

---

## 7. Policy Examples

| Use Case | `path` | `require` | `allowed_senders` | `rate_limit` |
|---|---|---|---|---|
| Public health probe | `/health` | `none` | — | — |
| Open public API | `/public/**` | `none` | — | — |
| Any authenticated agent | `/api/**` | `ed25519` | — | 1 000 req / 60 s |
| Named admin agents only | `/api/admin/**` | `ed25519` | `admin-agent@…`, `orchestrator@…` | — |
| Partner integration | `/api/partner/**` | `ed25519` | `partner-bot@partner.example.com` | 200 req / 60 s |
| Webhook receiver | `/webhooks/**` | `hmac` | — | 500 req / 60 s |
