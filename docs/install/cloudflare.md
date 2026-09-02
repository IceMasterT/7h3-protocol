# Install: Cloudflare Workers

7h3 is Workers-native — Web Crypto only, zero dependencies, no Node built-ins
and no polyfills.

Two ways to use it: a **standalone reverse-proxy gateway**, or **drop-in
middleware** inside an existing Worker.

## Install

```bash
npm install @7h3/protocol
```

## A. Drop-in middleware

```ts
import { create7h3Middleware } from './middleware'

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const verified = await create7h3Middleware(env)(request)
    if (!verified.ok) return new Response(verified.reason, { status: verified.status })
    return handleRequest(request, env, ctx)
  },
}
```

`DEFAULT_POLICY` **fails closed** on any value other than exactly `'allow'`.

## B. Standalone gateway

```ts
import { createGateway } from '@7h3/protocol/gateway'
import { KvKeyRegistry, KvReplayStore } from './kv'

export default {
  async fetch(request: Request, env: Env) {
    const gateway = createGateway({
      upstream: env.UPSTREAM_URL,
      keyRegistry: new KvKeyRegistry(env.KEY_REGISTRY),
      replayStore: new KvReplayStore(env.REPLAY_STORE),
      defaultPolicy: 'deny',
    })

    const result = await gateway.verify({
      method: request.method,
      path: new URL(request.url).pathname,
      headers: Object.fromEntries(request.headers),
    })
    if (!result.ok) return new Response(result.reason, { status: result.status })

    return fetch(env.UPSTREAM_URL + new URL(request.url).pathname)
  },
}
```

Prefer `createProductionGateway()` — it **throws** unless `defaultPolicy` is
explicitly `'deny'` and a `replayStore` is set, rather than silently letting
unmatched routes through unverified.

## Storage bindings

| Binding | Class | Use |
|---|---|---|
| KV | `KvKeyRegistry` | Public key lookup by sender |
| KV | `KvReplayStore` | Nonce replay protection |
| KV | `KvRateLimitStore` | Rate-limit counters |
| Durable Object | `DurableReplayStore` | Atomic replay protection, no KV race window |

KV is eventually consistent, so it has a small replay race window. For
money-moving or otherwise irreversible routes, use the Durable Object store.

## Scaffold it

```bash
npx 7h3 add --framework cloudflare-worker --sender agent@example.com
```

## wrangler.toml

Wrangler does **not** inherit KV bindings into named environments — declare
them for `staging` and `production` explicitly, or those deployments start with
no key registry and no replay store.

## Deploy

```bash
npx wrangler deploy
```

Full walkthrough, including one-command setup and key loading:
[`cloudflare/DEPLOY.md`](../../cloudflare/DEPLOY.md).
