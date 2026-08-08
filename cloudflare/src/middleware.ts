import { createGateway, type GatewayConfig } from '@7h3/protocol/gateway'
import type { KeyRegistry } from '@7h3/protocol/key-registry'
import type { ReplayStore } from '@7h3/protocol/replay'
import { KvReplayStore } from './kv-replay-store'
import { KvRateLimitStore } from './kv-rate-limit-store'
import { KvKeyRegistry } from './kv-key-registry'

export interface MiddlewareEnv {
  KEY_REGISTRY: KVNamespace
  REPLAY_STORE: KVNamespace
  GATEWAY_PRIVATE_KEY?: string
  GATEWAY_SENDER?: string
  DEFAULT_POLICY?: 'allow' | 'deny'
}

export interface VerifyResult {
  ok: true
  sender: string
}

export interface DenyResult {
  ok: false
  response: Response
}

/**
 * create7h3Middleware
 *
 * Returns a verify() function suitable for use inside any Cloudflare Worker.
 * Call it at the top of your fetch() handler — if it returns ok:false, return
 * result.response immediately. If ok:true, proceed with your handler.
 *
 * Usage:
 *
 *   import { create7h3Middleware } from './middleware'
 *
 *   export default {
 *     async fetch(request, env, ctx) {
 *       const mw = create7h3Middleware(env)
 *       const check = await mw.verify(request)
 *       if (!check.ok) return check.response
 *       // your handler
 *       return new Response('ok')
 *     }
 *   }
 *
 * Because this is called fresh on every request, rate limiting is backed by
 * KvRateLimitStore (persisted in REPLAY_STORE) rather than the gateway's
 * default in-memory limiter — an in-memory limiter reset every request would
 * never actually enforce a limit.
 */
export function create7h3Middleware(env: MiddlewareEnv, extra?: Partial<GatewayConfig>) {
  const keyRegistry: KeyRegistry = new KvKeyRegistry(env.KEY_REGISTRY)
  const replayStore: ReplayStore = new KvReplayStore(env.REPLAY_STORE)
  const rateLimitStore = new KvRateLimitStore(env.REPLAY_STORE)

  const gatewayConfig: GatewayConfig = {
    upstream: '',
    keyRegistry,
    replayStore,
    rateLimitStore,
    // `env.DEFAULT_POLICY` is a raw Worker env var string at runtime — the
    // `MiddlewareEnv` type annotation doesn't validate it. Fail closed: only
    // the exact string 'allow' opts into the permissive default; anything
    // else (a typo, wrong casing, empty string) falls through to 'deny'
    // rather than passing an unrecognized value straight to the gateway.
    defaultPolicy: env.DEFAULT_POLICY === 'allow' ? 'allow' : 'deny',
    privateKey: env.GATEWAY_PRIVATE_KEY,
    sender: env.GATEWAY_SENDER,
    signResponses: !!env.GATEWAY_PRIVATE_KEY,
    ...extra,
  }

  const gateway = createGateway(gatewayConfig)

  return {
    async verify(request: Request): Promise<VerifyResult | DenyResult> {
      const url = new URL(request.url)
      const headers: Record<string, string> = {}
      request.headers.forEach((v, k) => { headers[k] = v })

      const result = await gateway.verify({
        method: request.method,
        path: url.pathname,
        headers,
        url: request.url,
      })

      if (result.ok) {
        return { ok: true, sender: result.sender }
      }

      return {
        ok: false,
        response: new Response(
          JSON.stringify({ error: result.reason }),
          {
            status: result.status,
            headers: {
              'content-type': 'application/json',
              'x-7h3-reject-reason': result.reason,
            },
          },
        ),
      }
    },
  }
}
