/**
 * 7h3 Protocol — Cloudflare Gateway Worker
 *
 * Acts as a cryptographic reverse proxy in front of any upstream service.
 * All incoming requests must carry a valid 7h3 envelope (x-7h3-envelope header)
 * unless the route matches a policy with require: 'none'.
 *
 * Environment bindings (wrangler.toml):
 *   KEY_REGISTRY      KVNamespace  — Ed25519 public keys by sender ID
 *   REPLAY_STORE      KVNamespace  — nonce dedup / replay protection
 *   UPSTREAM_URL      string       — where to forward verified requests
 *   GATEWAY_SENDER    string       — this gateway's identity (for signing responses)
 *   GATEWAY_PRIVATE_KEY string     — secret: Ed25519 PKCS8 base64url
 *   DEFAULT_POLICY    string       — 'allow' | 'deny'  (default: 'deny')
 *   METRICS_PUBLIC    string       — 'true' to expose /metrics without an envelope (default: gated)
 */

import { createGateway, type RoutePolicy } from '@7h3/protocol/gateway'
import { KvKeyRegistry } from './kv-key-registry'
import { KvReplayStore } from './kv-replay-store'
import { ReplayDurableObject } from './durable-replay'

export { ReplayDurableObject }

export interface Env {
  KEY_REGISTRY: KVNamespace
  REPLAY_STORE: KVNamespace
  UPSTREAM_URL: string
  GATEWAY_SENDER?: string
  GATEWAY_PRIVATE_KEY?: string
  DEFAULT_POLICY?: string
  // 'true' opens /metrics without a 7h3 envelope. Off by default — traffic
  // metadata is worth protecting, so scrapers should present an envelope
  // unless the operator explicitly opts out.
  METRICS_PUBLIC?: string
  // Optional: Durable Object for atomic replay (upgrade from KV)
  REPLAY_DO?: DurableObjectNamespace
}

// Routes that bypass 7h3 verification (health + key discovery)
const OPEN_ROUTES: RoutePolicy[] = [
  { path: '/health',               require: 'none' },
  { path: '/healthz',              require: 'none' },
  { path: '/.well-known/7h3-keys', require: 'none' },
]

function buildGateway(env: Env) {
  const keyRegistry = new KvKeyRegistry(env.KEY_REGISTRY)
  const replayStore = new KvReplayStore(env.REPLAY_STORE)
  const defaultPolicy = (env.DEFAULT_POLICY === 'allow' ? 'allow' : 'deny') as 'allow' | 'deny'
  const policies: RoutePolicy[] = env.METRICS_PUBLIC === 'true'
    ? [...OPEN_ROUTES, { path: '/metrics', require: 'none' }]
    : OPEN_ROUTES

  return createGateway({
    upstream: env.UPSTREAM_URL,
    keyRegistry,
    replayStore,
    defaultPolicy,
    policies,
    privateKey: env.GATEWAY_PRIVATE_KEY,
    sender: env.GATEWAY_SENDER,
    signResponses: !!env.GATEWAY_PRIVATE_KEY,
  })
}

// Expose /.well-known/7h3-keys for key discovery
async function handleKeyDiscovery(env: Env): Promise<Response> {
  const keys: Record<string, string> = {}
  if (env.GATEWAY_SENDER && env.GATEWAY_PRIVATE_KEY) {
    const list = await env.KEY_REGISTRY.list({ prefix: '7h3:pk:' })
    for (const item of list.keys) {
      const senderId = item.name.replace('7h3:pk:', '')
      const pubKey = await env.KEY_REGISTRY.get(item.name)
      if (pubKey) keys[senderId] = pubKey
    }
  }
  return Response.json({ keys, version: '7h3/0.1' })
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)

    // Key discovery — list all registered public keys
    if (url.pathname === '/.well-known/7h3-keys' && request.method === 'GET') {
      return handleKeyDiscovery(env)
    }

    const gateway = buildGateway(env)

    // Extract headers for gateway.verify()
    const headers: Record<string, string> = {}
    request.headers.forEach((v, k) => { headers[k] = v })

    const verifyResult = await gateway.verify({
      method: request.method,
      path: url.pathname,
      headers,
      url: request.url,
    })

    if (!verifyResult.ok) {
      return new Response(
        JSON.stringify({ error: verifyResult.reason, version: '7h3/0.1' }),
        {
          status: verifyResult.status,
          headers: {
            'content-type': 'application/json',
            'x-7h3-reject-reason': verifyResult.reason,
          },
        },
      )
    }

    // Forward the clean request to upstream (strip the 7h3 envelope header)
    const upstreamUrl = `${env.UPSTREAM_URL}${url.pathname}${url.search}`
    const upstreamHeaders = new Headers(request.headers)
    upstreamHeaders.delete('x-7h3-envelope')
    upstreamHeaders.set('x-7h3-sender', verifyResult.sender)
    upstreamHeaders.set('x-forwarded-host', url.host)

    const upstreamReq = new Request(upstreamUrl, {
      method: request.method,
      headers: upstreamHeaders,
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
    })

    const upstreamResp = await fetch(upstreamReq)

    // Sign the response if gateway has a private key
    if (env.GATEWAY_PRIVATE_KEY && env.GATEWAY_SENDER) {
      const respHeaders = new Headers(upstreamResp.headers)
      // Gateway signs responses so callers can verify the proxy wasn't tampered with
      respHeaders.set('x-7h3-gateway', env.GATEWAY_SENDER)
      respHeaders.set('x-7h3-verified-sender', verifyResult.sender)
      return new Response(upstreamResp.body, {
        status: upstreamResp.status,
        statusText: upstreamResp.statusText,
        headers: respHeaders,
      })
    }

    return upstreamResp
  },
}
