import type { RateLimitPolicy, RateLimitResult, RateLimitStore } from '@7h3/protocol/rate-limiter'

/**
 * Durable Object that provides fully atomic sliding-window rate limiting.
 *
 * Each sender's window is stored in Durable Object storage, which is
 * strongly consistent and serialized — no race window, unlike KvRateLimitStore.
 * Requires Durable Objects to be enabled on your Workers plan.
 *
 * Wrangler config (add to wrangler.toml):
 *
 *   [[durable_objects.bindings]]
 *   name = "RATE_LIMIT_DO"
 *   class_name = "RateLimitDurableObject"
 *
 *   [[migrations]]
 *   tag = "v1"
 *   new_classes = ["RateLimitDurableObject"]
 *
 * Usage in worker.ts:
 *   import { DurableRateLimitStore } from './durable-rate-limit'
 *   const rateLimitStore = new DurableRateLimitStore(env.RATE_LIMIT_DO)
 */
export class RateLimitDurableObject {
  private state: DurableObjectState

  constructor(state: DurableObjectState) {
    this.state = state
  }

  async fetch(request: Request): Promise<Response> {
    const { key, policy, nowMs } = await request.json<{ key: string; policy: RateLimitPolicy; nowMs: number }>()
    const cutoff = nowMs - policy.windowMs
    const timestamps = ((await this.state.storage.get<number[]>(key)) ?? []).filter((t) => t > cutoff)
    const used = timestamps.length
    const allowed = used < policy.requests

    if (allowed) {
      timestamps.push(nowMs)
      await this.state.storage.put(key, timestamps)
      this.state.storage.setAlarm(nowMs + policy.windowMs)
    }

    const remaining = Math.max(0, policy.requests - timestamps.length)
    const resetMs = timestamps.length > 0 ? Math.max(0, timestamps[0] + policy.windowMs - nowMs) : 0
    return Response.json({ allowed, remaining, resetMs } satisfies RateLimitResult)
  }

  async alarm(): Promise<void> {
    // Clean up windows that have fully expired — Cloudflare fires alarm at set time.
    const all = await this.state.storage.list<number[]>()
    const now = Date.now()
    const expired: string[] = []
    for (const [k, timestamps] of all) {
      if (timestamps.every((t) => now - t > 300_000)) expired.push(k) // 5-min max window assumed stale
    }
    if (expired.length > 0) await this.state.storage.delete(expired)
  }
}

export class DurableRateLimitStore implements RateLimitStore {
  constructor(private readonly doNamespace: DurableObjectNamespace) {}

  async consume(key: string, policy: RateLimitPolicy, nowMs = Date.now()): Promise<RateLimitResult> {
    // Shard by key so rate-limit traffic for different senders isn't
    // serialized through a single Durable Object instance.
    const id = this.doNamespace.idFromName(`ratelimit:${key}`)
    const stub = this.doNamespace.get(id)
    const resp = await stub.fetch('https://internal/consume', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key, policy, nowMs }),
    })
    return await resp.json<RateLimitResult>()
  }
}
