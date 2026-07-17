import type { RateLimitPolicy, RateLimitResult, RateLimitStore } from '@7h3/protocol/rate-limiter'

/**
 * Cloudflare KV-backed rate limit store.
 *
 * Persists each sender's sliding-window timestamps in KV so limits are
 * enforced across Workers instances/invocations — the gateway is rebuilt
 * per-request in a Workers fetch handler, so an in-memory limiter would
 * silently reset (and stop limiting) on every single request.
 *
 * Race window: concurrent requests from the same sender may read-modify-write
 * the same KV entry, occasionally letting one extra request through. For
 * zero-race-window accuracy use DurableRateLimitStore (durable-rate-limit.ts).
 */
export class KvRateLimitStore implements RateLimitStore {
  private readonly prefix: string

  constructor(
    private readonly kv: KVNamespace,
    opts?: { prefix?: string },
  ) {
    this.prefix = opts?.prefix ?? '7h3:ratelimit:'
  }

  async consume(key: string, policy: RateLimitPolicy, nowMs = Date.now()): Promise<RateLimitResult> {
    const kvKey = `${this.prefix}${key}`
    const cutoff = nowMs - policy.windowMs
    const raw = await this.kv.get(kvKey)
    const timestamps: number[] = raw ? (JSON.parse(raw) as number[]).filter((t) => t > cutoff) : []
    const used = timestamps.length
    const allowed = used < policy.requests

    if (allowed) {
      timestamps.push(nowMs)
      // Cloudflare KV rejects expirationTtl below 60s.
      const ttlSeconds = Math.max(60, Math.ceil(policy.windowMs / 1000))
      await this.kv.put(kvKey, JSON.stringify(timestamps), { expirationTtl: ttlSeconds })
    }

    const remaining = Math.max(0, policy.requests - timestamps.length)
    const resetMs = timestamps.length > 0 ? Math.max(0, timestamps[0] + policy.windowMs - nowMs) : 0
    return { allowed, remaining, resetMs }
  }
}
