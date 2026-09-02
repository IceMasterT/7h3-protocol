export type RateLimitPolicy = { requests: number; windowMs: number }
export type RateLimitResult = { allowed: boolean; remaining: number; resetMs: number }

/**
 * Persistent rate-limit store — required for correct rate limiting in any
 * environment where the gateway/limiter instance doesn't live for the
 * lifetime of the traffic it's limiting (e.g. a serverless function that
 * rebuilds its gateway on every invocation). Without one, SlidingWindowRateLimiter's
 * in-memory Map resets whenever the process/instance does, silently
 * defeating the limit.
 */
export interface RateLimitStore {
  consume(key: string, policy: RateLimitPolicy, nowMs?: number): Promise<RateLimitResult>
}

class SlidingWindowRateLimiter {
  private windows: Map<string, number[]> = new Map()
  // A key seen once and never again (a one-off caller, a scanner, a typo'd
  // sender id) would otherwise stay in `windows` for the lifetime of the
  // process — unbounded growth under enough unique keys. Cap total tracked
  // keys and evict least-recently-used on overflow.
  private readonly maxKeys: number

  constructor(opts: { maxKeys?: number } = {}) {
    this.maxKeys = opts.maxKeys ?? 50_000
  }

  // Check without recording — pure read
  check(key: string, policy: RateLimitPolicy, nowMs = Date.now()): RateLimitResult {
    const cutoff = nowMs - policy.windowMs
    const timestamps = (this.windows.get(key) ?? []).filter(t => t > cutoff)
    const used = timestamps.length
    const allowed = used < policy.requests
    const remaining = Math.max(0, policy.requests - used - (allowed ? 1 : 0))
    // resetMs: time until the oldest timestamp falls out of window (0 if window empty)
    const resetMs = timestamps.length > 0 ? Math.max(0, timestamps[0] + policy.windowMs - nowMs) : 0
    return { allowed, remaining, resetMs }
  }

  // Consume — record a timestamp if allowed
  consume(key: string, policy: RateLimitPolicy, nowMs = Date.now()): RateLimitResult {
    const cutoff = nowMs - policy.windowMs
    const timestamps = (this.windows.get(key) ?? []).filter(t => t > cutoff)
    const used = timestamps.length
    const allowed = used < policy.requests

    if (allowed) {
      timestamps.push(nowMs)
    }

    if (timestamps.length > 0) {
      // Map preserves insertion order; delete+set moves this key to the
      // most-recently-used end so eviction below removes the true LRU key.
      this.windows.delete(key)
      this.windows.set(key, timestamps)

      if (this.windows.size > this.maxKeys) {
        // Reclaim fully-expired windows first. They carry no live state, so
        // dropping them is free — whereas evicting a key that is currently at
        // its quota *resets that quota*, which turns memory pressure into a
        // rate-limit bypass: flood enough distinct keys and a victim's window
        // is evicted and their allowance starts over.
        //
        // This does not make the bound infinite; under genuine pressure from
        // many simultaneously-active keys, LRU eviction still applies below.
        // Size `maxKeys` above the number of distinct callers you expect.
        const cutoffNow = nowMs - policy.windowMs
        for (const [k, ts] of this.windows) {
          if (this.windows.size <= this.maxKeys) break
          if (k === key) continue
          if (ts.length === 0 || ts[ts.length - 1] <= cutoffNow) this.windows.delete(k)
        }

        // Then evict least-recently-used keys that are *under* quota. Losing
        // their state grants nothing: they were not being limited. Keys at or
        // over quota are evicted only as a last resort, because dropping one is
        // precisely what hands an attacker a reset.
        for (const [k, ts] of this.windows) {
          if (this.windows.size <= this.maxKeys) break
          if (k === key) continue
          if (ts.length < policy.requests) this.windows.delete(k)
        }

        // Last resort: the bound is real, and with more concurrently-active
        // keys than maxKeys something live has to go. Size maxKeys above the
        // number of distinct callers you expect to see inside one window.
        while (this.windows.size > this.maxKeys) {
          const oldestKey = this.windows.keys().next().value as string | undefined
          if (oldestKey === undefined) break
          this.windows.delete(oldestKey)
        }
      }
    } else {
      // Nothing left worth tracking for this key — drop it instead of
      // storing an empty array forever.
      this.windows.delete(key)
    }

    const remaining = Math.max(0, policy.requests - timestamps.length)
    const resetMs = timestamps.length > 0 ? Math.max(0, timestamps[0] + policy.windowMs - nowMs) : 0
    return { allowed, remaining, resetMs }
  }

  reset(key: string): void {
    this.windows.delete(key)
  }

  clear(): void {
    this.windows.clear()
  }
}

export const globalRateLimiter = new SlidingWindowRateLimiter()
export { SlidingWindowRateLimiter }
