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
      this.windows.set(key, timestamps)
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
