import { describe, it, expect, beforeEach } from 'vitest'
import { SlidingWindowRateLimiter } from './rateLimiter'

describe('SlidingWindowRateLimiter', () => {
  let limiter: SlidingWindowRateLimiter

  beforeEach(() => {
    limiter = new SlidingWindowRateLimiter()
  })

  it('check() allows when under limit', () => {
    const result = limiter.check('alice', { requests: 5, windowMs: 1000 })
    expect(result.allowed).toBe(true)
    expect(result.remaining).toBe(4) // 4 left after this one would be consumed
  })

  it('check() does not record a timestamp', () => {
    const policy = { requests: 1, windowMs: 1000 }
    limiter.check('alice', policy)
    limiter.check('alice', policy)
    // Still allowed — check doesn't consume
    const result = limiter.check('alice', policy)
    expect(result.allowed).toBe(true)
  })

  it('consume() records and blocks at limit', () => {
    const policy = { requests: 2, windowMs: 10_000 }
    const r1 = limiter.consume('alice', policy)
    expect(r1.allowed).toBe(true)
    expect(r1.remaining).toBe(1)

    const r2 = limiter.consume('alice', policy)
    expect(r2.allowed).toBe(true)
    expect(r2.remaining).toBe(0)

    const r3 = limiter.consume('alice', policy)
    expect(r3.allowed).toBe(false)
    expect(r3.remaining).toBe(0)
  })

  it('consume() sliding window expires old timestamps', () => {
    const policy = { requests: 2, windowMs: 1000 }
    const baseMs = 10_000

    // Fill the window at t=0
    limiter.consume('alice', policy, baseMs)
    limiter.consume('alice', policy, baseMs)

    // Blocked at t=500 (still inside window)
    const blocked = limiter.consume('alice', policy, baseMs + 500)
    expect(blocked.allowed).toBe(false)

    // Allowed at t=1001 (first entry has expired)
    const allowed = limiter.consume('alice', policy, baseMs + 1001)
    expect(allowed.allowed).toBe(true)
  })

  it('reset() clears a specific key', () => {
    const policy = { requests: 1, windowMs: 10_000 }
    limiter.consume('alice', policy)
    const blocked = limiter.consume('alice', policy)
    expect(blocked.allowed).toBe(false)

    limiter.reset('alice')
    const allowed = limiter.consume('alice', policy)
    expect(allowed.allowed).toBe(true)
  })

  it('clear() clears all keys', () => {
    const policy = { requests: 1, windowMs: 10_000 }
    limiter.consume('alice', policy)
    limiter.consume('bob', policy)

    limiter.clear()

    expect(limiter.consume('alice', policy).allowed).toBe(true)
    expect(limiter.consume('bob', policy).allowed).toBe(true)
  })

  it('resetMs is non-zero when window has entries', () => {
    const policy = { requests: 5, windowMs: 1000 }
    const baseMs = 50_000
    limiter.consume('alice', policy, baseMs)
    const result = limiter.check('alice', policy, baseMs + 100)
    expect(result.resetMs).toBeGreaterThan(0)
    expect(result.resetMs).toBeLessThanOrEqual(1000)
  })

  it('different keys are independent', () => {
    const policy = { requests: 1, windowMs: 10_000 }
    limiter.consume('alice', policy)
    // alice is blocked, but bob is not
    expect(limiter.consume('alice', policy).allowed).toBe(false)
    expect(limiter.consume('bob', policy).allowed).toBe(true)
  })
})

describe('SlidingWindowRateLimiter — bounded key growth', () => {
  it('evicts least-recently-used keys once maxKeys is exceeded', () => {
    const limiter = new SlidingWindowRateLimiter({ maxKeys: 3 })
    const policy = { requests: 10, windowMs: 10_000 }

    limiter.consume('a', policy)
    limiter.consume('b', policy)
    limiter.consume('c', policy)
    // 'a' is now the least-recently-used key; adding a 4th key evicts it.
    limiter.consume('d', policy)

    // 'a' was evicted, so its window reset. Use check() (a pure read) so the
    // assertion itself doesn't mutate the map and cascade a second eviction.
    const aAfterEvict = limiter.check('a', policy)
    expect(aAfterEvict.remaining).toBe(9) // requests(10) - used(0) - allowed(1)

    // 'b', 'c', 'd' survived the eviction and kept their recorded usage.
    const bStill = limiter.check('b', policy)
    expect(bStill.remaining).toBe(8) // requests(10) - used(1) - allowed(1)
  })

  it('touching a key on consume() protects it from eviction as LRU', () => {
    const limiter = new SlidingWindowRateLimiter({ maxKeys: 2 })
    const policy = { requests: 10, windowMs: 10_000 }

    limiter.consume('a', policy)
    limiter.consume('b', policy)
    // Re-touch 'a' so 'b' becomes the least-recently-used key.
    limiter.consume('a', policy)
    limiter.consume('c', policy) // evicts 'b', not 'a'

    const bAfterEvict = limiter.check('b', policy)
    expect(bAfterEvict.remaining).toBe(9) // 'b' was evicted, window reset

    const aStillTracked = limiter.check('a', policy)
    expect(aStillTracked.remaining).toBe(7) // 'a' consumed twice, still tracked
  })

  it('never exceeds maxKeys tracked windows regardless of unique key volume', () => {
    const limiter = new SlidingWindowRateLimiter({ maxKeys: 5 })
    const policy = { requests: 1, windowMs: 10_000 }
    for (let i = 0; i < 100; i++) {
      limiter.consume(`sender-${i}`, policy)
    }
    // Internal map size isn't exposed directly; verify indirectly by confirming
    // an early key's usage was forgotten (proof it was evicted, not retained forever).
    const earlyKeyFresh = limiter.consume('sender-0', policy)
    expect(earlyKeyFresh.allowed).toBe(true)
  })
})
