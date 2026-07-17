import { describe, it, expect } from 'vitest'
import { KvRateLimitStore } from './kv-rate-limit-store'

/** Minimal in-memory KVNamespace fake covering the get/put surface KvRateLimitStore uses. */
class FakeKV {
  private store = new Map<string, string>()

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null
  }

  async put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void> {
    if (opts?.expirationTtl !== undefined && opts.expirationTtl < 60) {
      // Mirrors real Cloudflare KV's rejection of sub-60s TTLs.
      throw new Error(`Invalid expiration_ttl of ${opts.expirationTtl}. Please use a value greater than 60.`)
    }
    this.store.set(key, value)
  }
}

describe('KvRateLimitStore', () => {
  it('allows requests under the limit and denies once exceeded', async () => {
    const kv = new FakeKV()
    const store = new KvRateLimitStore(kv as unknown as KVNamespace)
    const policy = { requests: 2, windowMs: 10_000 }

    const r1 = await store.consume('agent-a', policy, 1_000)
    expect(r1.allowed).toBe(true)
    const r2 = await store.consume('agent-a', policy, 1_100)
    expect(r2.allowed).toBe(true)
    const r3 = await store.consume('agent-a', policy, 1_200)
    expect(r3.allowed).toBe(false)
  })

  it('persists across separate KvRateLimitStore instances sharing the same KV', async () => {
    // Proves the fix: a fresh store instance (mirroring a fresh gateway
    // rebuilt on the next request) still sees prior consumption because
    // state lives in KV, not in JS heap memory.
    const kv = new FakeKV()
    const policy = { requests: 1, windowMs: 10_000 }

    const storeA = new KvRateLimitStore(kv as unknown as KVNamespace)
    const first = await storeA.consume('agent-a', policy, 1_000)
    expect(first.allowed).toBe(true)

    const storeB = new KvRateLimitStore(kv as unknown as KVNamespace)
    const second = await storeB.consume('agent-a', policy, 1_100)
    expect(second.allowed).toBe(false)
  })

  it('resets once the sliding window passes', async () => {
    const kv = new FakeKV()
    const store = new KvRateLimitStore(kv as unknown as KVNamespace)
    const policy = { requests: 1, windowMs: 10_000 }

    const first = await store.consume('agent-a', policy, 1_000)
    expect(first.allowed).toBe(true)
    const second = await store.consume('agent-a', policy, 12_000) // 11s later, outside window
    expect(second.allowed).toBe(true)
  })

  it('never calls KV.put with expirationTtl under 60s, even for short windows', async () => {
    // Regression test: Cloudflare KV rejects expirationTtl < 60. A rate-limit
    // policy with a short window (e.g. 5s) must not crash the gateway.
    const kv = new FakeKV()
    const store = new KvRateLimitStore(kv as unknown as KVNamespace)
    const policy = { requests: 5, windowMs: 5_000 }

    await expect(store.consume('agent-a', policy, 1_000)).resolves.toMatchObject({ allowed: true })
  })

  it('isolates rate limits per key', async () => {
    const kv = new FakeKV()
    const store = new KvRateLimitStore(kv as unknown as KVNamespace)
    const policy = { requests: 1, windowMs: 10_000 }

    const a = await store.consume('agent-a', policy, 1_000)
    expect(a.allowed).toBe(true)
    const b = await store.consume('agent-b', policy, 1_000)
    expect(b.allowed).toBe(true)
  })
})
