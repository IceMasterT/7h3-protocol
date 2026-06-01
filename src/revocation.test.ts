import { describe, expect, it, vi } from 'vitest'
import { InMemoryRedisLikeClient } from './redisClient'
import {
  InMemoryRevocationStore,
  createRedisRevocationStore,
  withRevocationCheck,
} from './revocation'
import type { SignatureVerificationMaterial } from './protocol'

describe('InMemoryRevocationStore', () => {
  it('reports a key as not revoked until it is revoked', async () => {
    const store = new InMemoryRevocationStore()
    expect(await store.isRevoked('agent.a', 'k1')).toBe(false)
    await store.revoke('agent.a', 'k1')
    expect(await store.isRevoked('agent.a', 'k1')).toBe(true)
  })

  it('scopes revocation to the exact (sender, keyId) pair', async () => {
    const store = new InMemoryRevocationStore()
    await store.revoke('agent.a', 'k1')
    expect(await store.isRevoked('agent.a', 'k2')).toBe(false)
    expect(await store.isRevoked('agent.b', 'k1')).toBe(false)
  })

  it('honors a time-bounded revocation (untilMs)', async () => {
    let now = 1000
    const store = new InMemoryRevocationStore({ now: () => now })
    await store.revoke('agent.a', 'k1', { untilMs: 2000 })
    expect(await store.isRevoked('agent.a', 'k1')).toBe(true)
    now = 2500
    expect(await store.isRevoked('agent.a', 'k1')).toBe(false)
  })
})

describe('createRedisRevocationStore', () => {
  it('revoke writes a key that isRevoked reads back', async () => {
    const store = createRedisRevocationStore(new InMemoryRedisLikeClient())
    expect(await store.isRevoked('agent.a', 'k1')).toBe(false)
    await store.revoke('agent.a', 'k1')
    expect(await store.isRevoked('agent.a', 'k1')).toBe(true)
  })

  it('caches reads so repeated checks within the freshness window hit Redis once', async () => {
    let now = 1000
    const client = new InMemoryRedisLikeClient({ now: () => now })
    const getSpy = vi.spyOn(client, 'get')
    const store = createRedisRevocationStore(client, { cacheTtlMs: 5000, now: () => now })
    await store.isRevoked('agent.a', 'k1')
    await store.isRevoked('agent.a', 'k1')
    expect(getSpy).toHaveBeenCalledOnce()
    now = 7000 // past the cache window
    await store.isRevoked('agent.a', 'k1')
    expect(getSpy).toHaveBeenCalledTimes(2)
  })

  it('fails closed by default: a Redis error means the key is treated as revoked', async () => {
    const onDegraded = vi.fn()
    const throwing = {
      set: async () => 'OK' as const,
      get: async () => {
        throw new Error('redis unreachable')
      },
    }
    const store = createRedisRevocationStore(throwing, { onDegraded })
    expect(await store.isRevoked('agent.a', 'k1')).toBe(true)
    expect(onDegraded).toHaveBeenCalledOnce()
  })

  it('errorBehavior "allow" treats a Redis error as not revoked', async () => {
    const throwing = {
      set: async () => 'OK' as const,
      get: async () => {
        throw new Error('redis unreachable')
      },
    }
    const store = createRedisRevocationStore(throwing, { errorBehavior: 'allow' })
    expect(await store.isRevoked('agent.a', 'k1')).toBe(false)
  })
})

describe('withRevocationCheck (signature resolver wrapper)', () => {
  const material: SignatureVerificationMaterial = { alg: 'HS256', secret: 's3cret' }
  const innerResolver = async () => material
  const signature = { alg: 'HS256' as const, keyId: 'k1', value: 'sig' }

  it('returns material for a key that is not revoked', async () => {
    const store = new InMemoryRevocationStore()
    const resolver = withRevocationCheck(innerResolver, store)
    expect(await resolver(signature, 'agent.a')).toEqual(material)
  })

  it('returns undefined (verification fails) for a revoked key', async () => {
    const store = new InMemoryRevocationStore()
    await store.revoke('agent.a', 'k1')
    const resolver = withRevocationCheck(innerResolver, store)
    expect(await resolver(signature, 'agent.a')).toBeUndefined()
  })
})
