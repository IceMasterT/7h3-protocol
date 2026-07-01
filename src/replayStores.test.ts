import { describe, expect, it, vi } from 'vitest'
import { InMemoryRedisLikeClient } from './redisClient'
import {
  createRedisReplayStore,
  RedisReplayStore,
  ClusterRedisReplayStore,
  createClusterReplayStore,
  type ReplayStore,
  type RedisClientLike,
} from './replayStores'
import { DistributedReplayCache } from './protocolReplay'
import { createEnvelope } from './protocol'

describe('InMemoryRedisLikeClient (reference client)', () => {
  it('SET NX returns OK on first write and null when the key already exists', async () => {
    const client = new InMemoryRedisLikeClient()
    const first = await client.set('k', '1', { nx: true, pxMs: 1000 })
    const second = await client.set('k', '1', { nx: true, pxMs: 1000 })
    expect(first).toBe('OK')
    expect(second).toBeNull()
  })

  it('SET NX succeeds again after the PX TTL elapses', async () => {
    let now = 1000
    const client = new InMemoryRedisLikeClient({ now: () => now })
    expect(await client.set('k', '1', { nx: true, pxMs: 500 })).toBe('OK')
    now = 1400
    expect(await client.set('k', '1', { nx: true, pxMs: 500 })).toBeNull()
    now = 1600
    expect(await client.set('k', '1', { nx: true, pxMs: 500 })).toBe('OK')
  })
})

describe('createRedisReplayStore', () => {
  it('reserve returns true for a new key and false for a duplicate', async () => {
    const store = createRedisReplayStore(new InMemoryRedisLikeClient())
    expect(await store.reserve('sender|m1|n1', 5000, 1000)).toBe(true)
    expect(await store.reserve('sender|m1|n1', 5000, 1000)).toBe(false)
  })

  it('reserves distinct keys independently', async () => {
    const store = createRedisReplayStore(new InMemoryRedisLikeClient())
    expect(await store.reserve('sender|m1|n1', 5000, 1000)).toBe(true)
    expect(await store.reserve('sender|m2|n2', 5000, 1000)).toBe(true)
  })

  it('sets the Redis key with the prefix and a positive PX derived from expiry minus now', async () => {
    const client = new InMemoryRedisLikeClient()
    const setSpy = vi.spyOn(client, 'set')
    const store = createRedisReplayStore(client, { keyPrefix: 'aip:replay:' })
    await store.reserve('sender|m1|n1', 5000, 1000)
    expect(setSpy).toHaveBeenCalledWith('aip:replay:sender|m1|n1', '1', { nx: true, pxMs: 4000 })
  })

  it('clamps PX to at least 1ms when expiry is not in the future', async () => {
    const client = new InMemoryRedisLikeClient()
    const setSpy = vi.spyOn(client, 'set')
    const store = createRedisReplayStore(client)
    await store.reserve('sender|m1|n1', 1000, 1000)
    expect(setSpy).toHaveBeenCalledWith('aip:replay:sender|m1|n1', '1', { nx: true, pxMs: 1 })
  })
})

describe('createRedisReplayStore degraded behavior', () => {
  function throwingClient() {
    return {
      set: async () => {
        throw new Error('redis unreachable')
      },
    }
  }

  it('errorBehavior "reject" returns false and fires onDegraded when the client throws', async () => {
    const onDegraded = vi.fn()
    const store = createRedisReplayStore(throwingClient(), { errorBehavior: 'reject', onDegraded })
    expect(await store.reserve('sender|m1|n1', 5000, 1000)).toBe(false)
    expect(onDegraded).toHaveBeenCalledOnce()
  })

  it('errorBehavior "allow" returns true and fires onDegraded when the client throws', async () => {
    const onDegraded = vi.fn()
    const store = createRedisReplayStore(throwingClient(), { errorBehavior: 'allow', onDegraded })
    expect(await store.reserve('sender|m1|n1', 5000, 1000)).toBe(true)
    expect(onDegraded).toHaveBeenCalledOnce()
  })

  it('errorBehavior "fallback" (default) degrades to a local store and fires onDegraded', async () => {
    const onDegraded = vi.fn()
    const store = createRedisReplayStore(throwingClient(), { onDegraded })
    // first call to the degraded local store reserves successfully
    expect(await store.reserve('sender|m1|n1', 5000, 1000)).toBe(true)
    // second identical call is caught locally as a replay
    expect(await store.reserve('sender|m1|n1', 5000, 1000)).toBe(false)
    expect(onDegraded).toHaveBeenCalledTimes(2)
  })

  it('errorBehavior "fallback" delegates to an explicitly provided local store', async () => {
    const onDegraded = vi.fn()
    const fallback = createRedisReplayStore(new InMemoryRedisLikeClient())
    const store = createRedisReplayStore(throwingClient(), { fallback, onDegraded })
    expect(await store.reserve('sender|m1|n1', 5000, 1000)).toBe(true)
    expect(await store.reserve('sender|m1|n1', 5000, 1000)).toBe(false)
    expect(onDegraded).toHaveBeenCalledTimes(2)
  })
})

describe('createRedisReplayStore batch (reserveMany)', () => {
  it('reserves a batch, deduplicating within the batch and against prior reservations', async () => {
    const store = createRedisReplayStore(new InMemoryRedisLikeClient())
    await store.reserve('sender|m0|n0', 5000, 1000)
    const results = await store.reserveMany!(
      [
        { key: 'sender|m0|n0', expiresAtMs: 5000 }, // already reserved → false
        { key: 'sender|m1|n1', expiresAtMs: 5000 }, // new → true
        { key: 'sender|m1|n1', expiresAtMs: 5000 }, // duplicate within batch → false
      ],
      1000,
    )
    expect(results).toEqual([false, true, false])
  })

  it('uses the client pipeline when one is available (single round-trip)', async () => {
    const client = new InMemoryRedisLikeClient()
    const pipelineSpy = vi.spyOn(client, 'pipeline')
    const store = createRedisReplayStore(client)
    await store.reserveMany!(
      [
        { key: 'sender|m1|n1', expiresAtMs: 5000 },
        { key: 'sender|m2|n2', expiresAtMs: 5000 },
      ],
      1000,
    )
    expect(pipelineSpy).toHaveBeenCalledOnce()
  })
})

describe('DistributedReplayCache batch delegation', () => {
  it('consumeMany routes through the store reserveMany when present', async () => {
    const store = createRedisReplayStore(new InMemoryRedisLikeClient())
    const reserveManySpy = vi.spyOn(store, 'reserveMany')
    const cache = new DistributedReplayCache(store)
    const e1 = { ...createEnvelope({ sender: 's', intent: 'PING', content: 'p', messageId: 'm1', nonce: 'n1', nowMs: 1000 }), signature: undefined } as never
    const e2 = { ...createEnvelope({ sender: 's', intent: 'PING', content: 'p', messageId: 'm2', nonce: 'n2', nowMs: 1000 }), signature: undefined } as never
    const results = await cache.consumeMany([e1, e2], 1000)
    expect(reserveManySpy).toHaveBeenCalledOnce()
    expect(results.map((r) => r.ok)).toEqual([true, true])
  })
})

// ---------------------------------------------------------------------------
// New ReplayStore interface and class tests (check()-based API)
// ---------------------------------------------------------------------------

/**
 * Build a mock RedisClientLike whose SET NX behaviour can be scripted:
 * first call returns 'OK' (fresh), subsequent calls return null (replay).
 */
function mockRedisClient(): RedisClientLike {
  let callCount = 0
  return {
    set: vi.fn(async (_key: string, _value: string, _opts?: { nx?: boolean; px?: number }) => {
      callCount++
      return callCount === 1 ? 'OK' : null
    }),
    get: vi.fn(async (_key: string) => null),
    del: vi.fn(async (_key: string) => 0),
    quit: vi.fn(async () => undefined),
  }
}

describe('RedisReplayStore (check() interface)', () => {
  it('first call returns false (fresh) and second call returns true (replay)', async () => {
    const client = mockRedisClient()
    const store = new RedisReplayStore({ client })
    const fresh = await store.check('nonce-abc', 30_000)
    const replay = await store.check('nonce-abc', 30_000)
    expect(fresh).toBe(false)
    expect(replay).toBe(true)
  })

  it('satisfies the ReplayStore interface', () => {
    const store: ReplayStore = new RedisReplayStore({ client: mockRedisClient() })
    expect(typeof store.check).toBe('function')
  })

  it('uses default keyPrefix "7h3:nonce:"', async () => {
    const client = mockRedisClient()
    const store = new RedisReplayStore({ client })
    await store.check('my-nonce', 5000)
    expect(client.set).toHaveBeenCalledWith('7h3:nonce:my-nonce', '1', { nx: true, px: 5000 })
  })

  it('respects a custom keyPrefix', async () => {
    const client = mockRedisClient()
    const store = new RedisReplayStore({ client, keyPrefix: 'custom:' })
    await store.check('n1', 1000)
    expect(client.set).toHaveBeenCalledWith('custom:n1', '1', { nx: true, px: 1000 })
  })

  it('clamps TTL to at least 1ms', async () => {
    const client = mockRedisClient()
    const store = new RedisReplayStore({ client })
    await store.check('n1', 0)
    expect(client.set).toHaveBeenCalledWith('7h3:nonce:n1', '1', { nx: true, px: 1 })
  })
})

describe('createRedisReplayStore opts-object overload', () => {
  it('returns a RedisReplayStore with the correct keyPrefix', () => {
    const store = createRedisReplayStore({ keyPrefix: '7h3:nonce:' })
    expect(store).toBeInstanceOf(RedisReplayStore)
  })

  it('returns a RedisReplayStore with default keyPrefix when none specified', () => {
    const store = createRedisReplayStore({ client: mockRedisClient() })
    expect(store).toBeInstanceOf(RedisReplayStore)
  })
})

describe('ClusterRedisReplayStore', () => {
  it('check() returns false (fresh) when ALL nodes say fresh', async () => {
    // Build two nodes each with a fresh client
    const makeClient = () => {
      const c = mockRedisClient()
      return c
    }
    const node1 = new RedisReplayStore({ client: makeClient() })
    const node2 = new RedisReplayStore({ client: makeClient() })
    const cluster = new ClusterRedisReplayStore([node1, node2])
    // First call: both nodes return OK → fresh
    const result = await cluster.check('nonce-xyz', 10_000)
    expect(result).toBe(false)
  })

  it('check() returns true (replay) when ANY node reports replay', async () => {
    // node1: already seen (returns null immediately)
    const replayClient: RedisClientLike = {
      set: vi.fn(async () => null), // always null = always replay
      get: vi.fn(async () => null),
      del: vi.fn(async () => 0),
      quit: vi.fn(async () => undefined),
    }
    // node2: fresh (returns OK)
    const freshClient: RedisClientLike = {
      set: vi.fn(async () => 'OK'),
      get: vi.fn(async () => null),
      del: vi.fn(async () => 0),
      quit: vi.fn(async () => undefined),
    }
    const node1 = new RedisReplayStore({ client: replayClient })
    const node2 = new RedisReplayStore({ client: freshClient })
    const cluster = new ClusterRedisReplayStore([node1, node2])
    const result = await cluster.check('nonce-xyz', 10_000)
    expect(result).toBe(true)
  })

  it('queries all nodes in parallel via Promise.all', async () => {
    const clients = [mockRedisClient(), mockRedisClient(), mockRedisClient()]
    const nodes = clients.map((c) => new RedisReplayStore({ client: c }))
    const cluster = new ClusterRedisReplayStore(nodes)
    await cluster.check('nonce-parallel', 5000)
    for (const c of clients) {
      expect(c.set).toHaveBeenCalledOnce()
    }
  })
})

describe('createClusterReplayStore', () => {
  it('returns a ClusterRedisReplayStore from an array of URLs', () => {
    const cluster = createClusterReplayStore(['redis://node1:6379', 'redis://node2:6379'])
    expect(cluster).toBeInstanceOf(ClusterRedisReplayStore)
  })
})
