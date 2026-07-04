import type { DistributedReplayStore } from './protocolReplay'
import { InMemoryRedisLikeClient, type RedisLikeClient } from './redisClient'

// ---------------------------------------------------------------------------
// ReplayStore — high-level check() interface (returns true = REPLAY)
// ---------------------------------------------------------------------------

/**
 * Minimal Redis client surface required by RedisReplayStore.
 *
 * Distinct from the internal RedisLikeClient: this interface uses a `quit()`
 * lifecycle method and does not require pipeline support, making it easy to
 * adapt any Redis client (ioredis, node-redis, Upstash, etc.) without coupling
 * to the internal pipeline abstraction.
 */
export interface RedisClientLike {
  set(key: string, value: string, opts?: { nx?: boolean; px?: number }): Promise<string | null>
  get(key: string): Promise<string | null>
  del(key: string): Promise<number | unknown>
  quit(): Promise<unknown>
}

/**
 * Gateway-facing replay store interface.
 *
 * `check()` atomically marks a key as seen and returns whether it was already
 * present: `false` = fresh (first time seen), `true` = replay (already seen).
 */
export interface ReplayStore {
  check(key: string, ttlMs: number): Promise<boolean>
}

/**
 * Redis-backed implementation of {@link ReplayStore}.
 *
 * Uses SET … NX PX for an atomic "set if not exists with TTL" operation.
 * The operation is single-round-trip and safe under concurrent access from
 * multiple gateway instances.
 */
export class RedisReplayStore implements ReplayStore {
  private readonly keyPrefix: string
  private readonly client: RedisClientLike

  constructor(opts: { redisUrl?: string; keyPrefix?: string; client?: RedisClientLike } = {}) {
    this.keyPrefix = opts.keyPrefix ?? '7h3:nonce:'
    if (opts.client) {
      this.client = opts.client
    } else {
      // Lazily adapt InMemoryRedisLikeClient to RedisClientLike for zero-dep default
      const inner = new InMemoryRedisLikeClient()
      this.client = {
        set: (key, value, setOpts) =>
          inner.set(key, value, { nx: setOpts?.nx, pxMs: setOpts?.px }),
        get: (key) => inner.get ? inner.get(key) : Promise.resolve(null),
        del: (key) => inner.del ? inner.del(key) : Promise.resolve(0),
        quit: () => Promise.resolve(),
      }
    }
  }

  /**
   * Returns `false` if the key is fresh (first time seen — key was set in Redis),
   * or `true` if the key is a replay (key already existed — SET NX returned null).
   */
  async check(key: string, ttlMs: number): Promise<boolean> {
    const redisKey = `${this.keyPrefix}${key}`
    const result = await this.client.set(redisKey, '1', { nx: true, px: Math.max(1, ttlMs) })
    // SET NX returns 'OK' when the key was newly set (fresh), null when already present (replay)
    return result === null
  }
}

/**
 * Cluster-aware replay store that wraps multiple {@link RedisReplayStore}
 * instances — one per Redis shard / node.
 *
 * A message is treated as a replay if ANY node has already seen the nonce.
 * All nodes are checked in parallel via Promise.all.
 */
export class ClusterRedisReplayStore implements ReplayStore {
  private readonly nodes: RedisReplayStore[]

  constructor(nodes: RedisReplayStore[]) {
    this.nodes = nodes
  }

  async check(key: string, ttlMs: number): Promise<boolean> {
    const results = await Promise.all(this.nodes.map((node) => node.check(key, ttlMs)))
    // If any node reports replay (true), the request is a replay
    return results.some((seen) => seen)
  }
}

/**
 * Convenience factory that creates a {@link RedisReplayStore} from a URL
 * or options object.
 */
export function createRedisReplayStore(
  clientOrOpts: RedisLikeClient | { redisUrl?: string; keyPrefix?: string; client?: RedisClientLike },
  options?: RedisReplayStoreOptions,
): DistributedReplayStore

export function createRedisReplayStore(
  clientOrOpts: RedisLikeClient | { redisUrl?: string; keyPrefix?: string; client?: RedisClientLike },
  options: RedisReplayStoreOptions = {},
): DistributedReplayStore | RedisReplayStore {
  // Detect old (client-first) vs new (opts-object) call style
  if (isRedisLikeClient(clientOrOpts)) {
    return _createDistributedReplayStore(clientOrOpts, options)
  }
  // New style: return a RedisReplayStore instance
  return new RedisReplayStore(clientOrOpts as { redisUrl?: string; keyPrefix?: string; client?: RedisClientLike })
}

function isRedisLikeClient(val: unknown): val is RedisLikeClient {
  return (
    val !== null &&
    typeof val === 'object' &&
    typeof (val as Record<string, unknown>).set === 'function' &&
    // RedisLikeClient does NOT have a `quit` method — RedisClientLike does
    // Pipeline presence distinguishes internal RedisLikeClient
    (typeof (val as Record<string, unknown>).pipeline === 'function' || !('quit' in val))
  )
}

/**
 * Creates a {@link ClusterRedisReplayStore} from an array of Redis URLs.
 * Each URL is used to create an independent {@link RedisReplayStore} node.
 */
export function createClusterReplayStore(redisUrls: string[]): ClusterRedisReplayStore {
  const nodes = redisUrls.map((url) => new RedisReplayStore({ redisUrl: url }))
  return new ClusterRedisReplayStore(nodes)
}

/**
 * What to do when the Redis client throws (network blip, server down).
 *
 * - `fallback` (default): degrade to a local in-memory store so traffic keeps
 *   flowing with single-node replay protection still in force. Quality +
 *   reliability + scalability: Redis is never a fleet-wide kill switch.
 * - `reject`: fail closed — deny the message because uniqueness cannot be confirmed.
 * - `allow`: fail open — accept the message (skip the check) to maximise uptime.
 */
export type ReplayErrorBehavior = 'fallback' | 'reject' | 'allow'

export interface RedisReplayStoreOptions {
  /** Key namespace in Redis. Default `aip:replay:`. */
  keyPrefix?: string
  /** Behavior when the Redis client throws. Default `fallback`. */
  errorBehavior?: ReplayErrorBehavior
  /** Local store used when `errorBehavior` is `fallback`. Defaults to an in-memory-backed store. */
  fallback?: DistributedReplayStore
  /** Observability hook fired whenever a Redis error forces degraded handling. */
  onDegraded?: (error: unknown, context: { key: string; behavior: ReplayErrorBehavior }) => void
}

/**
 * Internal factory — creates a {@link DistributedReplayStore} backed by
 * Redis-style `SET NX PX`. Used by the overloaded `createRedisReplayStore`
 * when a `RedisLikeClient` is passed as the first argument.
 *
 * Drop the returned store into `new DistributedReplayCache(store)` (or pass a
 * `DistributedReplayCache` as the transport `replayCache`).
 */
function _createDistributedReplayStore(
  client: RedisLikeClient,
  options: RedisReplayStoreOptions = {},
): DistributedReplayStore {
  const keyPrefix = options.keyPrefix ?? 'aip:replay:'
  const errorBehavior = options.errorBehavior ?? 'fallback'
  const onDegraded = options.onDegraded
  const fallback =
    options.fallback ??
    (errorBehavior === 'fallback'
      ? // The local fallback runs over a non-throwing in-memory client, so it
        // needs no fallback of its own — `reject` terminates the chain.
        _createDistributedReplayStore(new InMemoryRedisLikeClient(), { keyPrefix, errorBehavior: 'reject' })
      : undefined)

  function degrade(error: unknown, key: string, expiresAtMs: number, nowMs: number): Promise<boolean> | boolean {
    onDegraded?.(error, { key, behavior: errorBehavior })
    if (errorBehavior === 'allow') return true
    if (errorBehavior === 'reject') return false
    return fallback ? fallback.reserve(key, expiresAtMs, nowMs) : false
  }

  return {
    async reserve(key: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
      const pxMs = Math.max(1, expiresAtMs - nowMs)
      try {
        const result = await client.set(`${keyPrefix}${key}`, '1', { nx: true, pxMs })
        return result === 'OK'
      } catch (error) {
        return degrade(error, key, expiresAtMs, nowMs)
      }
    },

    async reserveMany(entries: Array<{ key: string; expiresAtMs: number }>, nowMs: number): Promise<boolean[]> {
      if (entries.length === 0) return []
      if (client.pipeline) {
        try {
          const batch = client.pipeline()
          for (const { key, expiresAtMs } of entries) {
            batch.set(`${keyPrefix}${key}`, '1', { nx: true, pxMs: Math.max(1, expiresAtMs - nowMs) })
          }
          const results = await batch.exec()
          return results.map((result) => result === 'OK')
        } catch (error) {
          return Promise.all(entries.map((entry) => degrade(error, entry.key, entry.expiresAtMs, nowMs)))
        }
      }
      return Promise.all(entries.map((entry) => this.reserve(entry.key, entry.expiresAtMs, nowMs)))
    },
  }
}
