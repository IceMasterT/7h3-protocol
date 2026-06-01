import type { DistributedReplayStore } from './protocolReplay'
import { InMemoryRedisLikeClient, type RedisLikeClient } from './redisClient'

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
 * Creates a {@link DistributedReplayStore} backed by Redis-style `SET NX PX`.
 *
 * Drop the returned store into `new DistributedReplayCache(store)` (or pass a
 * `DistributedReplayCache` as the transport `replayCache`).
 */
export function createRedisReplayStore(
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
        createRedisReplayStore(new InMemoryRedisLikeClient(), { keyPrefix, errorBehavior: 'reject' })
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
