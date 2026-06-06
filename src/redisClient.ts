/**
 * Minimal Redis command surface the AIP stores depend on.
 *
 * The library stays client-agnostic: any Redis client (ioredis, node-redis,
 * Upstash, a cluster proxy, ...) can be adapted to this interface, so
 * `@7h3/protocol` ships with no Redis dependency of its own.
 *
 * # High-Availability topologies
 *
 * ## Redis Sentinel
 * ioredis connects to a Sentinel group transparently — adapt the same client
 * to `RedisLikeClient` with the same three-line wrapper. The library requires
 * no topology-specific changes:
 *
 * ```ts
 * import Redis from 'ioredis'
 * import { adaptIoredis } from './adaptIoredis'  // your adapter module
 *
 * const client = new Redis({
 *   sentinels: [
 *     { host: 'sentinel-1', port: 26379 },
 *     { host: 'sentinel-2', port: 26379 },
 *     { host: 'sentinel-3', port: 26379 },
 *   ],
 *   name: 'mymaster',
 * })
 * const aipRedis = adaptIoredis(client)  // same adapter as standalone Redis
 * ```
 *
 * ## Redis Cluster
 * Cluster mode shards keys across nodes using CRC16. AIP replay keys
 * (`aip:replay:{sender}:{messageId}:{nonce}`) and revocation keys
 * (`aip:revoked:{keyId}`) are independent — no cross-slot transactions are
 * required. Adapt a Cluster client the same way as a standalone client.
 *
 * ## Upstash / serverless Redis
 * Upstash's HTTP-based Redis client exposes a `set(key, value, options)`
 * interface compatible with `RedisLikeClient` without any wrapping.
 *
 * ## Operational requirements
 * - **Clock sync**: AIP TTL checks require clocks within the configured skew
 *   window (default ±30 s). NTP or PTP is required across all nodes.
 * - **HA of the replay store itself**: the protocol degrades gracefully on
 *   Redis outage (`errorBehavior: 'fallback'` or `'allow'`), but a hard
 *   `'reject'` posture prevents replay-store outage from becoming a
 *   denial-of-service vector. Choose the posture that matches your threat model.
 * - See `docs/DISTRIBUTED_REPLAY.md` for full operational guidance.
 */

export interface RedisSetOptions {
  /** Only set when the key does not already exist (Redis `NX`). */
  nx?: boolean
  /** Expire the key after this many milliseconds (Redis `PX`). */
  pxMs?: number
}

/** A queued, chainable batch of `set` commands flushed in a single round-trip. */
export interface RedisPipelineLike {
  set(key: string, value: string, options?: RedisSetOptions): RedisPipelineLike
  exec(): Promise<Array<'OK' | null>>
}

export interface RedisLikeClient {
  /** Returns `'OK'` when the value was written, or `null` when `NX` prevented it. */
  set(key: string, value: string, options?: RedisSetOptions): Promise<'OK' | null>
  /** Truthy when the key exists and has not expired. */
  get?(key: string): Promise<string | null>
  /** Removes a key; returns the number of keys removed. */
  del?(key: string): Promise<number>
  /** Optional batch pipeline; when present, batch reserves use a single round-trip. */
  pipeline?(): RedisPipelineLike
}

interface Entry {
  value: string
  expiresAt?: number
}

/**
 * In-memory reference implementation of {@link RedisLikeClient}.
 *
 * It is a faithful stand-in for a single Redis node's `SET NX PX` / `GET` /
 * `DEL` semantics — useful for tests, local development, and as the default
 * degraded-mode fallback. It is NOT a distributed store: it provides no
 * cross-process guarantees and must not be used as a production replay store
 * for a horizontally scaled deployment.
 */
export class InMemoryRedisLikeClient implements RedisLikeClient {
  private readonly entries = new Map<string, Entry>()
  private readonly now: () => number

  constructor(options: { now?: () => number } = {}) {
    this.now = options.now ?? (() => Date.now())
  }

  private live(key: string): Entry | undefined {
    const entry = this.entries.get(key)
    if (!entry) return undefined
    if (entry.expiresAt !== undefined && entry.expiresAt <= this.now()) {
      this.entries.delete(key)
      return undefined
    }
    return entry
  }

  async set(key: string, value: string, options: RedisSetOptions = {}): Promise<'OK' | null> {
    if (options.nx && this.live(key)) return null
    const expiresAt = options.pxMs !== undefined ? this.now() + options.pxMs : undefined
    this.entries.set(key, { value, expiresAt })
    return 'OK'
  }

  async get(key: string): Promise<string | null> {
    return this.live(key)?.value ?? null
  }

  async del(key: string): Promise<number> {
    const existed = this.live(key) !== undefined
    this.entries.delete(key)
    return existed ? 1 : 0
  }

  pipeline(): RedisPipelineLike {
    const commands: Array<{ key: string; value: string; options?: RedisSetOptions }> = []
    const pipeline: RedisPipelineLike = {
      set: (key: string, value: string, options?: RedisSetOptions) => {
        commands.push({ key, value, options })
        return pipeline
      },
      exec: async () => {
        const results: Array<'OK' | null> = []
        for (const command of commands) {
          results.push(await this.set(command.key, command.value, command.options))
        }
        return results
      },
    }
    return pipeline
  }
}
