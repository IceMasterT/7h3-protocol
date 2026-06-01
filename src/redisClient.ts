/**
 * Minimal Redis command surface the AIP stores depend on.
 *
 * The library stays client-agnostic: any Redis client (ioredis, node-redis,
 * Upstash, a cluster proxy, ...) can be adapted to this interface, so
 * `@7h3/protocol` ships with no Redis dependency of its own.
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
