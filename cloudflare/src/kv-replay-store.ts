import type { ReplayStore } from '@7h3/protocol/replay'

/**
 * Cloudflare KV-backed replay store.
 *
 * Stores nonce keys with TTL expiry to prevent replay attacks across all
 * Workers instances in the same account. KV is globally distributed with
 * strong read-after-write consistency within a datacenter.
 *
 * Race window: Two simultaneous requests carrying the same nonce from
 * different datacenters may both pass during KV's global replication window
 * (~60ms). For stronger guarantees use DurableReplayStore (durable-replay.ts).
 */
export class KvReplayStore implements ReplayStore {
  private readonly prefix: string

  constructor(
    private readonly kv: KVNamespace,
    opts?: { prefix?: string },
  ) {
    this.prefix = opts?.prefix ?? '7h3:nonce:'
  }

  async check(key: string, ttlMs: number): Promise<boolean> {
    const kvKey = `${this.prefix}${key}`
    const existing = await this.kv.get(kvKey)
    if (existing !== null) return true // replay

    // KV doesn't have SET NX — mark as seen with TTL.
    // Cloudflare KV rejects expirationTtl below 60s, so short-TTL envelopes
    // (routine for real-time agent messages) must be floored, not just ceil'd.
    const ttlSeconds = Math.max(60, Math.ceil(ttlMs / 1000))
    await this.kv.put(kvKey, '1', { expirationTtl: ttlSeconds })
    return false // fresh
  }
}
