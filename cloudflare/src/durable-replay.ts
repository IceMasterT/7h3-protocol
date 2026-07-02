import type { ReplayStore } from '@7h3/protocol/replay'

/**
 * Durable Object that provides fully atomic SET-NX replay protection.
 *
 * Each nonce key is stored in Durable Object storage, which is strongly
 * consistent and serialized — no race window. Requires Durable Objects to be
 * enabled on your Workers plan.
 *
 * Wrangler config (add to wrangler.toml):
 *
 *   [[durable_objects.bindings]]
 *   name = "REPLAY_DO"
 *   class_name = "ReplayDurableObject"
 *
 *   [[migrations]]
 *   tag = "v1"
 *   new_classes = ["ReplayDurableObject"]
 *
 * Usage in worker.ts:
 *   import { DurableReplayStore } from './durable-replay'
 *   const replay = new DurableReplayStore(env.REPLAY_DO)
 */
export class ReplayDurableObject {
  private state: DurableObjectState

  constructor(state: DurableObjectState) {
    this.state = state
  }

  async fetch(request: Request): Promise<Response> {
    const { key, ttlMs } = await request.json<{ key: string; ttlMs: number }>()

    const existing = await this.state.storage.get<number>(key)
    if (existing !== undefined) {
      return Response.json({ replay: true })
    }

    await this.state.storage.put(key, Date.now())
    // Schedule automatic deletion after TTL
    this.state.storage.setAlarm(Date.now() + ttlMs)

    return Response.json({ replay: false })
  }

  async alarm(): Promise<void> {
    // Clean up expired nonces — Cloudflare fires alarm at set time
    const all = await this.state.storage.list<number>()
    const now = Date.now()
    const expired: string[] = []
    for (const [k, ts] of all) {
      if (now - ts > 300_000) expired.push(k) // 5-min max TTL
    }
    if (expired.length > 0) await this.state.storage.delete(expired)
  }
}

export class DurableReplayStore implements ReplayStore {
  constructor(private readonly doNamespace: DurableObjectNamespace) {}

  async check(key: string, ttlMs: number): Promise<boolean> {
    // Use a single global DO instance for the replay store
    const id = this.doNamespace.idFromName('global-replay-store')
    const stub = this.doNamespace.get(id)
    const resp = await stub.fetch('https://internal/check', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key, ttlMs }),
    })
    const { replay } = await resp.json<{ replay: boolean }>()
    return replay
  }
}
