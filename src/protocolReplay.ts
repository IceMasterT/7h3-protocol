import type { ProtocolEnvelope } from './protocol'

export interface ReplayCheckResult {
  ok: boolean
  reason?: string
}

export interface ReplayCache {
  consume(envelope: ProtocolEnvelope, nowMs?: number): ReplayCheckResult | Promise<ReplayCheckResult>
  consumeMany?(envelopes: ProtocolEnvelope[], nowMs?: number): ReplayCheckResult[] | Promise<ReplayCheckResult[]>
}

export interface DistributedReplayStore {
  reserve(key: string, expiresAtMs: number, nowMs: number): boolean | Promise<boolean>
  /** Optional batch reserve; enables single round-trip checks for batched envelopes. */
  reserveMany?(
    entries: Array<{ key: string; expiresAtMs: number }>,
    nowMs: number,
  ): boolean[] | Promise<boolean[]>
}

interface ExpiryEntry {
  key: string
  expiresAt: number
}

class ExpiryMinHeap {
  private readonly items: ExpiryEntry[] = []

  peek(): ExpiryEntry | undefined {
    return this.items[0]
  }

  push(entry: ExpiryEntry): void {
    this.items.push(entry)
    this.bubbleUp(this.items.length - 1)
  }

  pop(): ExpiryEntry | undefined {
    if (this.items.length === 0) return undefined
    const first = this.items[0]
    const last = this.items.pop()
    if (this.items.length > 0 && last) {
      this.items[0] = last
      this.bubbleDown(0)
    }
    return first
  }

  private bubbleUp(index: number): void {
    let current = index
    while (current > 0) {
      const parent = Math.floor((current - 1) / 2)
      const parentItem = this.items[parent]
      const currentItem = this.items[current]
      if (!parentItem || !currentItem || parentItem.expiresAt <= currentItem.expiresAt) break
      this.items[parent] = currentItem
      this.items[current] = parentItem
      current = parent
    }
  }

  private bubbleDown(index: number): void {
    let current = index
    while (true) {
      const left = current * 2 + 1
      const right = current * 2 + 2
      let smallest = current

      const currentItem = this.items[current]
      const leftItem = this.items[left]
      const rightItem = this.items[right]

      if (leftItem && currentItem && leftItem.expiresAt < currentItem.expiresAt) {
        smallest = left
      }
      const smallestItem = this.items[smallest]
      if (rightItem && smallestItem && rightItem.expiresAt < smallestItem.expiresAt) {
        smallest = right
      }

      if (smallest === current) break
      const swapA = this.items[current]
      const swapB = this.items[smallest]
      if (!swapA || !swapB) break
      this.items[current] = swapB
      this.items[smallest] = swapA
      current = smallest
    }
  }
}

export class InMemoryReplayCache implements ReplayCache {
  private readonly entries = new Map<string, number>()
  private readonly maxEntries: number
  private readonly expiries = new ExpiryMinHeap()

  constructor(maxEntries = 10000) {
    this.maxEntries = maxEntries
  }

  private makeKey(envelope: ProtocolEnvelope): string {
    // encodeURIComponent escapes '|' so sender/messageId/nonce can never collide
    // across field boundaries (e.g. sender="a|b" vs messageId="a|b").
    return `${encodeURIComponent(envelope.header.sender)}|${encodeURIComponent(envelope.header.messageId)}|${encodeURIComponent(envelope.header.nonce)}`
  }

  prune(nowMs = Date.now()): void {
    while (true) {
      const next = this.expiries.peek()
      if (!next || next.expiresAt > nowMs) break

      this.expiries.pop()
      const currentExpiry = this.entries.get(next.key)
      if (currentExpiry !== undefined && currentExpiry === next.expiresAt && currentExpiry <= nowMs) {
        this.entries.delete(next.key)
      }
    }
  }

  private evictOne(): void {
    while (this.entries.size >= this.maxEntries) {
      const next = this.expiries.pop()
      if (!next) break
      const currentExpiry = this.entries.get(next.key)
      if (currentExpiry !== undefined && currentExpiry === next.expiresAt) {
        this.entries.delete(next.key)
        return
      }
    }

    if (this.entries.size >= this.maxEntries) {
      const fallback = this.entries.keys().next().value as string | undefined
      if (fallback) this.entries.delete(fallback)
    }
  }

  consume(envelope: ProtocolEnvelope, nowMs = Date.now()): ReplayCheckResult {
    this.prune(nowMs)

    const key = this.makeKey(envelope)
    const existingExpiry = this.entries.get(key)
    // A NaN existingExpiry is falsy, so `existingExpiry && ...` alone would
    // silently treat "this key is already reserved, but with a corrupt
    // expiry" as "no reservation exists" — the exact opposite of fail-closed.
    // Callers are expected to reject non-finite timestampMs/ttlMs before
    // ever reaching here (receiveEnvelope does, via validateEnvelope), but
    // this is the last line of defense for any caller that doesn't.
    if (existingExpiry !== undefined && (!Number.isFinite(existingExpiry) || existingExpiry > nowMs)) {
      return { ok: false, reason: 'Replay detected for sender/messageId/nonce' }
    }

    const expiresAt = envelope.header.timestampMs + envelope.header.ttlMs
    if (!Number.isFinite(expiresAt)) {
      return { ok: false, reason: 'Cannot track replay protection for a non-finite timestampMs/ttlMs' }
    }

    if (this.entries.size >= this.maxEntries) this.evictOne()

    this.entries.set(key, expiresAt)
    this.expiries.push({ key, expiresAt })
    return { ok: true }
  }

  consumeMany(envelopes: ProtocolEnvelope[], nowMs = Date.now()): ReplayCheckResult[] {
    return envelopes.map((envelope) => this.consume(envelope, nowMs))
  }
}

export class DistributedReplayCache implements ReplayCache {
  private readonly store: DistributedReplayStore

  constructor(store: DistributedReplayStore) {
    this.store = store
  }

  private makeKey(envelope: ProtocolEnvelope): string {
    return `${encodeURIComponent(envelope.header.sender)}|${encodeURIComponent(envelope.header.messageId)}|${encodeURIComponent(envelope.header.nonce)}`
  }

  async consume(envelope: ProtocolEnvelope, nowMs = Date.now()): Promise<ReplayCheckResult> {
    const key = this.makeKey(envelope)
    const expiresAtMs = envelope.header.timestampMs + envelope.header.ttlMs
    if (!Number.isFinite(expiresAtMs)) {
      return { ok: false, reason: 'Cannot track replay protection for a non-finite timestampMs/ttlMs' }
    }
    const reserved = await this.store.reserve(key, expiresAtMs, nowMs)
    if (!reserved) {
      return { ok: false, reason: 'Replay detected for sender/messageId/nonce' }
    }
    return { ok: true }
  }

  async consumeMany(envelopes: ProtocolEnvelope[], nowMs = Date.now()): Promise<ReplayCheckResult[]> {
    if (this.store.reserveMany) {
      const entries = envelopes.map((envelope) => ({
        key: this.makeKey(envelope),
        expiresAtMs: envelope.header.timestampMs + envelope.header.ttlMs,
      }))
      const reserved = await this.store.reserveMany(entries, nowMs)
      return reserved.map((ok) =>
        ok ? { ok: true } : { ok: false, reason: 'Replay detected for sender/messageId/nonce' },
      )
    }
    return Promise.all(envelopes.map((envelope) => this.consume(envelope, nowMs)))
  }
}
