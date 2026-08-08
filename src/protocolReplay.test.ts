import { describe, expect, it } from 'vitest'
import { createEnvelope } from './protocol'
import { InMemoryReplayCache } from './protocolReplay'

describe('InMemoryReplayCache', () => {
  it('rejects replays until ttl expires', () => {
    const cache = new InMemoryReplayCache(100)
    const envelope = createEnvelope({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'hello',
      messageId: 'r1',
      nonce: 'n1',
      nowMs: 1000,
      ttlMs: 100,
    })

    expect(cache.consume(envelope, 1001).ok).toBe(true)
    expect(cache.consume(envelope, 1002).ok).toBe(false)
    expect(cache.consume(envelope, 1101).ok).toBe(true)
  })

  // A NaN expiresAt is falsy, so a naive `existingExpiry && existingExpiry >
  // nowMs` check would treat "reserved, but with a corrupt expiry" the same
  // as "never reserved" — letting the same envelope through repeatedly with
  // no error ever surfacing. consume() must fail closed instead: refuse to
  // store a non-finite expiry in the first place, and if one is somehow
  // already present, treat the key as still blocked.
  it('refuses to reserve an entry with a non-finite ttlMs/timestampMs expiry', () => {
    const cache = new InMemoryReplayCache(100)
    const envelope = createEnvelope({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'hello',
      messageId: 'r-nan',
      nonce: 'n-nan',
      nowMs: 1000,
      ttlMs: 100,
    })
    const nanEnvelope = { ...envelope, header: { ...envelope.header, ttlMs: NaN } }

    const first = cache.consume(nanEnvelope, 1001)
    expect(first.ok).toBe(false)
    // Consuming again must not silently succeed just because nothing valid
    // was ever actually reserved for this key.
    const second = cache.consume(nanEnvelope, 1002)
    expect(second.ok).toBe(false)
  })

  it('evicts by expiry order when capacity is reached', () => {
    const cache = new InMemoryReplayCache(2)
    const first = createEnvelope({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'one',
      messageId: 'r2-1',
      nonce: 'n1',
      nowMs: 1000,
      ttlMs: 10,
    })
    const second = createEnvelope({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'two',
      messageId: 'r2-2',
      nonce: 'n2',
      nowMs: 1000,
      ttlMs: 1000,
    })
    const third = createEnvelope({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'three',
      messageId: 'r2-3',
      nonce: 'n3',
      nowMs: 1000,
      ttlMs: 1000,
    })

    expect(cache.consume(first, 1001).ok).toBe(true)
    expect(cache.consume(second, 1001).ok).toBe(true)
    expect(cache.consume(third, 1001).ok).toBe(true)

    // first key should be evicted or expired first; re-consuming at same window should be accepted
    expect(cache.consume(first, 1002).ok).toBe(true)
  })

  it('bulk consumes envelopes and rejects duplicates in order', () => {
    const cache = new InMemoryReplayCache(100)
    const first = createEnvelope({ sender: 'agent.alpha', intent: 'PING', content: 'one', messageId: 'bulk-1', nonce: 'n1', nowMs: 1000, ttlMs: 1000 })
    const duplicate = createEnvelope({ sender: 'agent.alpha', intent: 'PING', content: 'one-again', messageId: 'bulk-1', nonce: 'n1', nowMs: 1000, ttlMs: 1000 })
    const second = createEnvelope({ sender: 'agent.alpha', intent: 'PING', content: 'two', messageId: 'bulk-2', nonce: 'n2', nowMs: 1000, ttlMs: 1000 })

    const results = cache.consumeMany([first, duplicate, second], 1001)

    expect(results.map((result) => result.ok)).toEqual([true, false, true])
  })
})
