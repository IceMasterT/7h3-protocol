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
