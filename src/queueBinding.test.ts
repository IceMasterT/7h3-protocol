import { describe, it, expect, beforeAll } from 'vitest'
import { generateEd25519KeypairBase64Url } from './protocol'
import { signQueueMessage, verifyQueueMessage, verifyQueueBatch } from './queueBinding'
import { InMemoryReplayCache } from './protocolReplay'

let publicKey: string
let privateKey: string
let altPublicKey: string

beforeAll(async () => {
  const kp = await generateEd25519KeypairBase64Url()
  publicKey = kp.publicKey
  privateKey = kp.privateKey

  const alt = await generateEd25519KeypairBase64Url()
  altPublicKey = alt.publicKey
})

describe('signQueueMessage + verifyQueueMessage', () => {
  it('round trip with string payload', async () => {
    const payload = 'hello queue'
    const msg = await signQueueMessage(payload, { privateKey, sender: 'agent-a' })
    const result = await verifyQueueMessage<string>(msg, { publicKey })
    expect(result.payload).toBe(payload)
    expect(result.envelope.header.sender).toBe('agent-a')
    expect(result.envelope.body.intent).toBe('TASK')
  })

  it('round trip with object payload', async () => {
    const payload = { task: 'do-something', priority: 5 }
    const msg = await signQueueMessage(payload, { privateKey, sender: 'agent-b', recipient: 'agent-c' })
    const result = await verifyQueueMessage<typeof payload>(msg, { publicKey })
    expect(result.payload).toEqual(payload)
    expect(result.envelope.header.recipient).toBe('agent-c')
  })

  it('uses default 1 hour TTL', async () => {
    const msg = await signQueueMessage('ttl-test', { privateKey, sender: 'agent-a' })
    const parsed = JSON.parse(msg)
    expect(parsed.envelope.header.ttlMs).toBe(3_600_000)
  })

  it('respects custom ttlMs', async () => {
    const msg = await signQueueMessage('ttl-custom', { privateKey, sender: 'agent-a', ttlMs: 7200000 })
    const parsed = JSON.parse(msg)
    expect(parsed.envelope.header.ttlMs).toBe(7200000)
  })

  it('throws on tampered message (modified payload)', async () => {
    const msg = await signQueueMessage({ x: 1 }, { privateKey, sender: 'agent-a' })
    const parsed = JSON.parse(msg)
    // tamper with the envelope content
    parsed.envelope.body.content = '{"x":999}'
    const tampered = JSON.stringify(parsed)
    await expect(verifyQueueMessage(tampered, { publicKey })).rejects.toThrow('signature verification failed')
  })

  it('throws on wrong public key', async () => {
    const msg = await signQueueMessage('secure', { privateKey, sender: 'agent-a' })
    await expect(verifyQueueMessage(msg, { publicKey: altPublicKey })).rejects.toThrow('signature verification failed')
  })

  it('throws on invalid JSON', async () => {
    await expect(verifyQueueMessage('not-json', { publicKey })).rejects.toThrow('not valid JSON')
  })

  it('throws on missing envelope', async () => {
    await expect(verifyQueueMessage(JSON.stringify({ payload: 'x' }), { publicKey })).rejects.toThrow(
      'missing envelope',
    )
  })

  it('rejects an expired message by default (strictTtl defaults to true)', async () => {
    const msg = await signQueueMessage('expiring', { privateKey, sender: 'agent-a', ttlMs: 1_000 })
    // Verify far enough past timestamp+ttl that it must be expired.
    const parsed = JSON.parse(msg)
    const nowMs = parsed.envelope.header.timestampMs + parsed.envelope.header.ttlMs + 60_000
    await expect(verifyQueueMessage(msg, { publicKey, nowMs })).rejects.toThrow('failed validation')
  })

  it('accepts an expired message when strictTtl is explicitly disabled', async () => {
    const msg = await signQueueMessage('expiring', { privateKey, sender: 'agent-a', ttlMs: 1_000 })
    const parsed = JSON.parse(msg)
    const nowMs = parsed.envelope.header.timestampMs + parsed.envelope.header.ttlMs + 60_000
    const result = await verifyQueueMessage(msg, { publicKey, nowMs, strictTtl: false })
    expect(result.payload).toBe('expiring')
  })

  it('rejects a replayed message when a shared replayCache is reused across calls', async () => {
    // Regression test: a fresh replayCache constructed per call would provide
    // zero protection. This proves persistence across independent verify calls.
    const replayCache = new InMemoryReplayCache()
    const msg = await signQueueMessage('once-only', { privateKey, sender: 'agent-a' })

    const first = await verifyQueueMessage(msg, { publicKey, replayCache })
    expect(first.payload).toBe('once-only')

    await expect(verifyQueueMessage(msg, { publicKey, replayCache })).rejects.toThrow('Replay detected')
  })

  it('allows the same nonce twice when no replayCache is supplied (opt-in)', async () => {
    const msg = await signQueueMessage('no-dedup', { privateKey, sender: 'agent-a' })
    const first = await verifyQueueMessage(msg, { publicKey })
    const second = await verifyQueueMessage(msg, { publicKey })
    expect(first.payload).toBe('no-dedup')
    expect(second.payload).toBe('no-dedup')
  })
})

describe('verifyQueueBatch', () => {
  it('mixed valid/invalid returns correct ok/false results', async () => {
    const valid1 = await signQueueMessage('msg1', { privateKey, sender: 'a' })
    const valid2 = await signQueueMessage({ n: 2 }, { privateKey, sender: 'b' })
    const invalid = 'garbage-json'

    const results = await verifyQueueBatch<unknown>([valid1, invalid, valid2], { publicKey })
    expect(results).toHaveLength(3)
    expect(results[0].ok).toBe(true)
    expect(results[1].ok).toBe(false)
    expect(results[2].ok).toBe(true)

    const failed = results[1]
    if (!failed.ok) {
      expect(failed.raw).toBe(invalid)
      expect(failed.error).toBeTruthy()
    }
  })

  it('all valid batch', async () => {
    const messages = await Promise.all([
      signQueueMessage('a', { privateKey, sender: 'x' }),
      signQueueMessage('b', { privateKey, sender: 'y' }),
      signQueueMessage('c', { privateKey, sender: 'z' }),
    ])
    const results = await verifyQueueBatch<string>(messages, { publicKey })
    expect(results.every((r) => r.ok)).toBe(true)
    const payloads = results.filter((r) => r.ok).map((r) => (r.ok ? r.payload : null))
    expect(payloads).toEqual(['a', 'b', 'c'])
  })

  it('all invalid batch', async () => {
    const messages = ['bad1', 'bad2', JSON.stringify({ payload: 'no-envelope' })]
    const results = await verifyQueueBatch<string>(messages, { publicKey })
    expect(results.every((r) => !r.ok)).toBe(true)
    results.forEach((r, i) => {
      if (!r.ok) {
        expect(r.raw).toBe(messages[i])
        expect(typeof r.error).toBe('string')
      }
    })
  })

  it('wrong key causes all-invalid for valid messages', async () => {
    const messages = await Promise.all([
      signQueueMessage('p', { privateKey, sender: 'a' }),
      signQueueMessage('q', { privateKey, sender: 'b' }),
    ])
    const results = await verifyQueueBatch<string>(messages, { publicKey: altPublicKey })
    expect(results.every((r) => !r.ok)).toBe(true)
  })

  it('never throws even if all messages are invalid', async () => {
    await expect(verifyQueueBatch(['{}', 'nope', '{"envelope":null,"payload":1}'], { publicKey })).resolves.toBeDefined()
  })
})

describe('queue payload integrity — the payload must be what was signed', () => {
  async function signed() {
    const kp = await generateEd25519KeypairBase64Url()
    const message = await signQueueMessage(
      { job: 'reindex', amount: 10 },
      { sender: 'a@b.test', privateKey: kp.privateKey, keyId: 'k1', ttlMs: 60_000 },
    )
    return { kp, message, parsed: JSON.parse(message) as { envelope: unknown; payload: unknown } }
  }

  it('rejects a message whose payload was swapped under a valid signature', async () => {
    const { kp, parsed } = await signed()
    // The envelope is untouched, so the signature still verifies. Only the
    // sibling `payload` field — which the signature does not cover — changed.
    const forged = JSON.stringify({
      envelope: parsed.envelope,
      payload: { job: 'DROP TABLE users', amount: 1_000_000_000 },
    })
    await expect(verifyQueueMessage(forged, { publicKey: kp.publicKey })).rejects.toThrow(
      /payload does not match the signed content/,
    )
  })

  it('rejects a payload removed entirely', async () => {
    const { kp, parsed } = await signed()
    const forged = JSON.stringify({ envelope: parsed.envelope })
    await expect(verifyQueueMessage(forged, { publicKey: kp.publicKey })).rejects.toThrow(
      /payload does not match the signed content/,
    )
  })

  it('rejects a subtly altered numeric field', async () => {
    const { kp, parsed } = await signed()
    const forged = JSON.stringify({
      envelope: parsed.envelope,
      payload: { job: 'reindex', amount: 11 },
    })
    await expect(verifyQueueMessage(forged, { publicKey: kp.publicKey })).rejects.toThrow(
      /payload does not match the signed content/,
    )
  })

  it('still accepts an untouched message and returns the signed payload', async () => {
    const { kp, message } = await signed()
    const out = await verifyQueueMessage<{ job: string; amount: number }>(message, {
      publicKey: kp.publicKey,
    })
    expect(out.payload).toEqual({ job: 'reindex', amount: 10 })
    expect(JSON.stringify(out.payload)).toBe(out.envelope.body.content)
  })

  it('round-trips a string payload', async () => {
    const kp = await generateEd25519KeypairBase64Url()
    const message = await signQueueMessage('plain-text-job', {
      sender: 'a@b.test', privateKey: kp.privateKey, keyId: 'k1', ttlMs: 60_000,
    })
    const out = await verifyQueueMessage<string>(message, { publicKey: kp.publicKey })
    expect(out.payload).toBe('plain-text-job')
  })

  it('verifyQueueBatch inherits the check', async () => {
    const { kp, message, parsed } = await signed()
    const forged = JSON.stringify({ envelope: parsed.envelope, payload: { job: 'evil' } })
    const results = await verifyQueueBatch([message, forged], { publicKey: kp.publicKey })
    expect(results[0].ok).toBe(true)
    expect(results[1].ok).toBe(false)
  })
})
