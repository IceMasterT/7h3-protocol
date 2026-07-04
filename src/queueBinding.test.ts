import { describe, it, expect, beforeAll } from 'vitest'
import { generateEd25519KeypairBase64Url } from './protocol'
import { signQueueMessage, verifyQueueMessage, verifyQueueBatch } from './queueBinding'

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
