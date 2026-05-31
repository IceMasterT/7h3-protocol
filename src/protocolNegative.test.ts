import { describe, expect, it } from 'vitest'
import { createEnvelope, generateEd25519KeypairBase64Url, signEnvelopeEd25519, signEnvelopeHmac } from './protocol'
import { InMemoryReplayCache } from './protocolReplay'
import { decodeEnvelope, decodeEnvelopeBatch, encodeEnvelope, receiveEnvelope } from './protocolTransport'

describe('AIP negative corpus', () => {
  it('rejects invalid JSON envelopes', () => {
    const decoded = decodeEnvelope('{invalid-json')
    expect(decoded.ok).toBe(false)
    expect(decoded.diagnostics.some((d) => d.message === 'Invalid JSON envelope')).toBe(true)
  })

  it('rejects unknown envelope shape', () => {
    const decoded = decodeEnvelope(JSON.stringify({ hello: 'world' }))
    expect(decoded.ok).toBe(false)
    expect(decoded.diagnostics.some((d) => d.message.includes('shape is not recognized'))).toBe(true)
  })

  it('rejects batch payload that is not an array', () => {
    const decoded = decodeEnvelopeBatch(JSON.stringify({ not: 'array' }))
    expect(decoded).toHaveLength(1)
    expect(decoded[0]?.ok).toBe(false)
    expect(decoded[0]?.diagnostics.some((d) => d.message.includes('must be a JSON array'))).toBe(true)
  })

  it('rejects unsigned envelopes when signatures are required', async () => {
    const unsigned = createEnvelope({
      sender: 'agent.alpha',
      intent: 'TASK',
      content: 'unsigned',
      messageId: 'neg-unsigned-1',
      nonce: 'neg-unsigned-n1',
      nowMs: 1000,
      ttlMs: 60_000,
    })

    const result = await receiveEnvelope(encodeEnvelope(unsigned), {
      nowMs: 1001,
      replayCache: new InMemoryReplayCache(),
      requireSignature: true,
    })

    expect(result.ok).toBe(false)
    expect(result.diagnostics.some((d) => d.message === 'Missing signature')).toBe(true)
  })

  it('rejects signature when verification material algorithm mismatches', async () => {
    const signed = await signEnvelopeHmac(
      createEnvelope({
        sender: 'agent.alpha',
        intent: 'PING',
        content: 'alg-mismatch',
        messageId: 'neg-alg-1',
        nonce: 'neg-alg-n1',
        nowMs: 1000,
        ttlMs: 60_000,
      }),
      'shared-secret',
      'k1',
    )

    const result = await receiveEnvelope(encodeEnvelope(signed), {
      nowMs: 1001,
      replayCache: new InMemoryReplayCache(),
      signatureResolver: async () => ({ alg: 'ED25519', publicKey: 'not-a-valid-ed25519-key' }),
    })

    expect(result.ok).toBe(false)
    expect(result.diagnostics.some((d) => d.message === 'Signature verification failed')).toBe(true)
  })

  it('rejects ED25519 envelopes with missing verification material', async () => {
    const keys = await generateEd25519KeypairBase64Url()
    const signed = await signEnvelopeEd25519(
      createEnvelope({
        sender: 'agent.alpha',
        intent: 'TASK',
        content: 'needs-ed25519-material',
        messageId: 'neg-ed-1',
        nonce: 'neg-ed-n1',
        nowMs: 1000,
        ttlMs: 60_000,
      }),
      keys.privateKey,
      'ed-k1',
    )

    const result = await receiveEnvelope(encodeEnvelope(signed, 'compact'), {
      nowMs: 1001,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'shared-secret',
    })

    expect(result.ok).toBe(false)
    expect(result.diagnostics.some((d) => d.message.includes('No signature verification material'))).toBe(true)
  })
})
