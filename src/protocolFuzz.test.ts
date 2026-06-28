import { describe, expect, it } from 'vitest'
import { canonicalizeEnvelope, createEnvelope, signEnvelopeHmac, verifyEnvelopeHmac } from './protocol'
import { InMemoryReplayCache } from './protocolReplay'
import { decodeEnvelope, encodeEnvelope, receiveEnvelope } from './protocolTransport'

function seededRandom(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (1664525 * state + 1013904223) >>> 0
    return state / 0xffffffff
  }
}

function randomText(rand: () => number, length: number): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789:-_/'
  let out = ''
  for (let i = 0; i < length; i += 1) {
    out += alphabet[Math.floor(rand() * alphabet.length)]
  }
  return out
}

describe('AIP property and fuzz checks', () => {
  it('keeps canonicalization and signed roundtrip stable for random envelopes', async () => {
    const rand = seededRandom(0xdecafbad)

    for (let i = 0; i < 200; i += 1) {
      const nowMs = 1_700_000_000_000 + i
      const envelope = createEnvelope({
        sender: `agent.${randomText(rand, 6)}`,
        recipient: rand() > 0.5 ? `agent.${randomText(rand, 5)}` : undefined,
        intent: rand() > 0.5 ? 'TASK' : 'RESULT',
        content: randomText(rand, 64),
        capability: rand() > 0.6 ? `task.${randomText(rand, 5)}` : undefined,
        correlationId: rand() > 0.4 ? `corr-${randomText(rand, 8)}` : undefined,
        messageId: `fuzz-${i}-${randomText(rand, 8)}`,
        nonce: `n-${i}-${randomText(rand, 8)}`,
        nowMs,
        ttlMs: 10_000 + Math.floor(rand() * 20_000),
      })

      const canonicalA = canonicalizeEnvelope(envelope)
      const canonicalB = canonicalizeEnvelope({ header: envelope.header, body: envelope.body })
      expect(canonicalA).toBe(canonicalB)

      const signed = await signEnvelopeHmac(envelope, 'fuzz-shared-secret', 'fuzz-k1')
      expect(await verifyEnvelopeHmac(signed, 'fuzz-shared-secret')).toBe(true)

      const encoded = encodeEnvelope(signed, rand() > 0.5 ? 'compact' : 'json')
      const decoded = decodeEnvelope(encoded)
      expect(decoded.ok).toBe(true)
      expect(decoded.envelope).toEqual(signed)

      const received = await receiveEnvelope(encoded, {
        nowMs: nowMs + 1,
        replayCache: new InMemoryReplayCache(),
        secretResolver: async () => 'fuzz-shared-secret',
      })
      expect(received.ok).toBe(true)
    }
  })

  it('rejects fuzzed malformed or tampered payloads', async () => {
    const rand = seededRandom(0xabad1dea)
    const base = await signEnvelopeHmac(
      createEnvelope({
        sender: 'agent.fuzz',
        recipient: 'agent.verify',
        intent: 'TASK',
        content: 'fuzz-base',
        messageId: 'fuzz-base-1',
        nonce: 'fuzz-base-n1',
        nowMs: 1_700_000_001_000,
        ttlMs: 60_000,
      }),
      'fuzz-shared-secret',
      'fuzz-k1',
    )

    const malformedPayloads = ['{', '[]', '{"v":"7h3/0.1"}', '{"header":{},"body":{}}', '{"hello":"world"}']
    for (const raw of malformedPayloads) {
      const result = await receiveEnvelope(raw, {
        nowMs: 1_700_000_001_001,
        replayCache: new InMemoryReplayCache(),
        secretResolver: async () => 'fuzz-shared-secret',
      })
      expect(result.ok).toBe(false)
    }

    for (let i = 0; i < 120; i += 1) {
      const compact = JSON.parse(encodeEnvelope(base, 'compact')) as {
        sig?: { a?: string; k: string; v: string }
      }
      if (!compact.sig) throw new Error('expected signature in compact envelope')

      const index = Math.floor(rand() * compact.sig.v.length)
      const current = compact.sig.v[index] ?? 'A'
      const replacement = current === 'A' ? 'B' : 'A'
      compact.sig.v = `${compact.sig.v.slice(0, index)}${replacement}${compact.sig.v.slice(index + 1)}`
      const tampered = JSON.stringify(compact)

      const result = await receiveEnvelope(tampered, {
        nowMs: 1_700_000_001_001,
        replayCache: new InMemoryReplayCache(),
        secretResolver: async () => 'fuzz-shared-secret',
      })
      expect(result.ok).toBe(false)
      expect(result.diagnostics.some((d) => d.message === 'Signature verification failed')).toBe(true)
    }
  })
})
