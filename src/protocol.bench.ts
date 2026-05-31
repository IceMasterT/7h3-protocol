import { bench, describe } from 'vitest'
import { canonicalizeEnvelope, createEnvelope, signEnvelopeHmac, verifyEnvelopeHmac } from './protocol'
import { decodeEnvelope, encodeEnvelope } from './protocolTransport'

const unsigned = createEnvelope({
  sender: 'agent.alpha',
  recipient: 'agent.beta',
  intent: 'TASK',
  content: 'route-optimize:alpha-beta',
  capability: 'task.plan',
  correlationId: 'corr-1',
  messageId: 'bench-1',
  nonce: 'bench-nonce',
  nowMs: 1_000,
  ttlMs: 120_000,
})

describe('protocol throughput', () => {
  bench('canonicalize envelope', () => {
    canonicalizeEnvelope(unsigned)
  })

  bench('encode/decode envelope json', () => {
    const encoded = encodeEnvelope({ ...unsigned })
    decodeEnvelope(encoded)
  })

  bench('encode/decode envelope compact', () => {
    const encoded = encodeEnvelope({ ...unsigned }, 'compact')
    decodeEnvelope(encoded)
  })

  bench('sign + verify envelope', async () => {
    const signed = await signEnvelopeHmac(unsigned, 'bench-secret', 'bench-k1')
    await verifyEnvelopeHmac(signed, 'bench-secret')
  })
})
