import { describe, expect, it } from 'vitest'
import {
  canonicalizeEnvelope,
  createEnvelope,
  generateEd25519KeypairBase64Url,
  signCanonicalPayloadHmac,
  signEnvelopeEd25519,
  signEnvelopeHmac,
  verifyCanonicalPayloadEd25519,
  validateEnvelope,
  MAX_TTL_MS,
  verifyCanonicalPayloadHmac,
  verifyEnvelopeEd25519,
  verifyEnvelopeHmac,
} from './protocol'

describe('GLUV AIP protocol', () => {
  it('uses stable canonical field order', () => {
    const envelope = createEnvelope({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'TASK',
      content: 'compute route',
      capability: 'task.plan',
      correlationId: 'c-1',
      messageId: 'm0',
      nonce: 'n0',
      nowMs: 500,
      ttlMs: 10_000,
    })

    expect(canonicalizeEnvelope(envelope)).toBe(
      '{"body":{"capability":"task.plan","content":"compute route","correlationId":"c-1","intent":"TASK"},"header":{"messageId":"m0","nonce":"n0","recipient":"agent.beta","sender":"agent.alpha","timestampMs":500,"ttlMs":10000,"version":"7h3/0.1"}}',
    )
  })

  it('canonicalizes envelopes deterministically', () => {
    const envelope = createEnvelope({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'TASK',
      content: 'compute route',
      messageId: 'm1',
      nonce: 'n1',
      nowMs: 1000,
      ttlMs: 10000,
    })

    const c1 = canonicalizeEnvelope(envelope)
    const c2 = canonicalizeEnvelope({ header: envelope.header, body: envelope.body })
    expect(c1).toBe(c2)
  })

  it('signs and verifies with HMAC', async () => {
    const unsigned = createEnvelope({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'hello',
      messageId: 'm2',
      nonce: 'n2',
      nowMs: 2000,
      ttlMs: 10000,
    })

    const signed = await signEnvelopeHmac(unsigned, 'secret-key', 'dev-1')
    const ok = await verifyEnvelopeHmac(signed, 'secret-key')
    expect(ok).toBe(true)

    const tampered = {
      ...signed,
      body: {
        ...signed.body,
        content: 'tampered',
      },
    }
    const bad = await verifyEnvelopeHmac(tampered, 'secret-key')
    expect(bad).toBe(false)
  })

  it('signs and verifies canonical payload directly', async () => {
    const unsigned = createEnvelope({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'hello',
      messageId: 'm2b',
      nonce: 'n2b',
      nowMs: 2000,
      ttlMs: 10000,
    })

    const payload = canonicalizeEnvelope(unsigned)
    const sig = await signCanonicalPayloadHmac(payload, 'secret-key')
    expect(await verifyCanonicalPayloadHmac(payload, sig, 'secret-key')).toBe(true)
    expect(await verifyCanonicalPayloadHmac(`${payload}x`, sig, 'secret-key')).toBe(false)
  })

  it('signs and verifies with Ed25519', async () => {
    const keys = await generateEd25519KeypairBase64Url()
    const unsigned = createEnvelope({
      sender: 'agent.alpha',
      intent: 'TASK',
      content: 'route:ed25519',
      messageId: 'm-ed1',
      nonce: 'n-ed1',
      nowMs: 3000,
      ttlMs: 10000,
    })

    const signed = await signEnvelopeEd25519(unsigned, keys.privateKey, 'ed-1')
    const ok = await verifyEnvelopeEd25519(signed, keys.publicKey)
    expect(ok).toBe(true)

    const tampered = {
      ...signed,
      body: {
        ...signed.body,
        content: 'tampered',
      },
    }
    const bad = await verifyEnvelopeEd25519(tampered, keys.publicKey)
    expect(bad).toBe(false)
  })

  it('signs and verifies Ed25519 canonical payload directly', async () => {
    const keys = await generateEd25519KeypairBase64Url()
    const unsigned = createEnvelope({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'hello-ed25519',
      messageId: 'm-ed2',
      nonce: 'n-ed2',
      nowMs: 3100,
      ttlMs: 10000,
    })

    const payload = canonicalizeEnvelope(unsigned)
    const sig = await signEnvelopeEd25519(unsigned, keys.privateKey, 'ed-2')
    expect(sig.signature?.alg).toBe('ED25519')
    expect(await verifyCanonicalPayloadEd25519(payload, sig.signature?.value ?? '', keys.publicKey)).toBe(true)
    expect(await verifyCanonicalPayloadEd25519(`${payload}x`, sig.signature?.value ?? '', keys.publicKey)).toBe(false)
  })

  it('flags expired messages', () => {
    const unsigned = createEnvelope({
      sender: 'agent.alpha',
      intent: 'RESULT',
      content: 'done',
      messageId: 'm3',
      nonce: 'n3',
      nowMs: 0,
      ttlMs: 100,
    })
    const diagnostics = validateEnvelope({ ...unsigned }, 500)
    expect(diagnostics.some((d) => d.message === 'Message TTL expired')).toBe(true)
  })

  it('flags ttlMs above the 24h ceiling', () => {
    const unsigned = createEnvelope({
      sender: 'agent.alpha',
      intent: 'TASK',
      content: 'long-lived',
      messageId: 'm4',
      nonce: 'n4',
      nowMs: 0,
      ttlMs: MAX_TTL_MS + 1,
    })
    const diagnostics = validateEnvelope({ ...unsigned }, 0)
    expect(diagnostics.some((d) => d.message.includes('exceeds maximum'))).toBe(true)

    // Exactly at the ceiling is still valid
    const atCeiling = createEnvelope({
      sender: 'agent.alpha',
      intent: 'TASK',
      content: 'ok',
      messageId: 'm5',
      nonce: 'n5',
      nowMs: 0,
      ttlMs: MAX_TTL_MS,
    })
    expect(validateEnvelope({ ...atCeiling }, 0).filter((d) => d.level === 'error')).toEqual([])
  })
})
