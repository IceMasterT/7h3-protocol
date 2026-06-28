import { describe, it, expect } from 'vitest'
import {
  generateKeypair,
  canonicalizeEnvelope,
  createEnvelope,
  signEnvelope,
  verifyEnvelope,
  signRequest,
  isEnvelopeExpired,
  ENVELOPE_HEADER,
  WIRE_VERSION,
  type BrowserEnvelopeHeader,
  type BrowserEnvelopeBody,
} from './index.ts'

describe('Browser SDK', () => {
  // Test 1: generateKeypair produces non-empty strings
  it('generateKeypair produces non-empty strings', async () => {
    const kp = await generateKeypair()
    expect(typeof kp.publicKey).toBe('string')
    expect(kp.publicKey.length).toBeGreaterThan(0)
    expect(typeof kp.privateKey).toBe('string')
    expect(kp.privateKey.length).toBeGreaterThan(0)
  })

  // Test 2: canonicalizeEnvelope matches exact conformance vector
  it('canonicalizeEnvelope matches conformance vector', () => {
    const header: BrowserEnvelopeHeader = {
      version: '7h3/0.1',
      messageId: 'vec-1',
      nonce: 'nonce-vec-1',
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      timestampMs: 1712500000000,
      ttlMs: 60000,
    }
    const body: BrowserEnvelopeBody = {
      intent: 'TASK',
      content: 'route:alpha->beta',
      capability: 'task.plan',
      correlationId: 'corr-1',
    }
    const expected =
      '{"body":{"capability":"task.plan","content":"route:alpha->beta","correlationId":"corr-1","intent":"TASK"},"header":{"messageId":"vec-1","nonce":"nonce-vec-1","recipient":"agent.beta","sender":"agent.alpha","timestampMs":1712500000000,"ttlMs":60000,"version":"7h3/0.1"}}'
    expect(canonicalizeEnvelope({ header, body })).toBe(expected)
  })

  // Test 3: canonicalizeEnvelope with no optional fields
  it('canonicalizeEnvelope omits undefined optional fields', () => {
    const header: BrowserEnvelopeHeader = {
      version: '7h3/0.1',
      messageId: 'msg-1',
      nonce: 'n1',
      sender: 'agent.x',
      timestampMs: 1712500000000,
      ttlMs: 30000,
    }
    const body: BrowserEnvelopeBody = {
      intent: 'PING',
      content: 'hello',
    }
    const result = canonicalizeEnvelope({ header, body })
    const parsed = JSON.parse(result)
    expect(parsed.header.recipient).toBeUndefined()
    expect(parsed.body.capability).toBeUndefined()
    expect(parsed.body.correlationId).toBeUndefined()
    // Verify the raw string doesn't include those keys
    expect(result).not.toContain('"recipient"')
    expect(result).not.toContain('"capability"')
    expect(result).not.toContain('"correlationId"')
  })

  // Test 4: createEnvelope produces correct structure
  it('createEnvelope produces correct structure', () => {
    const env = createEnvelope({
      sender: 'agent.test',
      body: { intent: 'TASK', content: 'do work' },
    })
    expect(env.header.version).toBe(WIRE_VERSION)
    expect(typeof env.header.messageId).toBe('string')
    expect(env.header.messageId.length).toBeGreaterThan(0)
    expect(env.body.intent).toBe('TASK')
    expect(env.header.sender).toBe('agent.test')
    expect(env.header.ttlMs).toBe(60_000)
  })

  // Test 5: signEnvelope + verifyEnvelope round trip
  it('signEnvelope + verifyEnvelope round trip', async () => {
    const kp = await generateKeypair()
    const env = createEnvelope({
      sender: 'agent.a',
      body: { intent: 'PING', content: 'test' },
    })
    const signed = await signEnvelope(env, kp.privateKey)
    expect(signed.signature).toBeDefined()
    expect(signed.signature?.alg).toBe('ED25519')
    const valid = await verifyEnvelope(signed, kp.publicKey)
    expect(valid).toBe(true)
  })

  // Test 6: verifyEnvelope: tampered body returns false
  it('verifyEnvelope: tampered body returns false', async () => {
    const kp = await generateKeypair()
    const env = createEnvelope({
      sender: 'agent.a',
      body: { intent: 'PING', content: 'original' },
    })
    const signed = await signEnvelope(env, kp.privateKey)
    const tampered = {
      ...signed,
      body: { ...signed.body, content: 'tampered' },
    }
    const valid = await verifyEnvelope(tampered, kp.publicKey)
    expect(valid).toBe(false)
  })

  // Test 7: verifyEnvelope: wrong key returns false
  it('verifyEnvelope: wrong key returns false', async () => {
    const kp1 = await generateKeypair()
    const kp2 = await generateKeypair()
    const env = createEnvelope({
      sender: 'agent.a',
      body: { intent: 'PING', content: 'test' },
    })
    const signed = await signEnvelope(env, kp1.privateKey)
    const valid = await verifyEnvelope(signed, kp2.publicKey)
    expect(valid).toBe(false)
  })

  // Test 8: signRequest: produces Request with x-7h3-envelope header set
  it('signRequest: produces Request with x-7h3-envelope header', async () => {
    const kp = await generateKeypair()
    const req = new Request('https://example.com/api')
    const signed = await signRequest(req, {
      sender: 'agent.client',
      privateKey: kp.privateKey,
    })
    const headerVal = signed.headers.get(ENVELOPE_HEADER)
    expect(headerVal).not.toBeNull()
    expect(typeof headerVal).toBe('string')
    const parsed = JSON.parse(headerVal!)
    expect(parsed.signature).toBeDefined()
    expect(parsed.header.sender).toBe('agent.client')
  })

  // Test 9: isEnvelopeExpired: returns true for past timestamp
  it('isEnvelopeExpired: returns true for past timestamp', () => {
    const past = Date.now() - 120_000
    const env = {
      header: {
        version: '7h3/0.1' as const,
        messageId: 'x',
        nonce: 'y',
        sender: 'agent.z',
        timestampMs: past,
        ttlMs: 60_000,
      },
      body: { intent: 'PING' as const, content: 'old' },
    }
    expect(isEnvelopeExpired(env)).toBe(true)
  })
})
