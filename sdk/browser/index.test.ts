import { describe, it, expect } from 'vitest'
import {
  generateKeypair,
  canonicalizeEnvelope,
  createEnvelope,
  signEnvelope,
  verifyEnvelope,
  signRequest,
  isEnvelopeExpired,
  validateEnvelope,
  ENVELOPE_HEADER,
  WIRE_VERSION,
  MAX_TTL_MS,
  MAX_CLOCK_SKEW_MS,
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

describe('validateEnvelope — parity with the TypeScript, Python, Rust and Go SDKs', () => {
  const now = 1_700_000_000_000
  const envelope = (over: Record<string, unknown> = {}) =>
    ({
      header: {
        version: '7h3/0.1', messageId: 'm1', timestampMs: now,
        ttlMs: 60_000, sender: 'a@b.test', nonce: 'abc123', ...over,
      },
      body: { intent: 'TASK', content: 'x' },
    }) as never

  const errors = (over: Record<string, unknown> = {}) =>
    validateEnvelope(envelope(over), now).filter((d) => d.level === 'error').map((d) => d.message)

  it('accepts a well-formed envelope', () => {
    expect(errors()).toEqual([])
  })

  it('rejects a ttl above the 24h ceiling', () => {
    expect(errors({ ttlMs: MAX_TTL_MS + 1 })).toContain(`ttlMs exceeds maximum allowed ${MAX_TTL_MS} ms`)
  })

  it('rejects a post-dated timestamp, so the ttl ceiling actually bounds something', () => {
    // A year ahead plus a legal 24h ttl would otherwise stay valid for a year.
    expect(errors({ timestampMs: now + 31_536_000_000 }).some((m) => m.includes('in the future'))).toBe(true)
    expect(errors({ timestampMs: now + MAX_CLOCK_SKEW_MS - 1_000 })).toEqual([])
  })

  it('rejects non-finite numbers rather than letting them defeat every check', () => {
    for (const bad of [NaN, Infinity, -Infinity]) {
      expect(errors({ ttlMs: bad })).toContain('ttlMs must be a finite number')
      expect(errors({ timestampMs: bad })).toContain('timestampMs must be a finite number')
    }
  })

  it('rejects a missing or non-string nonce, sender or messageId', () => {
    for (const bad of ['', '   ', undefined, null, 0, false, {}]) {
      expect(errors({ nonce: bad }).some((m) => m.includes('Missing nonce'))).toBe(true)
      expect(errors({ sender: bad })).toContain('Missing sender identity')
      expect(errors({ messageId: bad })).toContain('Missing messageId')
    }
  })

  it('rejects a foreign wire version', () => {
    expect(errors({ version: '7h3/9.9' })).toContain("Unsupported protocol version '7h3/9.9'")
  })

  it('rejects an expired envelope', () => {
    expect(errors({ timestampMs: now - 120_000, ttlMs: 60_000 })).toContain('Message TTL expired')
  })
})

describe('isEnvelopeExpired — fails closed', () => {
  const now = 1_700_000_000_000
  const env = (over: Record<string, unknown>) =>
    ({ header: { version: '7h3/0.1', messageId: 'm', sender: 's', nonce: 'n', timestampMs: now, ttlMs: 60_000, ...over }, body: { intent: 'TASK', content: 'x' } }) as never

  it('treats a non-finite timestamp or ttl as expired', () => {
    // NaN + NaN < now is false, so naive arithmetic would report "not expired".
    expect(isEnvelopeExpired(env({ ttlMs: NaN }), now)).toBe(true)
    expect(isEnvelopeExpired(env({ timestampMs: NaN }), now)).toBe(true)
    expect(isEnvelopeExpired(env({ ttlMs: Infinity }), now)).toBe(true)
  })

  it('still reports live and expired envelopes correctly', () => {
    expect(isEnvelopeExpired(env({}), now)).toBe(false)
    expect(isEnvelopeExpired(env({ timestampMs: now - 120_000 }), now)).toBe(true)
  })
})
