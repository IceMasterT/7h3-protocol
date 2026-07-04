import { describe, it, expect, vi } from 'vitest'
import {
  verifyHttpEnvelope,
  signHttpRequest,
  signHttpRequestHmac,
  createHttpMiddleware,
  signFetchRequest,
  createSignedFetchRequest,
  DEFAULT_HEADER,
} from './httpBinding'
import { createStaticKeyRegistry, type KeyRegistry } from './keyRegistry'
import {
  generateEd25519KeypairBase64Url,
  createEnvelope,
  signEnvelopeEd25519,
  signEnvelopeHmac,
  type ProtocolEnvelope,
} from './protocol'

// Helper: build a static KeyRegistry that also holds HMAC shared secrets
function createHmacKeyRegistry(secrets: Record<string, string>): KeyRegistry {
  return {
    async getPublicKey() { return null },
    async getSharedSecret(keyId) { return secrets[keyId] ?? null },
  }
}

describe('verifyHttpEnvelope', () => {
  it('returns missing-header when header is absent', async () => {
    const registry = createStaticKeyRegistry({})
    const result = await verifyHttpEnvelope({}, { keyRegistry: registry })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('missing-header')
  })

  it('returns missing-header when header value is undefined', async () => {
    const registry = createStaticKeyRegistry({})
    const result = await verifyHttpEnvelope(
      { [DEFAULT_HEADER]: undefined },
      { keyRegistry: registry },
    )
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('missing-header')
  })

  it('returns malformed-envelope for invalid JSON', async () => {
    const registry = createStaticKeyRegistry({})
    const result = await verifyHttpEnvelope(
      { [DEFAULT_HEADER]: 'not-json' },
      { keyRegistry: registry },
    )
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('malformed-envelope')
      expect(result.detail).toContain('JSON parse failed')
    }
  })

  it('returns malformed-envelope when required fields are missing', async () => {
    const registry = createStaticKeyRegistry({})
    const result = await verifyHttpEnvelope(
      { [DEFAULT_HEADER]: JSON.stringify({ header: {} }) },
      { keyRegistry: registry },
    )
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('malformed-envelope')
  })

  it('passes a valid Ed25519 signed envelope', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-alice'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const env = createEnvelope({ sender, intent: 'PING', content: 'hello', ttlMs: 60_000 })
    const signed = await signEnvelopeEd25519(env, privateKey)
    const headers = { [DEFAULT_HEADER]: JSON.stringify(signed) }

    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.envelope.header.sender).toBe(sender)
  })

  it('returns invalid-signature when envelope is tampered', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-bob'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const env = createEnvelope({ sender, intent: 'PING', content: 'hello', ttlMs: 60_000 })
    const signed = await signEnvelopeEd25519(env, privateKey)

    // Tamper with the content after signing
    const tampered: ProtocolEnvelope = {
      ...signed,
      body: { ...signed.body, content: 'tampered-content' },
    }
    const headers = { [DEFAULT_HEADER]: JSON.stringify(tampered) }

    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('invalid-signature')
  })

  it('returns unknown-sender when sender is not in registry', async () => {
    const { privateKey } = await generateEd25519KeypairBase64Url()
    const registry = createStaticKeyRegistry({}) // empty registry

    const env = createEnvelope({ sender: 'unknown-agent', intent: 'PING', content: 'hi', ttlMs: 60_000 })
    const signed = await signEnvelopeEd25519(env, privateKey)
    const headers = { [DEFAULT_HEADER]: JSON.stringify(signed) }

    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('unknown-sender')
      expect(result.detail).toBe('unknown-agent')
    }
  })

  it('returns ttl-expired for an expired envelope', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-expired'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    // Create envelope with past timestamp so it is already expired
    const pastNow = Date.now() - 120_000 // 2 minutes ago
    const env = createEnvelope({
      sender,
      intent: 'PING',
      content: 'hello',
      ttlMs: 1_000,      // 1 second TTL
      nowMs: pastNow,
    })
    const signed = await signEnvelopeEd25519(env, privateKey)
    const headers = { [DEFAULT_HEADER]: JSON.stringify(signed) }

    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry, strictTtl: true })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('ttl-expired')
  })

  it('skips TTL check when strictTtl is false', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-nostrictttl'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const pastNow = Date.now() - 120_000
    const env = createEnvelope({
      sender,
      intent: 'PING',
      content: 'hello',
      ttlMs: 1_000,
      nowMs: pastNow,
    })
    const signed = await signEnvelopeEd25519(env, privateKey)
    const headers = { [DEFAULT_HEADER]: JSON.stringify(signed) }

    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry, strictTtl: false })
    expect(result.ok).toBe(true)
  })
})

describe('signHttpRequest + verifyHttpEnvelope round trip (Ed25519)', () => {
  it('signs and verifies successfully', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-roundtrip'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const env = createEnvelope({ sender, intent: 'TASK', content: 'do something', ttlMs: 60_000 })
    const { headers } = await signHttpRequest(env, privateKey)

    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.envelope.header.sender).toBe(sender)
      expect(result.envelope.body.intent).toBe('TASK')
    }
  })

  it('uses custom header name when provided', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-custom-header'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })
    const customHeader = 'x-custom-sig'

    const env = createEnvelope({ sender, intent: 'PING', content: 'hi', ttlMs: 60_000 })
    const { headers } = await signHttpRequest(env, privateKey, { headerName: customHeader })

    expect(headers[customHeader]).toBeDefined()
    expect(headers[DEFAULT_HEADER]).toBeUndefined()

    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry, headerName: customHeader })
    expect(result.ok).toBe(true)
  })
})

describe('createHttpMiddleware', () => {
  it('calls next() when envelope is valid', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-middleware'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const env = createEnvelope({ sender, intent: 'PING', content: 'hi', ttlMs: 60_000 })
    const signed = await signEnvelopeEd25519(env, privateKey)
    const req = { headers: { [DEFAULT_HEADER]: JSON.stringify(signed) } }

    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() }
    const next = vi.fn()

    const middleware = createHttpMiddleware({ keyRegistry: registry })
    await middleware(req, res as any, next)

    expect(next).toHaveBeenCalledOnce()
    expect(next).toHaveBeenCalledWith()  // no error argument
    expect(res.status).not.toHaveBeenCalled()
    // The envelope should be attached to req
    expect((req as any)['7h3Envelope']).toBeDefined()
  })

  it('returns 401 and does not call next() when envelope is missing', async () => {
    const registry = createStaticKeyRegistry({})
    const req = { headers: {} }
    const jsonMock = vi.fn()
    const res = { status: vi.fn().mockReturnValue({ json: jsonMock }) }
    const next = vi.fn()

    const middleware = createHttpMiddleware({ keyRegistry: registry })
    await middleware(req, res as any, next)

    expect(res.status).toHaveBeenCalledWith(401)
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({ reason: 'missing-header' }),
    )
    expect(next).not.toHaveBeenCalled()
  })

  it('returns 401 for invalid signature', async () => {
    const { publicKey } = await generateEd25519KeypairBase64Url()
    const { privateKey: otherPrivateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-bad-sig'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const env = createEnvelope({ sender, intent: 'PING', content: 'hi', ttlMs: 60_000 })
    // Sign with wrong key
    const signed = await signEnvelopeEd25519(env, otherPrivateKey)
    const req = { headers: { [DEFAULT_HEADER]: JSON.stringify(signed) } }

    const jsonMock = vi.fn()
    const res = { status: vi.fn().mockReturnValue({ json: jsonMock }) }
    const next = vi.fn()

    const middleware = createHttpMiddleware({ keyRegistry: registry })
    await middleware(req, res as any, next)

    expect(res.status).toHaveBeenCalledWith(401)
    expect(next).not.toHaveBeenCalled()
  })
})

describe('signFetchRequest', () => {
  it('adds the envelope header to a Request', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-fetch'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const env = createEnvelope({ sender, intent: 'TASK', content: 'fetch-task', ttlMs: 60_000 })
    const originalRequest = new Request('https://example.com/api')
    const signedRequest = await signFetchRequest(originalRequest, env, privateKey)

    expect(signedRequest.headers.get(DEFAULT_HEADER)).not.toBeNull()

    // Parse and verify
    const headerVal = signedRequest.headers.get(DEFAULT_HEADER)!
    const headers = { [DEFAULT_HEADER]: headerVal }
    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
    expect(result.ok).toBe(true)
  })

  it('preserves existing headers on the Request', async () => {
    const { privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-headers'
    const env = createEnvelope({ sender, intent: 'PING', content: 'hi', ttlMs: 60_000 })
    const originalRequest = new Request('https://example.com/api', {
      headers: { 'Authorization': 'Bearer token123', 'Content-Type': 'application/json' },
    })
    const signedRequest = await signFetchRequest(originalRequest, env, privateKey)

    expect(signedRequest.headers.get('Authorization')).toBe('Bearer token123')
    expect(signedRequest.headers.get('Content-Type')).toBe('application/json')
    expect(signedRequest.headers.get(DEFAULT_HEADER)).not.toBeNull()
  })
})

describe('HMAC round trip', () => {
  it('signs with HMAC and verifies successfully', async () => {
    const secret = 'super-secret-hmac-key'
    const keyId = 'hmac-key-1'
    const sender = 'agent-hmac'
    const registry = createHmacKeyRegistry({ [keyId]: secret })

    const env = createEnvelope({ sender, intent: 'TASK', content: 'hmac task', ttlMs: 60_000 })
    const { headers } = await signHttpRequestHmac(env, secret, keyId)

    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.envelope.header.sender).toBe(sender)
      expect(result.envelope.signature?.alg).toBe('HS256')
    }
  })

  it('returns invalid-signature when HMAC tampered', async () => {
    const secret = 'super-secret-hmac-key'
    const keyId = 'hmac-key-2'
    const sender = 'agent-hmac-tamper'
    const registry = createHmacKeyRegistry({ [keyId]: secret })

    const env = createEnvelope({ sender, intent: 'TASK', content: 'hmac task', ttlMs: 60_000 })
    const signed = await signEnvelopeHmac(env, secret, keyId)

    const tampered: ProtocolEnvelope = {
      ...signed,
      body: { ...signed.body, content: 'tampered' },
    }
    const headers = { [DEFAULT_HEADER]: JSON.stringify(tampered) }

    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('invalid-signature')
  })

  it('returns unknown-sender when HMAC keyId not in registry', async () => {
    const secret = 'super-secret-hmac-key'
    const keyId = 'hmac-key-missing'
    const sender = 'agent-hmac-unknown'
    const registry = createHmacKeyRegistry({}) // empty

    const env = createEnvelope({ sender, intent: 'PING', content: 'hi', ttlMs: 60_000 })
    const signed = await signEnvelopeHmac(env, secret, keyId)
    const headers = { [DEFAULT_HEADER]: JSON.stringify(signed) }

    const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('unknown-sender')
      expect(result.detail).toBe(keyId)
    }
  })
})

describe('createSignedFetchRequest', () => {
  it('creates a signed fetch request with correct sender', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'agent-create-signed'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const originalRequest = new Request('https://example.com/api/task')
    const signedRequest = await createSignedFetchRequest(originalRequest, {
      privateKey,
      sender,
      ttlMs: 60_000,
    })

    const headerVal = signedRequest.headers.get(DEFAULT_HEADER)
    expect(headerVal).not.toBeNull()

    const result = await verifyHttpEnvelope(
      { [DEFAULT_HEADER]: headerVal! },
      { keyRegistry: registry },
    )
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.envelope.header.sender).toBe(sender)
      expect(result.envelope.body.intent).toBe('TASK')
    }
  })
})
