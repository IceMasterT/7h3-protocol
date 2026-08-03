import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest'
import { createGateway, createProductionGateway, type GatewayRequest } from './gateway'
import { createStaticKeyRegistry } from './keyRegistry'
import { generateEd25519KeypairBase64Url, createEnvelope, signEnvelopeEd25519, signEnvelopeHmac } from './protocol'
import { SlidingWindowRateLimiter, type RateLimitStore } from './rateLimiter'
import type { ReplayStore } from './replayStores'

const noopReplayStore: ReplayStore = { check: async () => false }

let senderKeys: { publicKey: string; privateKey: string }
let gatewayKeys: { publicKey: string; privateKey: string }

beforeAll(async () => {
  senderKeys = await generateEd25519KeypairBase64Url()
  gatewayKeys = await generateEd25519KeypairBase64Url()
})

async function makeSignedHeader(sender: string, privateKey: string): Promise<Record<string, string>> {
  const envelope = createEnvelope({
    sender,
    intent: 'TASK',
    content: '/api/test',
    ttlMs: 60_000,
  })
  const signed = await signEnvelopeEd25519(envelope, privateKey)
  return { 'x-7h3-envelope': JSON.stringify(signed) }
}

function mockFetch(status: number, body: string, headers: Record<string, string> = {}) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    status,
    text: () => Promise.resolve(body),
    headers: new Headers({ 'content-type': 'application/json', ...headers }),
  }))
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('createGateway', () => {
  it('returns a gateway with getRateLimiter()', async () => {
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({}),
    })
    expect(typeof gw.getRateLimiter).toBe('function')
    expect(gw.getRateLimiter()).toBeDefined()
  })

  it('warns when a signature-requiring policy is configured with no replayStore', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({}),
      policies: [{ path: '/api/**', require: 'ed25519' }],
    })
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('no replayStore configured'))
    warnSpy.mockRestore()
  })

  it('does not warn when replayStore is configured', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({}),
      policies: [{ path: '/api/**', require: 'ed25519' }],
      replayStore: noopReplayStore,
    })
    expect(warnSpy).not.toHaveBeenCalled()
    warnSpy.mockRestore()
  })

  it('does not warn when every policy has require: none', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({}),
      policies: [{ path: '/health', require: 'none' }],
    })
    expect(warnSpy).not.toHaveBeenCalled()
    warnSpy.mockRestore()
  })
})

describe('createProductionGateway', () => {
  const baseConfig = {
    upstream: 'http://upstream',
    keyRegistry: createStaticKeyRegistry({}),
  }

  it('throws when defaultPolicy is not explicitly deny', () => {
    expect(() => createProductionGateway({ ...baseConfig, replayStore: noopReplayStore })).toThrow(
      /defaultPolicy must be explicitly 'deny'/,
    )
    expect(() =>
      createProductionGateway({ ...baseConfig, defaultPolicy: 'allow', replayStore: noopReplayStore }),
    ).toThrow(/defaultPolicy must be explicitly 'deny'/)
  })

  it('throws when replayStore is missing', () => {
    expect(() => createProductionGateway({ ...baseConfig, defaultPolicy: 'deny' })).toThrow(
      /replayStore is required/,
    )
  })

  it('returns a gateway when defaultPolicy is deny and replayStore is set', () => {
    const gw = createProductionGateway({ ...baseConfig, defaultPolicy: 'deny', replayStore: noopReplayStore })
    expect(typeof gw.verify).toBe('function')
  })
})

describe('verify()', () => {
  it('allows request when require=none policy matches', async () => {
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({}),
      policies: [{ path: '/health', require: 'none' }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/health', headers: {} }
    const outcome = await gw.verify(req)
    expect(outcome.ok).toBe(true)
  })

  it('allows when no policy matches and defaultPolicy=allow (default)', async () => {
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({}),
      policies: [],
    })
    const req: GatewayRequest = { method: 'GET', path: '/unknown', headers: {} }
    const outcome = await gw.verify(req)
    expect(outcome.ok).toBe(true)
  })

  it('denies with 403 when no policy matches and defaultPolicy=deny', async () => {
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({}),
      defaultPolicy: 'deny',
      policies: [],
    })
    const req: GatewayRequest = { method: 'GET', path: '/unknown', headers: {} }
    const outcome = await gw.verify(req)
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) {
      expect(outcome.status).toBe(403)
    }
  })

  it('returns 401 when envelope header is missing', async () => {
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519' }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers: {} }
    const outcome = await gw.verify(req)
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) {
      expect(outcome.status).toBe(401)
      expect(outcome.reason).toBe('missing-header')
    }
  })

  it('returns 401 when signature is invalid (wrong key)', async () => {
    const wrongKeys = await generateEd25519KeypairBase64Url()
    const headers = await makeSignedHeader('agent-a', wrongKeys.privateKey) // wrong private key
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }), // expects different key
      policies: [{ path: '/api/**', require: 'ed25519' }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers }
    const outcome = await gw.verify(req)
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) {
      expect(outcome.status).toBe(401)
    }
  })

  it('returns 401 for unknown sender', async () => {
    const headers = await makeSignedHeader('unknown-agent', senderKeys.privateKey)
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({}), // empty registry
      policies: [{ path: '/api/**', require: 'ed25519' }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers }
    const outcome = await gw.verify(req)
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) {
      expect(outcome.status).toBe(401)
    }
  })

  it('returns 403 when sender not in allowedSenders', async () => {
    const headers = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519', allowedSenders: ['agent-b'] }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers }
    const outcome = await gw.verify(req)
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) {
      expect(outcome.status).toBe(403)
      expect(outcome.reason).toBe('sender-denied')
    }
  })

  it('returns 429 when rate limited', async () => {
    const headers = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519', rateLimit: { requests: 1, windowMs: 10_000 } }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers }

    const first = await gw.verify(req)
    expect(first.ok).toBe(true)

    // Need fresh headers for second call (same sender, same policy)
    const headers2 = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const req2: GatewayRequest = { method: 'GET', path: '/api/data', headers: headers2 }
    const second = await gw.verify(req2)
    expect(second.ok).toBe(false)
    if (!second.ok) {
      expect(second.status).toBe(429)
    }
  })

  it('rate limit persists across gateway rebuilds when a shared rateLimitStore is used', async () => {
    // Regression test for a critical bug: serverless/edge deployments (e.g. a
    // Workers fetch handler) rebuild the gateway on every request, so an
    // in-memory limiter resets every time and never actually limits. A
    // persistent rateLimitStore must keep enforcing the limit regardless of
    // how many separate Gateway instances are constructed.
    const store = new SlidingWindowRateLimiter()
    const rateLimitStore: RateLimitStore = {
      consume: (key, policy) => Promise.resolve(store.consume(key, policy)),
    }
    const gatewayConfig = {
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**' as const, require: 'ed25519' as const, rateLimit: { requests: 1, windowMs: 10_000 } }],
      rateLimitStore,
    }

    const gw1 = createGateway(gatewayConfig)
    const headers1 = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const first = await gw1.verify({ method: 'GET', path: '/api/data', headers: headers1 })
    expect(first.ok).toBe(true)

    // A brand-new Gateway instance (own fresh in-memory limiter) sharing the
    // same rateLimitStore must still see agent-a as rate-limited.
    const gw2 = createGateway(gatewayConfig)
    const headers2 = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const second = await gw2.verify({ method: 'GET', path: '/api/data', headers: headers2 })
    expect(second.ok).toBe(false)
    if (!second.ok) {
      expect(second.status).toBe(429)
    }
  })

  it('returns 401 when require=ed25519 but HMAC envelope provided', async () => {
    const sharedSecret = 'my-hmac-secret'
    const keyId = 'hmac-key-1'
    const envelope = createEnvelope({ sender: 'agent-a', intent: 'TASK', content: '/api/test', ttlMs: 60_000 })
    const signed = await signEnvelopeHmac(envelope, sharedSecret, keyId)
    const headers = { 'x-7h3-envelope': JSON.stringify(signed) }

    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: {
        async getPublicKey() { return null },
        async getSharedSecret() { return sharedSecret },
      },
      policies: [{ path: '/api/**', require: 'ed25519' }], // expects ed25519, got hmac
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers }
    const outcome = await gw.verify(req)
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) {
      expect(outcome.status).toBe(401)
    }
  })

  it('ok verify includes sender', async () => {
    const headers = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519' }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers }
    const outcome = await gw.verify(req)
    expect(outcome.ok).toBe(true)
    if (outcome.ok) {
      expect(outcome.sender).toBe('agent-a')
    }
  })
})

describe('handle()', () => {
  it('returns 401 for failed verification', async () => {
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519' }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers: {} }
    const response = await gw.handle(req)
    expect(response.status).toBe(401)
    expect(JSON.parse(response.body)).toMatchObject({ error: 'missing-header' })
  })

  it('returns 403 for sender-denied', async () => {
    const headers = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519', allowedSenders: ['agent-b'] }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers }
    const response = await gw.handle(req)
    expect(response.status).toBe(403)
  })

  it('forwards to upstream when verified and adds x-7h3 headers', async () => {
    mockFetch(200, '{"ok":true}')

    const headers = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519' }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers }
    const response = await gw.handle(req)

    expect(response.status).toBe(200)
    expect(response.body).toBe('{"ok":true}')

    // Verify fetch was called with x-7h3 headers
    const fetchMock = vi.mocked(fetch)
    expect(fetchMock).toHaveBeenCalledOnce()
    const [_url, fetchOpts] = fetchMock.mock.calls[0]
    const forwardedHeaders = fetchOpts?.headers as Record<string, string>
    expect(forwardedHeaders['x-7h3-sender']).toBe('agent-a')
    expect(forwardedHeaders['x-7h3-verified']).toBe('true')
  })

  it('calls upstream at correct URL', async () => {
    mockFetch(200, 'ok')

    const headers = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const gw = createGateway({
      upstream: 'http://myservice.internal',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519' }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/users', headers }
    await gw.handle(req)

    const fetchMock = vi.mocked(fetch)
    expect(fetchMock.mock.calls[0][0]).toBe('http://myservice.internal/api/users')
  })

  it('signs response when privateKey and sender configured', async () => {
    mockFetch(200, 'response-body')

    const headers = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519' }],
      privateKey: gatewayKeys.privateKey,
      sender: 'gateway-agent',
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers }
    const response = await gw.handle(req)

    expect(response.status).toBe(200)
    expect(response.headers['x-7h3-response']).toBeDefined()
  })

  it('does NOT sign response when signResponses=false', async () => {
    mockFetch(200, 'response-body')

    const headers = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519' }],
      privateKey: gatewayKeys.privateKey,
      sender: 'gateway-agent',
      signResponses: false,
    })
    const req: GatewayRequest = { method: 'GET', path: '/api/data', headers }
    const response = await gw.handle(req)

    expect(response.headers['x-7h3-response']).toBeUndefined()
  })

  it('allows unauthenticated route via require=none policy', async () => {
    mockFetch(200, 'pong')

    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({}),
      policies: [{ path: '/health', require: 'none' }],
    })
    const req: GatewayRequest = { method: 'GET', path: '/health', headers: {} }
    const response = await gw.handle(req)
    expect(response.status).toBe(200)
    expect(response.body).toBe('pong')
  })

  it('returns 429 status in response for rate limited', async () => {
    const headers1 = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: createStaticKeyRegistry({ 'agent-a': senderKeys.publicKey }),
      policies: [{ path: '/api/**', require: 'ed25519', rateLimit: { requests: 1, windowMs: 10_000 } }],
    })

    // First request passes
    mockFetch(200, 'ok')
    const r1 = await gw.handle({ method: 'GET', path: '/api/data', headers: headers1 })
    expect(r1.status).toBe(200)

    // Second request is rate limited
    const headers2 = await makeSignedHeader('agent-a', senderKeys.privateKey)
    const r2 = await gw.handle({ method: 'GET', path: '/api/data', headers: headers2 })
    expect(r2.status).toBe(429)
  })
})
