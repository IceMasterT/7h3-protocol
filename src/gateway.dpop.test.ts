import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'
import { createGateway, type GatewayConfig, type GatewayRequest } from './gateway'
import { createStaticKeyRegistry } from './keyRegistry'
import { DpopNonceIssuer, createDpopProof, dpopAuthorization, dpopJwkThumbprint, generateDpopKeyPair, type DpopKeyPair } from './dpop'
import { MemoryReplayStore } from './replayStores'

let agent: DpopKeyPair
let thief: DpopKeyPair
let agentJkt: string
const TOKEN = 'agent-access-token'

beforeAll(async () => {
  agent = await generateDpopKeyPair('ES256')
  thief = await generateDpopKeyPair('EdDSA')
  agentJkt = await dpopJwkThumbprint(agent.publicJwk)
})
afterEach(() => vi.unstubAllGlobals())

function stubUpstream() {
  const f = vi.fn().mockResolvedValue({ status: 200, text: () => Promise.resolve('ok'), headers: new Headers({ 'content-type': 'text/plain' }) })
  vi.stubGlobal('fetch', f)
  return f
}

function gateway(over: Partial<GatewayConfig> = {}, nonce?: DpopNonceIssuer) {
  return createGateway({
    upstream: 'http://upstream',
    keyRegistry: createStaticKeyRegistry({}),
    defaultPolicy: 'deny',
    replayStore: new MemoryReplayStore(),
    dpop: {
      resolveToken: (t) => (t === TOKEN ? { sender: 'agent.worker', jkt: agentJkt } : t === 'unbound-token' ? { sender: 'agent.worker', jkt: '' } : null),
      ...(nonce ? { nonce: { issuer: nonce } } : {}),
    },
    policies: [
      { path: '/api/**', require: 'dpop' },
      { path: '/only-other', require: 'dpop', allowedSenders: ['agent.other'] },
    ],
    ...over,
  })
}

async function request(over: Partial<GatewayRequest> = {}, opts: { key?: DpopKeyPair; token?: string; host?: string; nonce?: string; proofUrl?: string; proofMethod?: string } = {}): Promise<GatewayRequest> {
  const method = over.method ?? 'GET'
  const path = over.path ?? '/api/data?x=1'
  const host = opts.host ?? 'api.example.com'
  const proof = await createDpopProof({
    key: opts.key ?? agent,
    method: opts.proofMethod ?? method,
    url: opts.proofUrl ?? `https://${host}${path}`,
    accessToken: opts.token ?? TOKEN,
    nonce: opts.nonce,
  })
  return { method, path, headers: { host, authorization: dpopAuthorization(opts.token ?? TOKEN), dpop: proof }, ...over }
}

describe('gateway with DPoP', () => {
  it('authenticates a bound token with a valid proof and forwards the identity, not the proof', async () => {
    const f = stubUpstream()
    const res = await gateway().handle(await request())
    expect(res.status).toBe(200)
    const sent = f.mock.calls[0][1].headers as Record<string, string>
    expect(sent['x-7h3-sender']).toBe('agent.worker')
    expect(Object.keys(sent).map((k) => k.toLowerCase())).not.toContain('dpop')
  })

  it('refuses a plain Bearer token or no token at all', async () => {
    stubUpstream()
    const req = await request()
    for (const authorization of ['Bearer ' + TOKEN, '', undefined]) {
      const headers: Record<string, string> = { ...(req.headers as Record<string, string>) }
      if (authorization === undefined) delete headers.authorization
      else headers.authorization = authorization
      const res = await gateway().handle({ ...req, headers })
      expect(JSON.parse(res.body).error).toBe('dpop:missing-token')
      expect(res.headers['www-authenticate']).toContain('DPoP')
    }
  })

  it('refuses a request with a token but no proof', async () => {
    stubUpstream()
    const req = await request()
    const { dpop: _d, ...headers } = req.headers as Record<string, string>
    void _d
    const res = await gateway().handle({ ...req, headers })
    expect(JSON.parse(res.body).error).toBe('dpop:missing-proof')
  })

  it('a stolen token is useless without the bound key', async () => {
    const f = stubUpstream()
    const res = await gateway().handle(await request({}, { key: thief }))
    expect(JSON.parse(res.body).error).toBe('dpop:key-not-bound')
    expect(f).not.toHaveBeenCalled()
  })

  it('refuses unknown tokens and tokens that carry no key binding', async () => {
    stubUpstream()
    expect(JSON.parse((await gateway().handle(await request({}, { token: 'nope' }))).body).error).toBe('dpop:invalid-token')
    expect(JSON.parse((await gateway().handle(await request({}, { token: 'unbound-token' }))).body).error).toBe('dpop:invalid-token')
  })

  it('a proof made for another method, path or host cannot be reused', async () => {
    stubUpstream()
    const gw = gateway()
    const read = await request()
    expect(JSON.parse((await gw.handle({ ...read, method: 'DELETE' })).body).error).toBe('dpop:htm-mismatch')
    expect(JSON.parse((await gw.handle({ ...read, path: '/api/admin' })).body).error).toBe('dpop:htu-mismatch')
    expect(JSON.parse((await gw.handle({ ...read, headers: { ...read.headers, host: 'attacker.example' } })).body).error).toBe('dpop:htu-mismatch')
  })

  it('ignores the query string when matching the proof URL', async () => {
    stubUpstream()
    const req = await request({ path: '/api/data?x=1' }, { proofUrl: 'https://api.example.com/api/data' })
    expect((await gateway().handle(req)).status).toBe(200)
  })

  it('each proof works once', async () => {
    stubUpstream()
    const gw = gateway()
    const req = await request()
    expect((await gw.handle(req)).status).toBe(200)
    expect(JSON.parse((await gw.handle(req)).body).error).toBe('dpop:replayed')
  })

  it('refuses two DPoP headers', async () => {
    stubUpstream()
    const req = await request()
    const other = await createDpopProof({ key: agent, method: 'GET', url: 'https://api.example.com/api/data', accessToken: TOKEN })
    const res = await gateway().handle({ ...req, headers: { ...req.headers, dpop: [(req.headers as Record<string, string>).dpop, other] } })
    expect(JSON.parse(res.body).error).toBe('dpop:multiple-proofs')
  })

  it('applies allowedSenders to the token holder', async () => {
    stubUpstream()
    const res = await gateway().handle(await request({ path: '/only-other' }))
    expect(res.status).toBe(403)
  })

  it('challenges with a server nonce, then accepts a proof that carries it', async () => {
    stubUpstream()
    let t = 1_800_000_000_000
    const issuer = new DpopNonceIssuer('a-sufficiently-long-secret', { now: () => t })
    // The nonce is time-bound, so make the proof's clock agree with it.
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(t)
    try {
      const gw = gateway({}, issuer)
      const first = await gw.handle(await request())
      expect(first.status).toBe(401)
      expect(JSON.parse(first.body).error).toBe('dpop:nonce-required')
      expect(first.headers['www-authenticate']).toContain('use_dpop_nonce')
      const nonce = first.headers['dpop-nonce']
      expect(nonce).toBeTruthy()

      expect((await gw.handle(await request({}, { nonce }))).status).toBe(200)
      const bad = await gw.handle(await request({}, { nonce: 'forged' }))
      expect(JSON.parse(bad.body).error).toBe('dpop:nonce-mismatch')
      expect(bad.headers['dpop-nonce']).toBeTruthy() // a fresh one for the retry
      t += 10 * 60_000
      vi.setSystemTime(t)
      expect(JSON.parse((await gw.handle(await request({}, { nonce }))).body).error).toBe('dpop:nonce-mismatch')
    } finally {
      vi.useRealTimers()
    }
  })

  it('takes the authority from x-forwarded-host only when told to trust it', async () => {
    stubUpstream()
    const req = await request({}, { host: 'public.example.com' })
    const proxied = { ...req, headers: { ...req.headers, host: 'internal-lb:8080', 'x-forwarded-host': 'public.example.com' } }
    const trusting = gateway({ dpop: { resolveToken: () => ({ sender: 'agent.worker', jkt: agentJkt }), trustForwardedHost: true } })
    expect((await trusting.handle(proxied)).status).toBe(200)
    const naive = gateway()
    expect(JSON.parse((await naive.handle(await request({ headers: { ...proxied.headers } as never }, { host: 'public.example.com' }))).body).error).toMatch(/^dpop:/)
  })

  it('fails at construction when a policy needs dpop but it is not configured', () => {
    expect(() => createGateway({ upstream: 'http://u', keyRegistry: createStaticKeyRegistry({}), policies: [{ path: '/x', require: 'dpop' }] })).toThrow(/dpop/)
  })

  it('never lets a caller-supplied DPoP header reach the upstream on other routes', async () => {
    const f = stubUpstream()
    await createGateway({
      upstream: 'http://u',
      keyRegistry: createStaticKeyRegistry({}),
      defaultPolicy: 'allow',
      policies: [{ path: '/open/**', require: 'none' }],
    }).handle({ method: 'GET', path: '/open/x', headers: { DPoP: 'abc' } })
    const sent = Object.keys(f.mock.calls[0][1].headers as Record<string, string>).map((k) => k.toLowerCase())
    expect(sent).not.toContain('dpop')
  })
})
