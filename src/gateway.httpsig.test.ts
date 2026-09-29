import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'
import { createGateway, type GatewayConfig, type GatewayRequest } from './gateway'
import { createStaticKeyRegistry } from './keyRegistry'
import { createContentDigest, signMessage } from './httpMessageSignatures'
import { WEB_BOT_AUTH_TAG, jwkThumbprint, signWebBotAuthRequest, spkiToEd25519Jwk } from './webBotAuth'
import { generateEd25519KeypairBase64Url } from './protocol'
import { APPROVAL_HEADER, issueApproval, serializeApproval } from './approval'
import { bindAction } from './actionBinding'
import { MemoryReplayStore } from './replayStores'

let bot: { publicKey: string; privateKey: string }
let stranger: { publicKey: string; privateKey: string }
let alice: { publicKey: string; privateKey: string }
let botKeyId: string

beforeAll(async () => {
  bot = await generateEd25519KeypairBase64Url()
  stranger = await generateEd25519KeypairBase64Url()
  alice = await generateEd25519KeypairBase64Url()
  botKeyId = await jwkThumbprint(spkiToEd25519Jwk(bot.publicKey))
})
afterEach(() => vi.unstubAllGlobals())

function stubUpstream() {
  const f = vi.fn().mockResolvedValue({ status: 200, text: () => Promise.resolve('ok'), headers: new Headers({ 'content-type': 'text/plain' }) })
  vi.stubGlobal('fetch', f)
  return f
}

function gateway(over: Partial<GatewayConfig> = {}) {
  return createGateway({
    upstream: 'http://upstream',
    keyRegistry: createStaticKeyRegistry({}),
    defaultPolicy: 'deny',
    replayStore: new MemoryReplayStore(),
    httpSignature: {
      tag: WEB_BOT_AUTH_TAG,
      requireExpires: true,
      resolveKey: (keyId) => (keyId === botKeyId ? { key: { alg: 'ed25519', publicKey: bot.publicKey }, sender: 'bot.example' } : null),
    },
    policies: [
      { path: '/crawl/**', require: 'http-signature' },
      { path: '/pay', require: 'http-signature', approval: { require: 'always', approvers: ['alice'] } },
      { path: '/only-other', require: 'http-signature', allowedSenders: ['bot.other'] },
    ],
    approverRegistry: { getPublicKey: async (id) => (id === 'alice' ? alice.publicKey : null) },
    ...over,
  })
}

async function request(over: Partial<GatewayRequest> = {}, opts: { body?: string; host?: string } = {}): Promise<GatewayRequest> {
  const path = over.path ?? '/crawl/page?x=1'
  const method = over.method ?? 'GET'
  const host = opts.host ?? 'api.example.com'
  const signed = await signWebBotAuthRequest(
    { method, url: `https://${host}${path}`, headers: {} },
    { privateKey: bot.privateKey, publicKey: bot.publicKey, body: opts.body },
  )
  return { method, path, body: opts.body, headers: { host, ...signed.headers }, ...over }
}

describe('gateway with RFC 9421 / Web Bot Auth', () => {
  it('authenticates a signed request and forwards the resolved identity', async () => {
    const f = stubUpstream()
    const res = await gateway().handle(await request())
    expect(res.status).toBe(200)
    const sent = f.mock.calls[0][1].headers as Record<string, string>
    expect(sent['x-7h3-sender']).toBe('bot.example')
    expect(sent['x-7h3-verified']).toBe('true')
  })

  it('refuses an unsigned request and does not fall back to anything weaker', async () => {
    const f = stubUpstream()
    const res = await gateway().handle({ method: 'GET', path: '/crawl/page', headers: { host: 'api.example.com' } })
    expect(res.status).toBe(401)
    expect(JSON.parse(res.body).error).toBe('http-signature:missing-signature')
    expect(f).not.toHaveBeenCalled()
  })

  it('a request signed for one host cannot be replayed to another', async () => {
    stubUpstream()
    const req = await request()
    const res = await gateway().handle({ ...req, headers: { ...req.headers, host: 'attacker.example' } })
    expect(JSON.parse(res.body).error).toBe('http-signature:invalid-signature')
  })

  it('a signed request cannot be moved to a different path', async () => {
    stubUpstream()
    const req = await request()
    const res = await gateway().handle({ ...req, path: '/crawl/other?x=1' })
    expect(JSON.parse(res.body).error).toBe('http-signature:invalid-signature')
  })

  it('each signature works once', async () => {
    stubUpstream()
    const gw = gateway()
    const req = await request()
    expect((await gw.handle(req)).status).toBe(200)
    expect(JSON.parse((await gw.handle(req)).body).error).toBe('http-signature:replayed')
  })

  it('binds the body: a swapped payload is refused, and so is a signature that ignores the body', async () => {
    stubUpstream()
    const gw = gateway()
    const req = await request({ method: 'POST', path: '/crawl/submit' }, { body: '{"q":"a"}' })
    expect(JSON.parse((await gw.handle({ ...req, body: '{"q":"b"}' })).body).error).toBe('http-signature:digest-mismatch')

    const bare = await signMessage(
      { method: 'POST', url: 'https://api.example.com/crawl/submit', headers: {} },
      {
        components: ['@method', '@authority', '@path'],
        key: { alg: 'ed25519', privateKey: bot.privateKey },
        keyId: botKeyId,
        created: Math.floor(Date.now() / 1000),
        expires: Math.floor(Date.now() / 1000) + 60,
        nonce: true,
        tag: WEB_BOT_AUTH_TAG,
      },
    )
    const res = await gw.handle({ method: 'POST', path: '/crawl/submit', body: '{"q":"a"}', headers: { host: 'api.example.com', ...bare.headers } })
    expect(JSON.parse(res.body).error).toBe('http-signature:body-not-bound')
  })

  it('refuses keys the deployment does not know', async () => {
    stubUpstream()
    const s = await signWebBotAuthRequest(
      { method: 'GET', url: 'https://api.example.com/crawl/x', headers: {} },
      { privateKey: stranger.privateKey, publicKey: stranger.publicKey },
    )
    const res = await gateway().handle({ method: 'GET', path: '/crawl/x', headers: { host: 'api.example.com', ...s.headers } })
    expect(JSON.parse(res.body).error).toBe('http-signature:no-key')
  })

  it('applies allowedSenders to the identity the key stands for', async () => {
    stubUpstream()
    const res = await gateway().handle(await request({ path: '/only-other' }))
    expect(res.status).toBe(403)
    expect(JSON.parse(res.body).error).toBe('sender-denied')
  })

  it('composes with step-up approval on the same route', async () => {
    stubUpstream()
    const gw = gateway({ approvalReplayStore: new MemoryReplayStore() })
    const denied = await gw.handle(await request({ path: '/pay', method: 'POST' }, { body: '{"amount":5}' }))
    expect(JSON.parse(denied.body).error).toBe('approval-required')

    const action = await bindAction({ method: 'POST', path: '/pay', body: '{"amount":5}' })
    const grant = serializeApproval(await issueApproval({ approverPrivateKey: alice.privateKey, approverId: 'alice', subject: 'bot.example', action }))
    const req = await request({ path: '/pay', method: 'POST' }, { body: '{"amount":5}' })
    const ok = await gw.handle({ ...req, headers: { ...req.headers, [APPROVAL_HEADER]: grant } })
    expect(ok.status).toBe(200)
  })

  it('takes the authority from x-forwarded-host only when told to trust it', async () => {
    stubUpstream()
    const cfg = { tag: WEB_BOT_AUTH_TAG, resolveKey: () => ({ key: { alg: 'ed25519' as const, publicKey: bot.publicKey }, sender: 'bot.example' }) }
    const req = await request({}, { host: 'public.example.com' })
    const proxied = { ...req, headers: { ...req.headers, host: 'internal-lb:8080', 'x-forwarded-host': 'public.example.com' } }
    const trusting = gateway({ httpSignature: { ...cfg, trustForwardedHost: true } })
    expect((await trusting.handle(proxied)).status).toBe(200)
    const naive = gateway({ httpSignature: cfg })
    expect(JSON.parse((await naive.handle({ ...(await request({}, { host: 'public.example.com' })), headers: { ...proxied.headers } })).body).error).toBe(
      'http-signature:invalid-signature',
    )
  })

  it('refuses an identity-only signature: it proves who, not what, so it could be replayed onto any route', async () => {
    stubUpstream()
    const s = await signWebBotAuthRequest(
      { method: 'GET', url: 'https://api.example.com/crawl/x', headers: {} },
      { privateKey: bot.privateKey, publicKey: bot.publicKey, identityOnly: true },
    )
    const res = await gateway().handle({ method: 'GET', path: '/crawl/x', headers: { host: 'api.example.com', ...s.headers } })
    expect(JSON.parse(res.body).error).toBe('http-signature:insufficient-coverage')
  })

  it('requires the query string to be signed whenever the request has one', async () => {
    stubUpstream()
    const s = await signMessage(
      { method: 'GET', url: 'https://api.example.com/crawl/x?amount=5', headers: {} },
      {
        components: ['@method', '@authority', '@path'], // @query left out
        key: { alg: 'ed25519', privateKey: bot.privateKey },
        keyId: botKeyId,
        created: Math.floor(Date.now() / 1000),
        expires: Math.floor(Date.now() / 1000) + 60,
        nonce: true,
        tag: WEB_BOT_AUTH_TAG,
      },
    )
    const res = await gateway().handle({ method: 'GET', path: '/crawl/x?amount=5000', headers: { host: 'api.example.com', ...s.headers } })
    expect(JSON.parse(res.body)).toMatchObject({ error: 'http-signature:insufficient-coverage' })
  })

  it('a missing Host header is a 401, not a crash', async () => {
    const res = await gateway().handle({ method: 'GET', path: '/crawl/x', headers: {} })
    expect(res.status).toBe(401)
  })

  it('fails at construction when a policy needs http-signature but it is not configured', () => {
    expect(() =>
      createGateway({ upstream: 'http://u', keyRegistry: createStaticKeyRegistry({}), policies: [{ path: '/x', require: 'http-signature' }] }),
    ).toThrow(/httpSignature/)
  })

  it('a valid Content-Digest header alone (unsigned) is not enough to bind a body', async () => {
    stubUpstream()
    const body = '{"q":"a"}'
    const s = await signMessage(
      { method: 'POST', url: 'https://api.example.com/crawl/s', headers: { 'content-digest': await createContentDigest(body) } },
      {
        components: ['@method', '@authority', '@path'], // digest present but NOT covered
        key: { alg: 'ed25519', privateKey: bot.privateKey },
        keyId: botKeyId,
        created: Math.floor(Date.now() / 1000),
        expires: Math.floor(Date.now() / 1000) + 60,
        nonce: true,
        tag: WEB_BOT_AUTH_TAG,
      },
    )
    const res = await gateway().handle({
      method: 'POST',
      path: '/crawl/s',
      body,
      headers: { host: 'api.example.com', 'content-digest': await createContentDigest(body), ...s.headers },
    })
    expect(JSON.parse(res.body).error).toBe('http-signature:body-not-bound')
  })
})
