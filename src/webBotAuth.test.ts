import { describe, it, expect, beforeAll, vi } from 'vitest'
import {
  KEY_DIRECTORY_MEDIA_TYPE,
  WEB_BOT_AUTH_TAG,
  ed25519JwkToSpki,
  fetchKeyDirectory,
  jwkThumbprint,
  signWebBotAuthRequest,
  spkiToEd25519Jwk,
  verifyWebBotAuthRequest,
  type Ed25519Jwk,
} from './webBotAuth'
import { createContentDigest, createSignatureBase, signMessage, type HttpMessage } from './httpMessageSignatures'
import { generateEd25519KeypairBase64Url } from './protocol'
import { MemoryReplayStore } from './replayStores'

// RFC 9421 B.1.4 test key, reused by the Web Bot Auth draft's test vectors.
const RFC_PRIVATE = 'MC4CAQAwBQYDK2VwBCIEIJ-DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF'
const RFC_PUBLIC = 'MCowBQYDK2VwAyEAJrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs'
const RFC_JWK: Ed25519Jwk = { kty: 'OKP', crv: 'Ed25519', x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs' }
const RFC_THUMBPRINT = 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U'

const request: HttpMessage = { method: 'GET', url: 'https://example.com/path/to/resource', headers: {} }

describe('JWK helpers', () => {
  it('computes the RFC 7638 thumbprint the Web Bot Auth draft publishes for the RFC 9421 test key', async () => {
    expect(await jwkThumbprint(RFC_JWK)).toBe(RFC_THUMBPRINT)
  })

  it('converts between SPKI and JWK without loss', () => {
    expect(spkiToEd25519Jwk(RFC_PUBLIC)).toEqual(RFC_JWK)
    expect(ed25519JwkToSpki(RFC_JWK)).toBe(RFC_PUBLIC)
  })

  it('refuses non-Ed25519 input and JWKs that carry a private component', async () => {
    expect(() => spkiToEd25519Jwk('AAAA')).toThrow()
    expect(() => ed25519JwkToSpki({ ...RFC_JWK, x: 'short' })).toThrow()
    await expect(jwkThumbprint({ ...RFC_JWK, d: 'secret' } as unknown as Ed25519Jwk)).rejects.toThrow()
    await expect(jwkThumbprint({ kty: 'RSA' } as unknown as Ed25519Jwk)).rejects.toThrow()
  })
})

describe('Web Bot Auth draft test vectors (Appendix A.2)', () => {
  const created = 1735689600
  const expires = 4889289600
  const now = created * 1000 + 5000

  it('A.2.1: Signature-Agent absent', async () => {
    const s = await signMessage(request, {
      label: 'sig1',
      components: ['@authority'],
      key: { alg: 'ed25519', privateKey: RFC_PRIVATE },
      keyId: RFC_THUMBPRINT,
      includeAlg: true,
      created,
      expires,
      nonce: 'g0iqFa9e1ffijlyOScDkXpfSmTbYpRNSGPJrQ1It20ahwgzB3jOUcdgLgFxUg7RMtW4V8IILaKKtA+YuSyIgJQ==',
      tag: WEB_BOT_AUTH_TAG,
    })
    expect(s.signatureInput).toBe(
      'sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="g0iqFa9e1ffijlyOScDkXpfSmTbYpRNSGPJrQ1It20ahwgzB3jOUcdgLgFxUg7RMtW4V8IILaKKtA+YuSyIgJQ==";tag="web-bot-auth"',
    )
    expect(s.signature).toBe('sig1=:FFASViSdcgsyaqqYiCnkHreeZzbNKcTzDvZC5uVlP/dn9IbWj8j0o4wKFTH3rBnUiSUBduwm1Gp5VlIPCp01Ag==:')
    const r = await verifyWebBotAuthRequest({ ...request, headers: s.headers }, { resolveKeys: () => [RFC_JWK], now, maxAgeMs: 60_000 })
    expect(r).toMatchObject({ ok: true, keyId: RFC_THUMBPRINT })
  })

  it('A.2.2: dictionary-form Signature-Agent covered with ;key', async () => {
    const withAgent: HttpMessage = { ...request, headers: { 'Signature-Agent': 'agent2="https://signature-agent.test"' } }
    const nonce = 'XeP72svPKNiGEg3aDE7WJuTpN69H08oMFqC8NLFy1MptpENAT3WZTYwK+MYdsFMlaqHCJGo9ZAhqer1NWY9Epg=='
    const params = { keyid: RFC_THUMBPRINT, alg: 'ed25519', created, expires, nonce, tag: WEB_BOT_AUTH_TAG }

    // Our signature base is exactly the one the draft prints for this example.
    expect(createSignatureBase(withAgent, ['@authority', 'signature-agent;key="agent2"'], params)).toBe(
      [
        '"@authority": example.com',
        '"signature-agent";key="agent2": "https://signature-agent.test"',
        `"@signature-params": ("@authority" "signature-agent";key="agent2");created=1735689600;keyid="${RFC_THUMBPRINT}";alg="ed25519";expires=4889289600;nonce="${nonce}";tag="web-bot-auth"`,
      ].join('\n'),
    )

    // KNOWN DISCREPANCY: the signature the draft lists for A.2.2
    // (DGiW2Erl…/jCg==) is NOT a signature over that base. It verifies only over a
    // base whose member value has lost its quotes (`…: https://signature-agent.test`),
    // which contradicts both the draft's own printed base and RFC 9421 §2.1.2
    // ("strict serialization" keeps sf-string quotes). We follow the RFC, so a
    // signer that reproduces the draft's listed vector will be rejected here.
    const s = await signMessage(withAgent, {
      label: 'sig2',
      components: ['@authority', 'signature-agent;key="agent2"'],
      key: { alg: 'ed25519', privateKey: RFC_PRIVATE },
      keyId: RFC_THUMBPRINT,
      includeAlg: true,
      created,
      expires,
      nonce,
      tag: WEB_BOT_AUTH_TAG,
    })
    expect(s.signature).not.toBe('sig2=:DGiW2ErlQh0hc8wY2FQdbnFd6CEmonyY8nlvECIJFaUSYYNvNvSsGyP99BUGtq51gA4ouXlkUwjnta084bpjCg==:')

    const seen: Array<string | undefined> = []
    const r = await verifyWebBotAuthRequest(
      { ...request, headers: { ...withAgent.headers, ...s.headers } },
      { resolveKeys: (agent) => (seen.push(agent), [RFC_JWK]), now, maxAgeMs: 60_000 },
    )
    expect(r).toMatchObject({ ok: true, agentUrl: 'https://signature-agent.test' })
    expect(seen).toEqual(['https://signature-agent.test'])
  })
})

describe('signWebBotAuthRequest / verifyWebBotAuthRequest', () => {
  let keys: { publicKey: string; privateKey: string }
  let other: { publicKey: string; privateKey: string }
  const NOW = 1_800_000_000_000
  beforeAll(async () => {
    keys = await generateEd25519KeypairBase64Url()
    other = await generateEd25519KeypairBase64Url()
  })

  const directory = () => [spkiToEd25519Jwk(keys.publicKey)]
  const sign = async (over: Partial<Parameters<typeof signWebBotAuthRequest>[1]> = {}, msg: HttpMessage = request) => {
    const s = await signWebBotAuthRequest(msg, { privateKey: keys.privateKey, publicKey: keys.publicKey, now: NOW, ...over })
    return { ...msg, headers: { ...msg.headers, ...s.headers } }
  }
  const verify = (m: HttpMessage, over: Partial<Parameters<typeof verifyWebBotAuthRequest>[1]> = {}) =>
    verifyWebBotAuthRequest(m, { resolveKeys: directory, now: NOW, ...over })

  it('round-trips with the key id derived from the public key', async () => {
    const r = await verify(await sign())
    expect(r).toMatchObject({ ok: true, keyId: await jwkThumbprint(spkiToEd25519Jwk(keys.publicKey)) })
  })

  it('names and covers the Signature-Agent directory (dictionary and legacy forms)', async () => {
    for (const agentForm of ['dictionary', 'string'] as const) {
      const m = await sign({ agentUrl: 'https://bot.example', agentForm })
      const r = await verify(m, { resolveKeys: (agent) => (agent === 'https://bot.example' ? directory() : null) })
      expect(r).toMatchObject({ ok: true, agentUrl: 'https://bot.example' })
    }
  })

  it('refuses a Signature-Agent that the signature does not cover', async () => {
    const m = await sign()
    const forged = { ...m, headers: { ...m.headers, 'signature-agent': 'agent="https://attacker.example"' } }
    expect(await verify(forged)).toMatchObject({ ok: false, reason: 'bad-signature-agent' })
  })

  it('a swapped Signature-Agent breaks a covering signature', async () => {
    const m = await sign({ agentUrl: 'https://bot.example' })
    const swapped = { ...m, headers: { ...m.headers, 'signature-agent': 'agent="https://attacker.example"' } }
    expect(await verify(swapped)).toMatchObject({ ok: false, reason: 'invalid-signature' })
  })

  it('refuses keys that are not in the directory, and a signature by another key', async () => {
    expect(await verify(await sign(), { resolveKeys: () => [spkiToEd25519Jwk(other.publicKey)] })).toMatchObject({ ok: false, reason: 'unknown-key' })
    expect(await verify(await sign(), { resolveKeys: () => null })).toMatchObject({ ok: false, reason: 'no-key' })
  })

  it('requires the web-bot-auth tag and an expiry', async () => {
    const wrongTag = await signMessage(request, {
      components: ['@authority'],
      key: { alg: 'ed25519', privateKey: keys.privateKey },
      keyId: await jwkThumbprint(spkiToEd25519Jwk(keys.publicKey)),
      created: NOW / 1000,
      expires: NOW / 1000 + 60,
      tag: 'something-else',
    })
    expect(await verify({ ...request, headers: wrongTag.headers })).toMatchObject({ ok: false })
    const noExpiry = await signMessage(request, {
      components: ['@authority'],
      key: { alg: 'ed25519', privateKey: keys.privateKey },
      keyId: await jwkThumbprint(spkiToEd25519Jwk(keys.publicKey)),
      created: NOW / 1000,
      tag: WEB_BOT_AUTH_TAG,
    })
    expect(await verify({ ...request, headers: noExpiry.headers })).toMatchObject({ ok: false, reason: 'missing-expires' })
  })

  it('does not consume the nonce of a signature that is rejected for a missing expiry', async () => {
    const store = new MemoryReplayStore({ now: () => NOW })
    const kid = await jwkThumbprint(spkiToEd25519Jwk(keys.publicKey))
    const noExpiry = await signMessage(request, {
      components: ['@authority'],
      key: { alg: 'ed25519', privateKey: keys.privateKey },
      keyId: kid,
      created: NOW / 1000,
      nonce: 'fixed',
      tag: WEB_BOT_AUTH_TAG,
    })
    expect(await verify({ ...request, headers: noExpiry.headers }, { nonceStore: store })).toMatchObject({ reason: 'missing-expires' })
    expect(store.size).toBe(0)
  })

  it('enforces short lifetimes and single-use nonces', async () => {
    const store = new MemoryReplayStore({ now: () => NOW })
    const m = await sign()
    expect((await verify(m, { nonceStore: store })).ok).toBe(true)
    expect(await verify(m, { nonceStore: store })).toMatchObject({ ok: false, reason: 'replayed' })
    expect(await verify(m, { now: NOW + 5 * 60_000 })).toMatchObject({ ok: false })
  })

  it('can bind the body through Content-Digest', async () => {
    const body = '{"q":"weather"}'
    const m = await sign({ body }, { ...request, method: 'POST' })
    expect(m.headers['content-digest']).toBe(await createContentDigest(body))
    expect((await verify(m, { body, requireBodyBinding: true })).ok).toBe(true)
    expect(await verify(m, { body: '{"q":"other"}', requireBodyBinding: true })).toMatchObject({ ok: false, reason: 'digest-mismatch' })
    const unbound = await sign({}, { ...request, method: 'POST' })
    expect(await verify(unbound, { body, requireBodyBinding: true })).toMatchObject({ ok: false, reason: 'body-not-bound' })
  })

  it('validates signing options', async () => {
    await expect(sign({ agentUrl: 'http://insecure.example' })).rejects.toThrow(/https/)
    await expect(sign({ lifetimeSeconds: 0 })).rejects.toThrow()
    await expect(sign({ lifetimeSeconds: 100_000 })).rejects.toThrow()
    await expect(sign({ agentUrl: 'https://a.example', agentLabel: 'Bad Label' })).rejects.toThrow()
  })
})

describe('fetchKeyDirectory', () => {
  const okResponse = (body: unknown, headers: Record<string, string> = { 'content-type': KEY_DIRECTORY_MEDIA_TYPE }) =>
    ({ ok: true, status: 200, headers: new Headers(headers), text: async () => JSON.stringify(body) }) as unknown as Response

  it('fetches the fixed well-known path, refuses redirects, and keeps only public Ed25519 keys', async () => {
    const f = vi.fn().mockResolvedValue(okResponse({ keys: [RFC_JWK, { ...RFC_JWK, d: 'private' }, { kty: 'RSA', n: 'x', e: 'y' }, 'junk'] }))
    const keys = await fetchKeyDirectory('https://bot.example/some/other/path?x=1', { fetch: f })
    expect(keys).toEqual([RFC_JWK])
    expect(f.mock.calls[0][0]).toBe('https://bot.example/.well-known/http-message-signatures-directory')
    expect(f.mock.calls[0][1].redirect).toBe('error')
  })

  it.each([
    ['http://bot.example', 'https'],
    ['https://user:pw@bot.example', 'https'],
    ['not a url', 'invalid'],
  ])('refuses %s', async (url, why) => {
    await expect(fetchKeyDirectory(url, { fetch: vi.fn() })).rejects.toThrow(new RegExp(why))
  })

  it('rejects wrong content types, non-JWKS bodies, HTTP errors and oversized responses', async () => {
    const f = (r: Response) => ({ fetch: vi.fn().mockResolvedValue(r) })
    await expect(fetchKeyDirectory('https://b.example', f(okResponse({ keys: [] }, { 'content-type': 'text/html' })))).rejects.toThrow(/content-type/)
    await expect(fetchKeyDirectory('https://b.example', f(okResponse({ nope: 1 })))).rejects.toThrow(/JWKS/)
    await expect(fetchKeyDirectory('https://b.example', f({ ok: false, status: 404, headers: new Headers() } as unknown as Response))).rejects.toThrow(/404/)
    await expect(
      fetchKeyDirectory('https://b.example', { ...f(okResponse({ keys: [RFC_JWK] }, { 'content-type': KEY_DIRECTORY_MEDIA_TYPE, 'content-length': '999999' })), maxBytes: 100 }),
    ).rejects.toThrow(/too large/)
    await expect(fetchKeyDirectory('https://b.example', { ...f(okResponse({ keys: [RFC_JWK] })), maxBytes: 10 })).rejects.toThrow(/too large/)
  })

  it('caps the number of keys', async () => {
    const many = Array.from({ length: 50 }, () => RFC_JWK)
    const keys = await fetchKeyDirectory('https://b.example', { fetch: vi.fn().mockResolvedValue(okResponse({ keys: many })), maxKeys: 5 })
    expect(keys.length).toBe(5)
  })
})
