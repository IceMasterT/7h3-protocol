import { describe, it, expect, beforeAll } from 'vitest'
import {
  HttpSignatureError,
  createContentDigest,
  createSignatureBase,
  normalizeComponentId,
  parseSignatures,
  signMessage,
  verifyContentDigest,
  verifyMessage,
  type HttpMessage,
  type VerificationKey,
  type VerifyMessageOptions,
} from './httpMessageSignatures'
import { generateEd25519KeypairBase64Url } from './protocol'
import { MemoryReplayStore } from './replayStores'

// ---------------------------------------------------------------------------
// Fixtures taken verbatim from RFC 9421 Appendix B
// ---------------------------------------------------------------------------

const RFC_ED25519_PRIVATE = 'MC4CAQAwBQYDK2VwBCIEIJ-DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF' // B.1.4 (PKCS8, base64url)
const RFC_ED25519_PUBLIC = 'MCowBQYDK2VwAyEAJrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs' // B.1.4 (SPKI, base64url)
const RFC_SHARED_SECRET = Uint8Array.from(
  atob('uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=='),
  (c) => c.charCodeAt(0),
) // B.1.5

const CREATED = 1618884473
const CREATED_MS = CREATED * 1000

const testRequest: HttpMessage = {
  method: 'POST',
  url: 'https://example.com/foo?param=Value&Pet=dog',
  headers: {
    Host: 'example.com',
    Date: 'Tue, 20 Apr 2021 02:07:55 GMT',
    'Content-Type': 'application/json',
    'Content-Digest': 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
    'Content-Length': '18',
  },
}
const testBody = '{"hello": "world"}'

describe('RFC 9421 Appendix B test vectors', () => {
  it('B.2.2: signature base with @authority, content-digest and a named query parameter', () => {
    const base = createSignatureBase(
      testRequest,
      ['@authority', 'content-digest', '@query-param;name="Pet"'],
      { created: CREATED, keyid: 'test-key-rsa-pss', tag: 'header-example' },
    )
    expect(base).toBe(
      [
        '"@authority": example.com',
        '"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
        '"@query-param";name="Pet": dog',
        '"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
      ].join('\n'),
    )
  })

  it('Figure 1: the non-normative example signature base', () => {
    const base = createSignatureBase(
      testRequest,
      ['@method', '@authority', '@path', 'content-digest', 'content-length', 'content-type'],
      { created: CREATED, keyid: 'test-key-rsa-pss' },
    )
    expect(base).toBe(
      [
        '"@method": POST',
        '"@authority": example.com',
        '"@path": /foo',
        '"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
        '"content-length": 18',
        '"content-type": application/json',
        '"@signature-params": ("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss"',
      ].join('\n'),
    )
  })

  it('B.2.1: minimal signature base (no covered components)', () => {
    expect(createSignatureBase(testRequest, [], { created: CREATED, keyid: 'test-key-rsa-pss', nonce: 'b3k2pp5k7z-50gnwp.yemd' })).toBe(
      '"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
    )
  })

  it('B.2.5: hmac-sha256 produces the RFC signature byte-for-byte', async () => {
    const signed = await signMessage(testRequest, {
      label: 'sig-b25',
      components: ['date', '@authority', 'content-type'],
      key: { alg: 'hmac-sha256', secret: RFC_SHARED_SECRET },
      keyId: 'test-shared-secret',
      created: CREATED,
    })
    expect(signed.signatureInput).toBe('sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"')
    expect(signed.signature).toBe('sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:')
  })

  it('B.2.6: ed25519 produces the RFC signature byte-for-byte', async () => {
    const signed = await signMessage(testRequest, {
      label: 'sig-b26',
      components: ['date', '@method', '@path', '@authority', 'content-type', 'content-length'],
      key: { alg: 'ed25519', privateKey: RFC_ED25519_PRIVATE },
      keyId: 'test-key-ed25519',
      created: CREATED,
    })
    expect(signed.signatureInput).toBe(
      'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    )
    expect(signed.signature).toBe(
      'sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:',
    )
  })

  it('verifies the RFC-published B.2.5 and B.2.6 signatures as received', async () => {
    const hmac: HttpMessage = {
      ...testRequest,
      headers: {
        ...testRequest.headers,
        'Signature-Input': 'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
        Signature: 'sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:',
      },
    }
    const okHmac = await verifyMessage(hmac, {
      resolveKey: (id) => (id === 'test-shared-secret' ? { alg: 'hmac-sha256', secret: RFC_SHARED_SECRET } : null),
      requiredComponents: ['@authority'],
      now: CREATED_MS + 1000,
    })
    expect(okHmac.ok).toBe(true)

    const ed: HttpMessage = {
      ...testRequest,
      headers: {
        ...testRequest.headers,
        'Signature-Input':
          'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
        Signature: 'sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:',
      },
    }
    const okEd = await verifyMessage(ed, {
      resolveKey: () => ({ alg: 'ed25519', publicKey: RFC_ED25519_PUBLIC }),
      requiredComponents: ['@method', '@path'],
      now: CREATED_MS,
    })
    expect(okEd.ok).toBe(true)
  })
})

describe('derived components (RFC 9421 §2.2)', () => {
  const base = (url: string, comps: string[], method = 'GET') =>
    createSignatureBase({ method, url, headers: {} }, comps, {}).split('\n').slice(0, -1)

  it('@authority lower-cases the host and drops the default port', () => {
    expect(base('https://EXAMPLE.com:443/x', ['@authority'])).toEqual(['"@authority": example.com'])
    expect(base('http://example.com:80/x', ['@authority'])).toEqual(['"@authority": example.com'])
    expect(base('https://example.com:8443/x', ['@authority'])).toEqual(['"@authority": example.com:8443'])
  })

  it('@scheme, @path (empty becomes /), @query (? when absent), @request-target', () => {
    expect(base('HTTPS://example.com', ['@scheme', '@path', '@query', '@request-target'])).toEqual([
      '"@scheme": https',
      '"@path": /',
      '"@query": ?',
      '"@request-target": /',
    ])
    expect(base('https://e.com/p?a=1&b=2', ['@query', '@request-target'])).toEqual(['"@query": ?a=1&b=2', '"@request-target": /p?a=1&b=2'])
    expect(base('https://e.com/p?queryString', ['@query'])).toEqual(['"@query": ?queryString'])
  })

  it('@target-uri drops the fragment; percent-encoding is not decoded in @path', () => {
    expect(base('https://e.com/a%2Fb?x=1#frag', ['@target-uri', '@path'])).toEqual(['"@target-uri": https://e.com/a%2Fb?x=1', '"@path": /a%2Fb'])
  })

  it('@query-param follows the RFC examples, including form-decoding and re-encoding', () => {
    const url = 'https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something'
    expect(base(url, ['@query-param;name="var"', '@query-param;name="bar"', '@query-param;name="fa%C3%A7ade%22%3A%20"'])).toEqual([
      '"@query-param";name="var": this%20is%20a%20big%0Amultiline%20value',
      '"@query-param";name="bar": with%20plus%20whitespace',
      '"@query-param";name="fa%C3%A7ade%22%3A%20": something',
    ])
  })

  it('@query-param: empty value is an empty string; missing or repeated names are errors', () => {
    const url = 'https://www.example.com/path?param=value&foo=bar&baz=batman&qux=&dup=1&dup=2'
    expect(base(url, ['@query-param;name="baz"', '@query-param;name="qux"', '@query-param;name="param"'])).toEqual([
      '"@query-param";name="baz": batman',
      '"@query-param";name="qux": ',
      '"@query-param";name="param": value',
    ])
    expect(() => base(url, ['@query-param;name="nope"'])).toThrow(/component-not-found/)
    expect(() => base(url, ['@query-param;name="dup"'])).toThrow(/ambiguous-query-parameter/)
    expect(() => base(url, ['@query-param'])).toThrow(/component-not-found/)
  })

  it('rejects userinfo in the target URI and non-URLs', () => {
    expect(() => base('https://user:pw@example.com/x', ['@authority'])).toThrow(/invalid-url/)
    expect(() => base('/relative', ['@authority'])).toThrow(/invalid-url/)
  })

  it('@status only applies to responses, and `;req` pulls request components into a response', () => {
    const response: HttpMessage = { status: 200, headers: { 'Content-Type': 'application/json' } }
    expect(createSignatureBase(response, ['@status', 'content-type'], {}).split('\n').slice(0, -1)).toEqual(['"@status": 200', '"content-type": application/json'])
    expect(() => createSignatureBase({ method: 'GET', url: 'https://e.com/', headers: {} }, ['@status'], {})).toThrow(/component-not-applicable/)
    expect(() => createSignatureBase(response, ['@method'], {})).toThrow(/component-not-applicable/)
    const req: HttpMessage = { method: 'POST', url: 'https://e.com/x', headers: {} }
    expect(createSignatureBase(response, ['@status', '@method;req'], {}, { request: req }).split('\n').slice(0, -1)).toEqual([
      '"@status": 200',
      '"@method";req: POST',
    ])
    expect(() => createSignatureBase(response, ['@method;req'], {})).toThrow(/req-without-request/)
    expect(() => createSignatureBase(req, ['@method;req'], {}, { request: req })).toThrow(/req-on-request/)
  })

  it('header fields: case-insensitive, multiple values joined with ", ", trimmed; missing is an error', () => {
    const m: HttpMessage = { method: 'GET', url: 'https://e.com/', headers: { 'X-Thing': ['  a ', 'b  '], Other: 'x' } }
    expect(createSignatureBase(m, ['x-thing'], {}).split('\n')[0]).toBe('"x-thing": a, b')
    expect(() => createSignatureBase(m, ['missing'], {})).toThrow(/component-not-found/)
    expect(() => createSignatureBase({ ...m, headers: { A: 'x\ny' } }, ['a'], {})).toThrow(/invalid-field-value/)
  })

  it('rejects unknown derived components and unsupported parameters instead of ignoring them', () => {
    expect(() => base('https://e.com/', ['@made-up'])).toThrow(/unknown-derived-component/)
    expect(() => base('https://e.com/', ['content-type;sf'])).toThrow(/unsupported-component-parameter/)
    expect(() => base('https://e.com/', ['content-type;bs'])).toThrow(/unsupported-component-parameter/)
    expect(() => base('https://e.com/', ['content-type;tr'])).toThrow(/unsupported-component-parameter/)
    expect(() => base('https://e.com/', ['@method', '@method'])).toThrow(/duplicate-component/)
  })

  it('normalizeComponentId accepts bare and quoted forms', () => {
    expect(normalizeComponentId('@method')).toBe('"@method"')
    expect(normalizeComponentId('"@method"')).toBe('"@method"')
    expect(normalizeComponentId('@query-param;name="Pet"')).toBe('"@query-param";name="Pet"')
    expect(normalizeComponentId('content-digest;req')).toBe('"content-digest";req')
    expect(() => normalizeComponentId('@method;name=5')).toThrow()
  })
})

describe('Content-Digest (RFC 9530)', () => {
  it('matches the digest RFC 9421 publishes for {"hello": "world"}', async () => {
    expect(await createContentDigest(testBody, 'sha-512')).toBe(
      'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
    )
    expect(await createContentDigest(testBody)).toBe('sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:')
  })

  it('verifies, and rejects a changed body', async () => {
    const h = await createContentDigest(testBody)
    expect(await verifyContentDigest(h, testBody)).toBe(true)
    expect(await verifyContentDigest(h, testBody + ' ')).toBe(false)
  })

  it('every recognized algorithm must match; unknown ones are ignored; none recognized fails', async () => {
    const good256 = await createContentDigest(testBody, 'sha-256')
    const bad512 = 'sha-512=:' + 'A'.repeat(86) + '==:'
    expect(await verifyContentDigest(`${good256}, unknown-alg=:AAAA:`, testBody)).toBe(true)
    expect(await verifyContentDigest(`${good256}, ${bad512}`, testBody)).toBe(false)
    expect(await verifyContentDigest('md5=:AAAA:', testBody)).toBe(false)
    expect(await verifyContentDigest('garbage', testBody)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Sign / verify round trips and verifier policy
// ---------------------------------------------------------------------------

let keys: { publicKey: string; privateKey: string }
let otherKeys: { publicKey: string; privateKey: string }
const NOW = 1_800_000_000_000

beforeAll(async () => {
  keys = await generateEd25519KeypairBase64Url()
  otherKeys = await generateEd25519KeypairBase64Url()
})

const resolve = (): VerifyMessageOptions['resolveKey'] => (id) => (id === 'agent-key' ? { alg: 'ed25519', publicKey: keys.publicKey } : null)

async function signed(over: Partial<Parameters<typeof signMessage>[1]> = {}, message: HttpMessage = post()): Promise<HttpMessage> {
  const s = await signMessage(message, {
    components: ['@method', '@authority', '@path', 'content-digest'],
    key: { alg: 'ed25519', privateKey: keys.privateKey },
    keyId: 'agent-key',
    created: Math.floor(NOW / 1000),
    tag: 'agent',
    ...over,
  })
  return { ...message, headers: { ...message.headers, ...s.headers } }
}

function post(body = '{"amount":5000}'): HttpMessage & { body: string } {
  return {
    method: 'POST',
    url: 'https://api.example.com/payments',
    headers: { host: 'api.example.com', 'content-type': 'application/json', 'content-digest': 'PLACEHOLDER' },
    body,
  }
}

async function withDigest(body = '{"amount":5000}'): Promise<HttpMessage & { body: string }> {
  const m = post(body)
  m.headers['content-digest'] = await createContentDigest(body)
  return m
}

const verify = (m: HttpMessage, over: Partial<VerifyMessageOptions> = {}) =>
  verifyMessage(m, { resolveKey: resolve(), requiredComponents: ['@method', '@authority', '@path'], tag: 'agent', now: NOW, ...over })

describe('verifyMessage', () => {
  it('accepts a signed request and reports the key id and covered components', async () => {
    const m = await withDigest()
    const r = await verify(await signed({}, m), { body: m.body, requireBodyBinding: true })
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.keyId).toBe('agent-key')
      expect(r.covered).toContain('"content-digest"')
    }
  })

  it('refuses a request with no signature', async () => {
    expect(await verify(await withDigest())).toMatchObject({ ok: false, reason: 'missing-signature' })
  })

  it('refuses a validly signed request that does not cover what policy requires', async () => {
    const m = await withDigest()
    const s = await signed({ components: ['@method'] }, m)
    expect(await verify(s)).toMatchObject({ ok: false, reason: 'insufficient-coverage', detail: '"@authority"' })
    expect(await verify(s, { requiredComponents: ['@method'] })).toMatchObject({ ok: true })
  })

  it('refuses to be configured with no required components', async () => {
    await expect(verify(await signed({}, await withDigest()), { requiredComponents: [] })).rejects.toThrow(/requiredComponents/)
  })

  it('a body swapped after signing fails the covered digest', async () => {
    const m = await withDigest()
    const s = await signed({}, m)
    expect(await verify(s, { body: '{"amount":50000}' })).toMatchObject({ ok: false, reason: 'digest-mismatch' })
    expect(await verify(s, { body: m.body })).toMatchObject({ ok: true })
  })

  it('requireBodyBinding refuses a signature that does not cover content-digest', async () => {
    const m = await withDigest()
    const s = await signed({ components: ['@method', '@authority', '@path'] }, m)
    expect(await verify(s, { body: m.body, requireBodyBinding: true })).toMatchObject({ ok: false, reason: 'body-not-bound' })
    expect(await verify(s, { body: '', requireBodyBinding: true })).toMatchObject({ ok: true })
  })

  it('a tampered covered header or component invalidates the signature', async () => {
    const m = await withDigest()
    const s = await signed({ components: ['@method', '@authority', '@path', 'content-type'] }, m)
    expect(await verify({ ...s, headers: { ...s.headers, 'content-type': 'text/plain' } })).toMatchObject({ ok: false, reason: 'invalid-signature' })
    expect(await verify({ ...s, url: 'https://api.example.com/refunds' })).toMatchObject({ ok: false, reason: 'invalid-signature' })
    expect(await verify({ ...s, method: 'DELETE' })).toMatchObject({ ok: false, reason: 'invalid-signature' })
  })

  it('rejects a signature made with a different key', async () => {
    const s = await signed({ key: { alg: 'ed25519', privateKey: otherKeys.privateKey } }, await withDigest())
    expect(await verify(s)).toMatchObject({ ok: false, reason: 'invalid-signature' })
  })

  it('rejects an unknown key id', async () => {
    const s = await signed({ keyId: 'stranger' }, await withDigest())
    expect(await verify(s)).toMatchObject({ ok: false, reason: 'no-key' })
  })

  it('takes the algorithm from the key, so an HMAC keyed with the public key cannot pass as ed25519', async () => {
    const attackerSigned = await signed({ key: { alg: 'hmac-sha256', secret: keys.publicKey } }, await withDigest())
    expect(await verify(attackerSigned)).toMatchObject({ ok: false, reason: 'invalid-signature' })
    const claimsAlg = await signed({ key: { alg: 'hmac-sha256', secret: 'x' }, includeAlg: true }, await withDigest())
    expect(await verify(claimsAlg)).toMatchObject({ ok: false, reason: 'algorithm-mismatch' })
  })

  it('enforces freshness: future, too old, expired, missing created', async () => {
    const m = await withDigest()
    const at = (created: number | false, extra: Partial<Parameters<typeof signMessage>[1]> = {}) => signed({ created, ...extra }, m)
    expect(await verify(await at(NOW / 1000 + 120))).toMatchObject({ ok: false, reason: 'not-yet-valid' })
    expect(await verify(await at(NOW / 1000 - 600))).toMatchObject({ ok: false, reason: 'too-old' })
    expect(await verify(await at(NOW / 1000 - 600), { maxAgeMs: 20 * 60_000 })).toMatchObject({ ok: true })
    expect(await verify(await at(NOW / 1000, { expires: NOW / 1000 }))).toMatchObject({ ok: false, reason: 'expired' })
    expect(await verify(await at(false))).toMatchObject({ ok: false, reason: 'missing-created' })
  })

  it('tolerates small skew but not large', async () => {
    const m = await withDigest()
    expect(await verify(await signed({ created: NOW / 1000 + 20 }, m))).toMatchObject({ ok: true })
    expect(await verify(await signed({ created: NOW / 1000 + 40 }, m))).toMatchObject({ ok: false, reason: 'not-yet-valid' })
  })

  it('a signature for another tag is not accepted for this application', async () => {
    const s = await signed({ tag: 'some-other-app' }, await withDigest())
    expect(await verify(s)).toMatchObject({ ok: false, reason: 'tag-mismatch' })
  })

  it('nonces are single use, and a missing nonce is refused when a store is configured', async () => {
    const store = new MemoryReplayStore({ now: () => NOW })
    const m = await withDigest()
    const s = await signed({ nonce: 'n-1' }, m)
    expect((await verify(s, { nonceStore: store })).ok).toBe(true)
    expect(await verify(s, { nonceStore: store })).toMatchObject({ ok: false, reason: 'replayed' })
    expect(await verify(await signed({}, m), { nonceStore: store })).toMatchObject({ ok: false, reason: 'missing-nonce' })
  })

  it('does not consume the nonce for a signature that is otherwise invalid', async () => {
    const store = new MemoryReplayStore({ now: () => NOW })
    const m = await withDigest()
    const s = await signed({ nonce: 'n-2' }, m)
    expect(await verify({ ...s, method: 'PUT' }, { nonceStore: store })).toMatchObject({ ok: false, reason: 'invalid-signature' })
    expect((await verify(s, { nonceStore: store })).ok).toBe(true)
  })

  it('generates a fresh random nonce when asked', async () => {
    const a = await signMessage(await withDigest(), { components: ['@method'], key: { alg: 'ed25519', privateKey: keys.privateKey }, nonce: true })
    const b = await signMessage(await withDigest(), { components: ['@method'], key: { alg: 'ed25519', privateKey: keys.privateKey }, nonce: true })
    expect(a.signatureInput).toMatch(/nonce="[0-9a-f]{32}"/)
    expect(a.signatureInput).not.toBe(b.signatureInput)
  })

  it('only the first matching signature is considered: appending one you can forge does not help', async () => {
    const m = await withDigest()
    const good = await signed({ label: 'good', components: ['@method', '@authority', '@path'] }, m)
    const attacker = await signMessage(m, {
      label: 'evil',
      components: ['@method', '@authority', '@path'],
      key: { alg: 'ed25519', privateKey: otherKeys.privateKey },
      keyId: 'agent-key',
      created: NOW / 1000,
      tag: 'agent',
    })
    // Attacker's signature listed FIRST: it fails, and the valid one behind it is not consulted.
    const combined: HttpMessage = {
      ...good,
      headers: {
        ...good.headers,
        'signature-input': `${attacker.signatureInput}, ${good.headers['signature-input']}`,
        signature: `${attacker.signature}, ${good.headers.signature}`,
      },
    }
    expect(await verify(combined)).toMatchObject({ ok: false, reason: 'invalid-signature' })
    // A label selects the intended one explicitly.
    expect((await verify(combined, { label: 'good' })).ok).toBe(true)
  })

  it('signs and verifies a response that covers its request via ;req', async () => {
    const req: HttpMessage = { method: 'POST', url: 'https://api.example.com/payments', headers: {} }
    const res: HttpMessage = { status: 200, headers: { 'content-type': 'application/json' } }
    const s = await signMessage(res, {
      components: ['@status', 'content-type', '@method;req', '@path;req'],
      key: { alg: 'ed25519', privateKey: keys.privateKey },
      keyId: 'agent-key',
      created: NOW / 1000,
      request: req,
    })
    const signedRes = { ...res, headers: { ...res.headers, ...s.headers } }
    const opts = { resolveKey: resolve(), requiredComponents: ['@status', '@path;req'], now: NOW }
    expect((await verifyMessage(signedRes, { ...opts, request: req })).ok).toBe(true)
    // Bound to THAT request: the same response cannot be replayed for a different one.
    expect(await verifyMessage(signedRes, { ...opts, request: { ...req, url: 'https://api.example.com/refunds' } })).toMatchObject({
      ok: false,
      reason: 'invalid-signature',
    })
  })

  it('works with HMAC keys given as text', async () => {
    const m = await withDigest()
    const s = await signMessage(m, { components: ['@method', '@authority'], key: { alg: 'hmac-sha256', secret: 'shared' }, keyId: 'k', created: NOW / 1000 })
    const key: VerificationKey = { alg: 'hmac-sha256', secret: 'shared' }
    const r = await verifyMessage({ ...m, headers: { ...m.headers, ...s.headers } }, { resolveKey: () => key, requiredComponents: ['@method'], now: NOW })
    expect(r.ok).toBe(true)
  })
})

describe('parsing hostile input', () => {
  const at = (input: string, sig = 'a=:AAAA:') => parseSignatures({ 'signature-input': input, signature: sig })

  it('parses a labelled signature with parameters', () => {
    const [p] = at('a=("@method" "x-foo";req);created=1;keyid="k";nonce="n";alg="ed25519";tag="t";expires=9')
    expect(p.components).toEqual(['"@method"', '"x-foo";req'])
    expect(p.params).toEqual({ created: 1, keyid: 'k', nonce: 'n', alg: 'ed25519', tag: 't', expires: 9 })
  })

  it.each([
    ['not structured'],
    ['a=("@method"'],
    ['a=("@method");created="soon"'],
    ['a=("@method");created=1.5'],
    ['a=("@method");created=-1'],
    ['a=("@method");created=1;created=2'],
    ['a=("@method";sf=3)'],
    ['a=("café")'],
    ['a=("@method")junk'],
    ['a=("@method"),a=("@path")'],
  ])('rejects %s', (input) => {
    expect(() => at(input, 'a=:AAAA:')).toThrow(HttpSignatureError)
  })

  it('rejects a Signature-Input label that has no Signature, and malformed Signature values', () => {
    expect(() => at('a=("@method")', 'b=:AAAA:')).toThrow(/signature-missing-for-label/)
    expect(() => at('a=("@method")', 'a=AAAA')).toThrow()
    expect(() => at('a=("@method")', 'a=:***:')).toThrow()
  })

  it('rejects oversized fields and too many signatures or components', () => {
    expect(() => at('a=("@method")' + ';x="' + 'y'.repeat(9000) + '"')).toThrow(/field-too-large/)
    const many = Array.from({ length: 17 }, (_, i) => `s${i}=("@method")`).join(', ')
    const sigs = Array.from({ length: 17 }, (_, i) => `s${i}=:AAAA:`).join(', ')
    expect(() => parseSignatures({ 'signature-input': many, signature: sigs })).toThrow(/too-many-signatures/)
    const comps = Array.from({ length: 33 }, (_, i) => `"h${i}"`).join(' ')
    expect(() => at(`a=(${comps})`)).toThrow(/too-many-components/)
  })

  it('verifyMessage reports malformed input as a failure, never an exception', async () => {
    const r = await verifyMessage(
      { method: 'GET', url: 'https://e.com/', headers: { 'signature-input': '\u0000\u0001', signature: 'x' } },
      { resolveKey: () => null, requiredComponents: ['@method'] },
    )
    expect(r).toMatchObject({ ok: false, reason: 'malformed-signature' })
  })
})

describe('dictionary members (RFC 9421 §2.1.2)', () => {
  const m: HttpMessage = { method: 'GET', url: 'https://e.com/', headers: { 'Example-Dict': 'a=1, b=2;x=1;y=2, c=(a   b    c), d' } }
  it('re-serializes members exactly as the RFC shows', () => {
    const lines = createSignatureBase(m, ['example-dict;key="a"', 'example-dict;key="d"', 'example-dict;key="b"', 'example-dict;key="c"'], {}).split('\n').slice(0, -1)
    expect(lines).toEqual([
      '"example-dict";key="a": 1',
      '"example-dict";key="d": ?1',
      '"example-dict";key="b": 2;x=1;y=2',
      '"example-dict";key="c": (a b c)',
    ])
  })

  it('a missing member is an error, and `key` is refused on derived components', () => {
    expect(() => createSignatureBase(m, ['example-dict;key="z"'], {})).toThrow(/component-not-found/)
    expect(() => createSignatureBase(m, ['@method;key="a"'], {})).toThrow(/unsupported-component-parameter/)
  })

  it('combines multiple field lines into one dictionary', () => {
    const two: HttpMessage = { ...m, headers: { 'Example-Dict': ['a=1', 'b=2'] } }
    expect(createSignatureBase(two, ['example-dict;key="b"'], {}).split('\n')[0]).toBe('"example-dict";key="b": 2')
  })
})
