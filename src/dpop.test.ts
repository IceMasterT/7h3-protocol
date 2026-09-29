import { describe, it, expect, beforeAll } from 'vitest'
import {
  DpopNonceIssuer,
  accessTokenHash,
  createDpopProof,
  dpopAuthorization,
  dpopConfirmation,
  dpopHtu,
  dpopJwkThumbprint,
  generateDpopKeyPair,
  parseDpopAuthorization,
  verifyDpopProof,
  type DpopKeyPair,
  type VerifyDpopProofOptions,
} from './dpop'
import { MemoryReplayStore } from './replayStores'

// ---------------------------------------------------------------------------
// RFC 9449 §7.1 / Figure 13: a resource request with a DPoP-bound access token
// ---------------------------------------------------------------------------

const RFC_PROOF =
  'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA'
const RFC_TOKEN = 'Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU'
const RFC_JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I'
const RFC_IAT_MS = 1562262618 * 1000
const RFC_URL = 'https://resource.example.org/protectedresource'

describe('RFC 9449 published values', () => {
  it('computes the JWK thumbprint the RFC gives for the example key, and the ath for the example token', async () => {
    expect(
      await dpopJwkThumbprint({ kty: 'EC', crv: 'P-256', x: 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs', y: '9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA' }),
    ).toBe(RFC_JKT)
    expect(await accessTokenHash(RFC_TOKEN)).toBe('fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo')
  })

  it('verifies the RFC example proof as received', async () => {
    const r = await verifyDpopProof(RFC_PROOF, {
      method: 'GET',
      url: RFC_URL,
      accessToken: RFC_TOKEN,
      expectedJkt: RFC_JKT,
      now: RFC_IAT_MS + 1000,
    })
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.jkt).toBe(RFC_JKT)
      expect(r.claims).toMatchObject({ jti: 'e1j3V_bKic8-LAEB', htm: 'GET', htu: RFC_URL })
    }
  })

  it('refuses the same proof for a different method, URL, token or bound key', async () => {
    const base: VerifyDpopProofOptions = { method: 'GET', url: RFC_URL, accessToken: RFC_TOKEN, expectedJkt: RFC_JKT, now: RFC_IAT_MS }
    expect(await verifyDpopProof(RFC_PROOF, { ...base, method: 'POST' })).toEqual({ ok: false, reason: 'htm-mismatch' })
    expect(await verifyDpopProof(RFC_PROOF, { ...base, url: 'https://resource.example.org/other' })).toEqual({ ok: false, reason: 'htu-mismatch' })
    expect(await verifyDpopProof(RFC_PROOF, { ...base, accessToken: RFC_TOKEN + 'x' })).toEqual({ ok: false, reason: 'ath-mismatch' })
    expect(await verifyDpopProof(RFC_PROOF, { ...base, expectedJkt: 'other' })).toEqual({ ok: false, reason: 'key-not-bound' })
    expect(await verifyDpopProof(RFC_PROOF, { ...base, now: RFC_IAT_MS + 10 * 60_000 })).toEqual({ ok: false, reason: 'expired' })
  })

  it('a tampered payload breaks the RFC proof signature', async () => {
    const [h, p, s] = RFC_PROOF.split('.')
    const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')))
    payload.htm = 'POST'
    const forged = `${h}.${btoa(JSON.stringify(payload)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')}.${s}`
    expect(await verifyDpopProof(forged, { method: 'POST', url: RFC_URL, now: RFC_IAT_MS })).toEqual({ ok: false, reason: 'invalid-signature' })
  })
})

// ---------------------------------------------------------------------------
// Our own proofs, both algorithms
// ---------------------------------------------------------------------------

let es: DpopKeyPair
let ed: DpopKeyPair
let other: DpopKeyPair
const NOW = 1_800_000_000_000
const URL_ = 'https://api.example.com/v1/pay?amount=5#frag'

beforeAll(async () => {
  es = await generateDpopKeyPair('ES256')
  ed = await generateDpopKeyPair('EdDSA')
  other = await generateDpopKeyPair('ES256')
})

const proof = (key: DpopKeyPair, over: Partial<Parameters<typeof createDpopProof>[0]> = {}) =>
  createDpopProof({ key, method: 'post', url: URL_, iat: NOW / 1000, ...over })
const verify = (p: string | string[] | undefined, over: Partial<VerifyDpopProofOptions> = {}) =>
  verifyDpopProof(p, { method: 'POST', url: 'https://api.example.com/v1/pay?amount=5000', now: NOW, ...over })

describe.each([
  ['ES256', () => es],
  ['EdDSA', () => ed],
])('%s proofs', (_alg, key) => {
  it('round-trips, ignoring query and fragment, and reports the key thumbprint', async () => {
    const r = await verify(await proof(key()))
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.jkt).toBe(await dpopJwkThumbprint(key().publicJwk))
  })

  it('binds an access token: ath matches and the key must be the one the token is bound to', async () => {
    const token = 'opaque-token-123'
    const jkt = await dpopJwkThumbprint(key().publicJwk)
    const p = await proof(key(), { accessToken: token })
    expect((await verify(p, { accessToken: token, expectedJkt: jkt })).ok).toBe(true)
    expect(await verify(p, { accessToken: 'stolen-token', expectedJkt: jkt })).toEqual({ ok: false, reason: 'ath-mismatch' })
    // A thief with the token who signs with their OWN key is refused: the token is bound to another key.
    const thiefProof = await proof(other, { accessToken: token })
    expect(await verify(thiefProof, { accessToken: token, expectedJkt: jkt })).toEqual({ ok: false, reason: 'key-not-bound' })
  })
})

describe('verification policy', () => {
  it('refuses missing, empty and duplicate proofs', async () => {
    expect(await verify(undefined)).toEqual({ ok: false, reason: 'missing-proof' })
    expect(await verify('')).toEqual({ ok: false, reason: 'missing-proof' })
    const p = await proof(es)
    expect(await verify([p, p])).toEqual({ ok: false, reason: 'multiple-proofs' })
  })

  it('a proof without ath is refused when a token is presented', async () => {
    const jkt = await dpopJwkThumbprint(es.publicJwk)
    expect(await verify(await proof(es), { accessToken: 't', expectedJkt: jkt })).toEqual({ ok: false, reason: 'ath-required' })
  })

  it('demands expectedJkt whenever a token is presented (a programming error, not a runtime condition)', async () => {
    await expect(verify(await proof(es, { accessToken: 't' }), { accessToken: 't' })).rejects.toThrow(/expectedJkt/)
  })

  it('enforces freshness with small skew tolerance', async () => {
    const p = await proof(es)
    expect((await verify(p, { now: NOW + 30_000 })).ok).toBe(true)
    expect(await verify(p, { now: NOW + 5 * 60_000 })).toEqual({ ok: false, reason: 'expired' })
    expect((await verify(p, { now: NOW - 20_000 })).ok).toBe(true)
    expect(await verify(p, { now: NOW - 5 * 60_000 })).toEqual({ ok: false, reason: 'not-yet-valid' })
  })

  it('proofs are single use, and a rejected presentation does not burn the jti', async () => {
    const store = new MemoryReplayStore({ now: () => NOW })
    const p = await proof(es)
    expect(await verify(p, { method: 'GET', replayStore: store })).toEqual({ ok: false, reason: 'htm-mismatch' })
    expect((await verify(p, { replayStore: store })).ok).toBe(true)
    expect(await verify(p, { replayStore: store })).toEqual({ ok: false, reason: 'replayed' })
  })

  it('the same jti from a different key is a different proof', async () => {
    const store = new MemoryReplayStore({ now: () => NOW })
    expect((await verify(await proof(es, { jti: 'same' }), { replayStore: store })).ok).toBe(true)
    expect((await verify(await proof(other, { jti: 'same' }), { replayStore: store })).ok).toBe(true)
  })

  it('htu comparison ignores query and fragment and normalizes scheme, host and default port', async () => {
    const p = await proof(es, { url: 'HTTPS://API.Example.com:443/v1/pay' })
    expect((await verify(p)).ok).toBe(true)
    expect(await verify(await proof(es, { url: 'https://api.example.com/v1/refund' }))).toEqual({ ok: false, reason: 'htu-mismatch' })
    expect(await verify(await proof(es, { url: 'http://api.example.com/v1/pay' }))).toEqual({ ok: false, reason: 'htu-mismatch' })
  })

  it('dpopHtu drops the query and fragment', () => {
    expect(dpopHtu(URL_)).toBe('https://api.example.com/v1/pay')
  })

  it('honours the allowed algorithm list', async () => {
    expect(await verify(await proof(ed), { allowedAlgs: ['ES256'] })).toEqual({ ok: false, reason: 'unsupported-alg' })
  })
})

describe('malformed and hostile proofs', () => {
  const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
  const parts = async (key = es) => (await proof(key)).split('.')
  const rebuild = (h: unknown, p: unknown, s: string) => `${b64(h)}.${b64(p)}.${s}`

  it.each(['x', 'a.b', 'a.b.c.d', '....', 'not a jwt at all', 'e30.e30.'])('rejects %s', async (jwt) => {
    const r = await verify(jwt)
    expect(r.ok).toBe(false)
  })

  it('rejects an oversized proof', async () => {
    expect(await verify('a'.repeat(9000) + '.b.c')).toEqual({ ok: false, reason: 'malformed' })
  })

  it('rejects a wrong typ, alg none, HMAC algorithms and unknown algorithms', async () => {
    const [h, p, s] = await parts()
    const header = JSON.parse(atob(h.replace(/-/g, '+').replace(/_/g, '/')))
    const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')))
    expect(await verify(rebuild({ ...header, typ: 'JWT' }, payload, s))).toEqual({ ok: false, reason: 'bad-typ' })
    for (const alg of ['none', 'HS256', 'RS256', 'ES384', '']) {
      expect(await verify(rebuild({ ...header, alg }, payload, s))).toEqual({ ok: false, reason: 'unsupported-alg' })
    }
  })

  it('rejects a jwk carrying a private member, however it is spelled', async () => {
    const [h, p, s] = await parts()
    const header = JSON.parse(atob(h.replace(/-/g, '+').replace(/_/g, '/')))
    const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')))
    for (const member of ['d', 'p', 'k', 'priv']) {
      expect(await verify(rebuild({ ...header, jwk: { ...header.jwk, [member]: 'AAAA' } }, payload, s))).toEqual({ ok: false, reason: 'bad-jwk' })
    }
  })

  it('rejects a missing jwk, a jwk whose type disagrees with alg, and unsupported curves', async () => {
    const [h, p, s] = await parts()
    const header = JSON.parse(atob(h.replace(/-/g, '+').replace(/_/g, '/')))
    const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')))
    expect(await verify(rebuild({ typ: header.typ, alg: header.alg }, payload, s))).toEqual({ ok: false, reason: 'bad-jwk' })
    expect(await verify(rebuild({ ...header, alg: 'EdDSA' }, payload, s))).toEqual({ ok: false, reason: 'bad-jwk' })
    expect(await verify(rebuild({ ...header, jwk: { ...header.jwk, crv: 'P-384' } }, payload, s))).toEqual({ ok: false, reason: 'bad-jwk' })
    expect(await verify(rebuild({ ...header, jwk: { kty: 'RSA', n: 'x', e: 'AQAB' } }, payload, s))).toEqual({ ok: false, reason: 'bad-jwk' })
  })

  it('rejects a jwk whose point is not on the curve', async () => {
    const [h, p, s] = await parts()
    const header = JSON.parse(atob(h.replace(/-/g, '+').replace(/_/g, '/')))
    const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')))
    const bad = { ...header.jwk, y: 'A'.repeat(43) }
    const r = await verify(rebuild({ ...header, jwk: bad }, payload, s))
    expect(r.ok).toBe(false)
  })

  it('rejects critical headers it does not understand', async () => {
    const [h, p, s] = await parts()
    const header = JSON.parse(atob(h.replace(/-/g, '+').replace(/_/g, '/')))
    const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')))
    expect(await verify(rebuild({ ...header, crit: ['exp'] }, payload, s))).toEqual({ ok: false, reason: 'unsupported-critical-header' })
  })

  it('rejects an ES256 signature of the wrong length', async () => {
    const [h, p] = await parts()
    expect(await verify(`${h}.${p}.${'A'.repeat(20)}`)).toEqual({ ok: false, reason: 'invalid-signature' })
  })

  it('rejects a proof signed by a different key than the jwk it carries', async () => {
    const [h, p] = (await proof(es)).split('.')
    const [, , s] = (await proof(other)).split('.')
    expect(await verify(`${h}.${p}.${s}`)).toEqual({ ok: false, reason: 'invalid-signature' })
  })

  it('rejects missing or mistyped claims', async () => {
    // Re-sign with our own key so only the claim shape is at fault.
    for (const claims of [{ htm: 'POST', htu: 'https://api.example.com/v1/pay', iat: NOW / 1000 }, { jti: 'a', htu: 'https://api.example.com/v1/pay', iat: NOW / 1000 }, { jti: 'a', htm: 'POST', htu: 'https://api.example.com/v1/pay', iat: 'now' }]) {
      const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: es.publicJwk }
      const signingInput = `${b64(header)}.${b64(claims)}`
      const key = await crypto.subtle.importKey('jwk', es.privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
      const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(signingInput)))
      const s = btoa(String.fromCharCode(...sig)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
      expect(await verify(`${signingInput}.${s}`)).toEqual({ ok: false, reason: 'missing-claim' })
    }
  })
})

describe('server nonces', () => {
  it('a required nonce must be present and valid', async () => {
    const issuer = new DpopNonceIssuer('a-sufficiently-long-secret', { now: () => NOW })
    const nonce = await issuer.issue()
    const policy = { required: true, validate: (n: string) => issuer.validate(n) }
    expect((await verify(await proof(es, { nonce }), { nonce: policy })).ok).toBe(true)
    expect(await verify(await proof(es), { nonce: policy })).toEqual({ ok: false, reason: 'nonce-required' })
    expect(await verify(await proof(es, { nonce: 'made-up' }), { nonce: policy })).toEqual({ ok: false, reason: 'nonce-mismatch' })
  })

  it('nonces expire, cannot be forged, and are bound to the secret', async () => {
    let t = NOW
    const issuer = new DpopNonceIssuer('a-sufficiently-long-secret', { now: () => t, lifetimeMs: 60_000 })
    const nonce = await issuer.issue()
    expect(await issuer.validate(nonce)).toBe(true)
    t += 61_000
    expect(await issuer.validate(nonce)).toBe(false)
    t = NOW
    expect(await new DpopNonceIssuer('a-different-long-secret', { now: () => t }).validate(nonce)).toBe(false)
    const [issued, mac] = nonce.split('.')
    expect(await issuer.validate(`${Number(issued) + 1}.${mac}`)).toBe(false)
    expect(await issuer.validate('junk')).toBe(false)
  })

  it('refuses short secrets', () => {
    expect(() => new DpopNonceIssuer('short')).toThrow()
  })
})

describe('Authorization header helpers', () => {
  it('formats and parses the DPoP scheme only', () => {
    expect(dpopAuthorization('tok')).toBe('DPoP tok')
    expect(parseDpopAuthorization('DPoP abc.def-ghi_jkl~m+n/o=')).toBe('abc.def-ghi_jkl~m+n/o=')
    expect(parseDpopAuthorization('dpop tok')).toBe('tok')
    expect(parseDpopAuthorization('Bearer tok')).toBeNull()
    expect(parseDpopAuthorization('DPoP')).toBeNull()
    expect(parseDpopAuthorization('DPoP a b')).toBeNull()
    expect(parseDpopAuthorization(undefined)).toBeNull()
  })

  it('builds the confirmation claim', () => {
    expect(dpopConfirmation('abc')).toEqual({ cnf: { jkt: 'abc' } })
  })
})
