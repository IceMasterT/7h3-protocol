import { describe, it, expect, beforeAll } from 'vitest'
import {
  base58btcDecode,
  base58btcEncode,
  canonicalizeJcs,
  createDidKeyRegistry,
  didKeyDocument,
  didKeyFromEd25519,
  ed25519FromDidKey,
  ed25519PublicToX25519,
  isSpiffeIdAllowed,
  parseSpiffeId,
  signAgentCard,
  verifyAgentCard,
  type SignedAgentCard,
} from './agentIdentity'
import { generateDpopKeyPair, type DpopKeyPair } from './dpop'
import { bytesToB64u, jwkThumbprint, jwsSign } from './jose'
import { generateEd25519KeypairBase64Url } from './protocol'
import { spkiToEd25519Jwk } from './webBotAuth'

describe('canonicalizeJcs (RFC 8785)', () => {
  it('reproduces the RFC 8785 §3.2.2 / §3.2.3 sample', () => {
    const input = JSON.parse(
      '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", "literals": [null, true, false]}',
    )
    expect(canonicalizeJcs(input)).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    )
  })

  it('sorts property names by UTF-16 code unit, as the RFC requires (not by UTF-8)', () => {
    const input = {
      '€': 'Euro Sign',
      '\r': 'Carriage Return',
      'דּ': 'Hebrew Letter Dalet With Dagesh',
      '1': 'One',
      '😀': 'Emoji: Grinning Face',
      '\u0080': 'Control',
      'ö': 'Latin Small Letter O With Diaeresis',
    }
    // Read the values back out of the canonical TEXT: parsing it into an object would let the
    // JavaScript engine reorder integer-like keys such as "1" ahead of the others.
    const values = [...canonicalizeJcs(input).matchAll(/":"([^"]*)"/g)].map((m) => m[1])
    expect(values).toEqual([
      'Carriage Return',
      'One',
      'Control',
      'Latin Small Letter O With Diaeresis',
      'Euro Sign',
      'Emoji: Grinning Face',
      'Hebrew Letter Dalet With Dagesh',
    ])
  })

  it.each([
    ['0000000000000000', '0'],
    ['8000000000000000', '0'],
    ['0000000000000001', '5e-324'],
    ['8000000000000001', '-5e-324'],
    ['7fefffffffffffff', '1.7976931348623157e+308'],
    ['ffefffffffffffff', '-1.7976931348623157e+308'],
    ['4340000000000000', '9007199254740992'],
    ['c340000000000000', '-9007199254740992'],
    ['4430000000000000', '295147905179352830000'],
    ['44b52d02c7e14af5', '9.999999999999997e+22'],
    ['44b52d02c7e14af6', '1e+23'],
    ['44b52d02c7e14af7', '1.0000000000000001e+23'],
    ['444b1ae4d6e2ef4e', '999999999999999700000'],
    ['444b1ae4d6e2ef4f', '999999999999999900000'],
    ['444b1ae4d6e2ef50', '1e+21'],
    ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
    ['3eb0c6f7a0b5ed8d', '0.000001'],
    ['41b3de4355555553', '333333333.3333332'],
    ['41b3de4355555555', '333333333.3333333'],
    ['41b3de4355555557', '333333333.33333343'],
    ['becbf647612f3696', '-0.0000033333333333333333'],
    ['43143ff3c1cb0959', '1424953923781206.2'],
  ])('number serialization sample %s -> %s (RFC 8785 Appendix B)', (hex, expected) => {
    const view = new DataView(new ArrayBuffer(8))
    view.setBigUint64(0, BigInt('0x' + hex))
    expect(canonicalizeJcs(view.getFloat64(0))).toBe(expected)
  })

  it('refuses values JSON cannot represent', () => {
    expect(() => canonicalizeJcs(NaN)).toThrow()
    expect(() => canonicalizeJcs(Infinity)).toThrow()
    expect(() => canonicalizeJcs({ a: undefined })).toThrow()
  })
})

describe('base58btc', () => {
  it('matches the well-known Bitcoin vectors', () => {
    expect(base58btcEncode(new TextEncoder().encode('Hello World!'))).toBe('2NEpo7TZRRrLZSi2U')
    expect(base58btcEncode(Uint8Array.from([0, 0, 1]))).toBe('112')
    expect(base58btcEncode(new Uint8Array())).toBe('')
    expect(base58btcEncode(Uint8Array.from([0, 0, 0]))).toBe('111')
  })

  it('round-trips, preserving leading zero bytes', () => {
    for (const bytes of [[0], [0, 0, 1], [255, 255], [1, 2, 3, 4, 5, 250], Array.from({ length: 34 }, (_, i) => (i * 37) & 0xff)]) {
      expect([...base58btcDecode(base58btcEncode(Uint8Array.from(bytes)))!]).toEqual(bytes)
    }
  })

  it('rejects characters outside the alphabet', () => {
    for (const bad of ['0', 'O', 'I', 'l', 'abc+', ' ', 'é']) expect(base58btcDecode(bad)).toBeNull()
  })
})

describe('did:key', () => {
  const SPEC_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
  const SPEC_X25519 = 'z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p' // keyAgreement key in the did:key spec's DID document

  it('round-trips the did:key spec example', () => {
    const spki = ed25519FromDidKey(SPEC_DID)
    expect(spki).not.toBeNull()
    expect(didKeyFromEd25519(spki!)).toBe(SPEC_DID)
  })

  it("derives the X25519 keyAgreement key the spec's DID document lists for that DID", () => {
    const doc = didKeyDocument(SPEC_DID)!
    expect(doc.keyAgreement[0].publicKeyMultibase).toBe(SPEC_X25519)
    expect(doc.id).toBe(SPEC_DID)
    expect(doc.verificationMethod[0]).toMatchObject({ type: 'Multikey', controller: SPEC_DID, publicKeyMultibase: SPEC_DID.slice('did:key:'.length) })
    expect(doc.authentication).toEqual([`${SPEC_DID}#${SPEC_DID.slice('did:key:'.length)}`])
  })

  it('maps a generated Ed25519 key to a did:key and back', async () => {
    const kp = await generateEd25519KeypairBase64Url()
    const did = didKeyFromEd25519(kp.publicKey)
    expect(did).toMatch(/^did:key:z6Mk/)
    expect(ed25519FromDidKey(did)).toBe(kp.publicKey)
  })

  it('accepts a matching key-reference fragment and nothing else', () => {
    const id = SPEC_DID.slice('did:key:'.length)
    expect(ed25519FromDidKey(`${SPEC_DID}#${id}`)).not.toBeNull()
    expect(ed25519FromDidKey(`${SPEC_DID}#z6MkabcDEFGHJKLMN`)).toBeNull() // well-formed multibase, but not this key's own id
    expect(ed25519FromDidKey(`${SPEC_DID}/path`)).toBeNull()
    expect(ed25519FromDidKey(`${SPEC_DID}?x=1`)).toBeNull()
  })

  it.each([
    'did:web:example.com',
    'did:key:',
    'did:key:z',
    'did:key:z6Mk',
    'did:key:' + SPEC_DID.slice('did:key:z'.length), // no multibase prefix
    'did:key:z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p', // an X25519 key, not Ed25519
    'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme', // a secp256k1 key
    SPEC_DID + '0', // '0' is not base58
    'not a did',
    '',
  ])('rejects %s', (did) => {
    expect(ed25519FromDidKey(did)).toBeNull()
    expect(didKeyDocument(did)).toBeNull()
  })

  it('a key that is not 32 bytes is rejected, and an SPKI that is not Ed25519 throws', () => {
    expect(ed25519FromDidKey('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2do')).toBeNull()
    expect(() => didKeyFromEd25519('AAAA')).toThrow()
    expect(() => ed25519PublicToX25519('AAAA')).toThrow()
  })

  it('the registry resolves did:key senders and nobody else', async () => {
    const kp = await generateEd25519KeypairBase64Url()
    const reg = createDidKeyRegistry()
    expect(await reg.getPublicKey(didKeyFromEd25519(kp.publicKey))).toBe(kp.publicKey)
    expect(await reg.getPublicKey('agent@example.com')).toBeNull()
    expect(await reg.getPublicKey('did:web:example.com')).toBeNull()
  })
})

describe('SPIFFE IDs', () => {
  it('parses valid IDs', () => {
    expect(parseSpiffeId('spiffe://example.org/ns/prod/agent-1')).toEqual({ trustDomain: 'example.org', path: '/ns/prod/agent-1' })
    expect(parseSpiffeId('spiffe://example.org')).toEqual({ trustDomain: 'example.org', path: '' })
    expect(parseSpiffeId('spiffe://a-b_c.d/x.y_z-1')).toMatchObject({ trustDomain: 'a-b_c.d' })
  })

  it.each([
    'http://example.org/x',
    'spiffe://',
    'spiffe:///path',
    'spiffe://Example.org/x', // upper-case trust domain
    'spiffe://user@example.org/x',
    'spiffe://example.org:8080/x',
    'spiffe://example.org/x?y=1',
    'spiffe://example.org/x#frag',
    'spiffe://example.org/x/',
    'spiffe://example.org//x',
    'spiffe://example.org/./x',
    'spiffe://example.org/../x',
    'spiffe://example.org/a b',
    'spiffe://example.org/' + 'a'.repeat(3000),
  ])('rejects %s', (id) => {
    expect(parseSpiffeId(id)).toBeNull()
  })

  it('applies trust domain and path policy', () => {
    const policy = { trustDomains: ['example.org'], pathPrefixes: ['/ns/prod'] }
    expect(isSpiffeIdAllowed('spiffe://example.org/ns/prod', policy)).toBe(true)
    expect(isSpiffeIdAllowed('spiffe://example.org/ns/prod/agent-1', policy)).toBe(true)
    expect(isSpiffeIdAllowed('spiffe://example.org/ns/production', policy)).toBe(false) // prefix must end at a segment boundary
    expect(isSpiffeIdAllowed('spiffe://evil.org/ns/prod/agent-1', policy)).toBe(false)
    expect(isSpiffeIdAllowed('spiffe://example.org/other', policy)).toBe(false)
    expect(isSpiffeIdAllowed('spiffe://example.org/anything', { trustDomains: ['example.org'] })).toBe(true)
    expect(isSpiffeIdAllowed('garbage', { trustDomains: ['example.org'] })).toBe(false)
    expect(() => isSpiffeIdAllowed('spiffe://example.org', { trustDomains: [] })).toThrow()
  })
})

describe('Agent Card signatures (A2A §8.4)', () => {
  let ed: DpopKeyPair
  let es: DpopKeyPair
  let other: DpopKeyPair
  const card = () => ({
    name: 'GeoSpatial Route Planner Agent',
    description: 'Plans routes.',
    supportedInterfaces: [{ url: 'https://georoute.example.com/a2a/v1', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
    provider: { organization: 'Example Geo', url: 'https://example.com' },
    version: '1.2.0',
    capabilities: { streaming: true },
    skills: [{ id: 'route-plan', name: 'Route planning', description: 'Optimal routes.' }],
  })

  beforeAll(async () => {
    ed = await generateDpopKeyPair('EdDSA')
    es = await generateDpopKeyPair('ES256')
    other = await generateDpopKeyPair('EdDSA')
  })

  const resolver = (keys: Record<string, DpopKeyPair>) => (kid: string) => keys[kid]?.publicJwk ?? null

  describe.each([
    ['EdDSA', () => ed],
    ['ES256', () => es],
  ])('%s', (_name, key) => {
    it('signs and verifies', async () => {
      const signed = await signAgentCard(card(), { privateJwk: key().privateJwk, keyId: 'k1', jku: 'https://georoute.example.com/jwks.json' })
      const r = await verifyAgentCard(signed, { resolveKey: resolver({ k1: key() }) })
      expect(r).toEqual({ ok: true, keyIds: ['k1'] })
    })
  })

  it("emits the A2A signature shape: a JWS protected header with alg, typ 'JOSE', kid and jku", async () => {
    const signed = await signAgentCard(card(), { privateJwk: ed.privateJwk, keyId: 'key-1', jku: 'https://example.com/agent/jwks.json' })
    expect(Object.keys(signed.signatures[0]).sort()).toEqual(['protected', 'signature'])
    const header = JSON.parse(atob(signed.signatures[0].protected.replace(/-/g, '+').replace(/_/g, '/')))
    expect(header).toEqual({ alg: 'EdDSA', typ: 'JOSE', kid: 'key-1', jku: 'https://example.com/agent/jwks.json' })
  })

  it('does not depend on the order of the card fields, and excludes the signatures field itself', async () => {
    const signed = await signAgentCard(card(), { privateJwk: ed.privateJwk, keyId: 'k1' })
    const reordered = Object.fromEntries(Object.entries(signed).reverse()) as SignedAgentCard
    expect((await verifyAgentCard(reordered, { resolveKey: resolver({ k1: ed }) })).ok).toBe(true)
  })

  it('any change to the card invalidates the signature', async () => {
    const signed = await signAgentCard(card(), { privateJwk: ed.privateJwk, keyId: 'k1' })
    const check = (mutate: (c: ReturnType<typeof card> & { signatures: unknown }) => void) => {
      const copy = JSON.parse(JSON.stringify(signed))
      mutate(copy)
      return verifyAgentCard(copy, { resolveKey: resolver({ k1: ed }) })
    }
    expect(await check((c) => (c.name = 'Evil Agent'))).toMatchObject({ ok: false, reason: 'no-valid-signature' })
    expect(await check((c) => c.skills.push({ id: 'exfil', name: 'x', description: 'sends secrets' }))).toMatchObject({ ok: false })
    expect(await check((c) => (c.supportedInterfaces[0].url = 'https://attacker.example/a2a'))).toMatchObject({ ok: false })
    expect(await check((c) => ((c as Record<string, unknown>).securitySchemes = {}))).toMatchObject({ ok: false })
  })

  it('an unsigned card, or a card with no usable signature, is never trusted', async () => {
    expect(await verifyAgentCard(card(), { resolveKey: resolver({}) })).toEqual({ ok: false, reason: 'no-signature' })
    expect(await verifyAgentCard({ ...card(), signatures: [] }, { resolveKey: resolver({}) })).toEqual({ ok: false, reason: 'no-signature' })
    expect(await verifyAgentCard(null, { resolveKey: resolver({}) })).toEqual({ ok: false, reason: 'not-a-card' })
    expect(await verifyAgentCard([], { resolveKey: resolver({}) })).toEqual({ ok: false, reason: 'not-a-card' })
  })

  it('rejects a signature by a key the verifier does not trust, or one that has the wrong key', async () => {
    const signed = await signAgentCard(card(), { privateJwk: ed.privateJwk, keyId: 'k1' })
    expect(await verifyAgentCard(signed, { resolveKey: resolver({}) })).toMatchObject({ ok: false, reason: 'no-valid-signature' })
    expect(await verifyAgentCard(signed, { resolveKey: resolver({ k1: other }) })).toMatchObject({ ok: false, reason: 'no-valid-signature' })
  })

  it('takes the algorithm from the trusted key, so a header claiming another algorithm is refused', async () => {
    const signed = await signAgentCard(card(), { privateJwk: ed.privateJwk, keyId: 'k1' })
    // Same signature, but the verifier's key for k1 is a P-256 key: the algorithm does not match.
    expect(await verifyAgentCard(signed, { resolveKey: () => es.publicJwk })).toMatchObject({ ok: false })
    expect(await verifyAgentCard(signed, { resolveKey: resolver({ k1: ed }), allowedAlgs: ['ES256'] })).toMatchObject({ ok: false })
  })

  it('refuses unsupported and dangerous headers: none, HMAC, crit, missing kid, oversized', async () => {
    const signed = await signAgentCard(card(), { privateJwk: ed.privateJwk, keyId: 'k1' })
    const good = JSON.parse(atob(signed.signatures[0].protected.replace(/-/g, '+').replace(/_/g, '/')))
    const forge = (header: Record<string, unknown>) => ({
      ...signed,
      signatures: [{ protected: btoa(JSON.stringify(header)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'), signature: signed.signatures[0].signature }],
    })
    for (const h of [{ ...good, alg: 'none' }, { ...good, alg: 'HS256' }, { ...good, alg: 'RS256' }, { ...good, crit: ['x'] }, { alg: 'EdDSA' }, { ...good, kid: '' }]) {
      expect(await verifyAgentCard(forge(h), { resolveKey: resolver({ k1: ed }) })).toMatchObject({ ok: false })
    }
    const huge = { ...signed, signatures: [{ protected: 'A'.repeat(5000), signature: 'AAAA' }] }
    expect(await verifyAgentCard(huge, { resolveKey: resolver({ k1: ed }) })).toMatchObject({ ok: false })
  })

  it('refuses header tricks even when the forger re-signs the tampered header with the real key', async () => {
    // A properly signed card whose header is hostile: the signature is valid over the bytes,
    // so only the verifier's own rules can refuse it.
    const enc = new TextEncoder()
    const forge = async (header: Record<string, unknown>, signWith: 'EdDSA' | 'ES256' = 'EdDSA', key = ed) => {
      const protectedB64 = bytesToB64u(enc.encode(JSON.stringify(header)))
      const payload = bytesToB64u(enc.encode(canonicalizeJcs(card())))
      const sig = await jwsSign(signWith, key.privateJwk, `${protectedB64}.${payload}`)
      return { ...card(), signatures: [{ protected: protectedB64, signature: bytesToB64u(sig) }] }
    }
    const opts = { resolveKey: resolver({ k1: ed }) }
    // Control: same construction, honest header, is accepted.
    expect((await verifyAgentCard(await forge({ alg: 'EdDSA', typ: 'JOSE', kid: 'k1' }), opts)).ok).toBe(true)
    // `crit` names extensions the verifier does not understand: it must refuse, not ignore.
    expect(await verifyAgentCard(await forge({ alg: 'EdDSA', typ: 'JOSE', kid: 'k1', crit: ['x'], x: 1 }), opts)).toMatchObject({ ok: false })
    // The header says ES256 but the trusted key is Ed25519 and the signature really is Ed25519.
    expect(await verifyAgentCard(await forge({ alg: 'ES256', typ: 'JOSE', kid: 'k1' }), opts)).toMatchObject({ ok: false })
  })

  it('supports key rotation: extra signatures are kept, at least one valid signature is enough, and requireAll can insist on all', async () => {
    const once = await signAgentCard(card(), { privateJwk: ed.privateJwk, keyId: 'old' })
    const twice = await signAgentCard(once, { privateJwk: es.privateJwk, keyId: 'new' })
    expect(twice.signatures.length).toBe(2)
    const both = resolver({ old: ed, new: es })
    expect(await verifyAgentCard(twice, { resolveKey: both })).toEqual({ ok: true, keyIds: ['old', 'new'] })
    // The old key was revoked: the new signature still carries the card.
    expect(await verifyAgentCard(twice, { resolveKey: resolver({ new: es }) })).toEqual({ ok: true, keyIds: ['new'] })
    expect(await verifyAgentCard(twice, { resolveKey: resolver({ new: es }), requireAll: true })).toMatchObject({ ok: false })
  })

  it('limits the number of signatures it will process', async () => {
    const signed = await signAgentCard(card(), { privateJwk: ed.privateJwk, keyId: 'k1' })
    const many = { ...signed, signatures: Array.from({ length: 9 }, () => signed.signatures[0]) }
    expect(await verifyAgentCard(many, { resolveKey: resolver({ k1: ed }) })).toEqual({ ok: false, reason: 'too-many-signatures' })
  })

  it('a valid card lifted onto an attacker host is refused when the origin is pinned', async () => {
    const signed = await signAgentCard(card(), { privateJwk: ed.privateJwk, keyId: 'k1' })
    const opts = { resolveKey: resolver({ k1: ed }) }
    expect((await verifyAgentCard(signed, { ...opts, expectedOrigin: 'https://georoute.example.com' })).ok).toBe(true)
    expect(await verifyAgentCard(signed, { ...opts, expectedOrigin: 'https://georoute.example.com/some/path?x=1' })).toMatchObject({ ok: true })
    expect(await verifyAgentCard(signed, { ...opts, expectedOrigin: 'https://attacker.example' })).toMatchObject({ ok: false, reason: 'origin-mismatch' })
    expect(await verifyAgentCard(signed, { ...opts, expectedOrigin: 'http://georoute.example.com' })).toMatchObject({ ok: false, reason: 'origin-mismatch' })
    await expect(verifyAgentCard(signed, { ...opts, expectedOrigin: 'not a url' })).rejects.toThrow()
  })

  it('recognizes the endpoint fields older and newer A2A versions use', async () => {
    const legacy = await signAgentCard({ name: 'a', url: 'https://old.example.com/a2a', additionalInterfaces: [{ url: 'https://alt.example.com/x' }] }, { privateJwk: ed.privateJwk, keyId: 'k1' })
    const opts = { resolveKey: resolver({ k1: ed }) }
    expect((await verifyAgentCard(legacy, { ...opts, expectedOrigin: 'https://old.example.com' })).ok).toBe(true)
    expect((await verifyAgentCard(legacy, { ...opts, expectedOrigin: 'https://alt.example.com' })).ok).toBe(true)
    expect(await verifyAgentCard(legacy, { ...opts, expectedOrigin: 'https://evil.example.com' })).toMatchObject({ ok: false })
  })

  it('passes the jku hint to resolveKey without fetching it', async () => {
    const signed = await signAgentCard(card(), { privateJwk: ed.privateJwk, keyId: 'k1', jku: 'https://example.com/jwks.json' })
    const seen: Array<[string, string | undefined]> = []
    await verifyAgentCard(signed, { resolveKey: (kid, jku) => (seen.push([kid, jku]), ed.publicJwk) })
    expect(seen).toEqual([['k1', 'https://example.com/jwks.json']])
  })

  it('a key resolved from a 7h3 SPKI works, and thumbprints are stable across the conversion', async () => {
    const kp = await generateEd25519KeypairBase64Url()
    const jwk = spkiToEd25519Jwk(kp.publicKey)
    expect(await jwkThumbprint(jwk)).toBe(await jwkThumbprint({ ...jwk }))
  })
})
