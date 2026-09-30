import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest'
import {
  ATTESTATION_VERSION,
  MAX_ATTESTATION_LIFETIME_MS,
  createAttestedKeyRegistry,
  digestJson,
  issueAttestation,
  parseAttestation,
  toolPinsDigest,
  verifyAttestation,
  type AttestationStatement,
  type VerifyAttestationOptions,
} from './attestation'
import { createGateway } from './gateway'
import { createStaticKeyRegistry } from './keyRegistry'
import { pinTools } from './mcpToolPinning'
import { createEnvelope, generateEd25519KeypairBase64Url, signCanonicalPayloadEd25519, signEnvelopeEd25519 } from './protocol'
import { stableStringify } from './actionBinding'

const NOW = 1_800_000_000_000
const IMAGE_OK = 'a'.repeat(64)
const IMAGE_BAD = 'b'.repeat(64)
const CONFIG_OK = 'c'.repeat(64)

let attester: { publicKey: string; privateKey: string }
let stranger: { publicKey: string; privateKey: string }
let agentKey: { publicKey: string; privateKey: string }
let otherAgentKey: { publicKey: string; privateKey: string }

beforeAll(async () => {
  attester = await generateEd25519KeypairBase64Url()
  stranger = await generateEd25519KeypairBase64Url()
  agentKey = await generateEd25519KeypairBase64Url()
  otherAgentKey = await generateEd25519KeypairBase64Url()
})
afterEach(() => vi.unstubAllGlobals())

const attesterKeys = () => ({ getPublicKey: async (id: string) => (id === 'ci' ? attester.publicKey : null) })
const issue = (over: Partial<Parameters<typeof issueAttestation>[0]> = {}) =>
  issueAttestation({
    attesterPrivateKey: attester.privateKey,
    attester: 'ci',
    subject: { agent: 'agent.worker', publicKey: agentKey.publicKey },
    measurements: { image: IMAGE_OK, config: CONFIG_OK },
    now: NOW,
    ...over,
  })
const opts = (over: Partial<VerifyAttestationOptions> = {}): VerifyAttestationOptions => ({
  attesterKeys: attesterKeys(),
  allowedAttesters: ['ci'],
  agent: 'agent.worker',
  agentPublicKey: agentKey.publicKey,
  requiredMeasurements: { image: [IMAGE_OK] },
  now: NOW + 1000,
  ...over,
})

describe('issueAttestation', () => {
  it('produces a signed statement bound to the agent, its key and its measurements', async () => {
    const s = await issue({ claims: { env: 'prod', tier: 2, audited: true } })
    expect(s.version).toBe(ATTESTATION_VERSION)
    expect(s.subject).toEqual({ agent: 'agent.worker', publicKey: agentKey.publicKey })
    expect(s.claims).toEqual({ env: 'prod', tier: 2, audited: true })
    expect(s.expiresAt - s.issuedAt).toBeLessThanOrEqual(MAX_ATTESTATION_LIFETIME_MS)
  })

  it('accepts SHA-256 and SHA-512 digests and rejects anything else', async () => {
    await expect(issue({ measurements: { image: 'd'.repeat(128) } })).resolves.toBeTruthy()
    for (const bad of ['A'.repeat(64), 'a'.repeat(63), 'g'.repeat(64), 'sha256:' + 'a'.repeat(64), '']) {
      await expect(issue({ measurements: { image: bad } })).rejects.toThrow(/digest/)
    }
  })

  it('validates names, counts and lifetime', async () => {
    await expect(issue({ measurements: {} })).rejects.toThrow(/measurements/)
    await expect(issue({ measurements: { 'bad name': IMAGE_OK } })).rejects.toThrow(/name/)
    await expect(issue({ claims: { 'bad name': 1 } })).rejects.toThrow(/name/)
    await expect(issue({ claims: { n: NaN } })).rejects.toThrow(/finite/)
    await expect(issue({ lifetimeMs: 0 })).rejects.toThrow()
    await expect(issue({ lifetimeMs: MAX_ATTESTATION_LIFETIME_MS + 1 })).rejects.toThrow()
    await expect(issue({ subject: { agent: '', publicKey: 'k' } })).rejects.toThrow()
  })
})

describe('verifyAttestation', () => {
  it('accepts a fresh statement whose measurements are approved', async () => {
    expect((await verifyAttestation(await issue(), opts())).ok).toBe(true)
  })

  it('accepts any of several approved digests, and checks each named measurement', async () => {
    const s = await issue()
    expect((await verifyAttestation(s, opts({ requiredMeasurements: { image: [IMAGE_BAD, IMAGE_OK], config: [CONFIG_OK] } }))).ok).toBe(true)
    expect(await verifyAttestation(s, opts({ requiredMeasurements: { image: [IMAGE_OK], config: [IMAGE_BAD] } }))).toEqual({
      ok: false,
      reason: 'measurement-not-approved',
      detail: 'config',
    })
  })

  it('refuses a build that is not on the approved list, and a missing measurement', async () => {
    const wrongBuild = await issue({ measurements: { image: IMAGE_BAD } })
    expect(await verifyAttestation(wrongBuild, opts())).toEqual({ ok: false, reason: 'measurement-not-approved', detail: 'image' })
    expect(await verifyAttestation(await issue({ measurements: { config: CONFIG_OK } }), opts())).toEqual({ ok: false, reason: 'measurement-missing', detail: 'image' })
  })

  it("cannot be presented for a different agent, or for a key it wasn't issued to", async () => {
    const s = await issue()
    expect(await verifyAttestation(s, opts({ agent: 'agent.other' }))).toEqual({ ok: false, reason: 'subject-mismatch' })
    // The attested build's statement, replayed by someone using a DIFFERENT key for the same agent id.
    expect(await verifyAttestation(s, opts({ agentPublicKey: otherAgentKey.publicKey }))).toEqual({ ok: false, reason: 'key-mismatch' })
  })

  it('only trusts attesters on the allow-list, with a key you registered', async () => {
    const s = await issue()
    expect(await verifyAttestation(s, opts({ allowedAttesters: ['someone-else'] }))).toEqual({ ok: false, reason: 'attester-not-allowed' })
    expect(await verifyAttestation(s, opts({ attesterKeys: { getPublicKey: async () => null } }))).toEqual({ ok: false, reason: 'no-attester-key' })
  })

  it('rejects a statement signed by a key that is not the attester’s', async () => {
    const forged = await issue({ attesterPrivateKey: stranger.privateKey })
    expect(await verifyAttestation(forged, opts())).toEqual({ ok: false, reason: 'invalid-signature' })
  })

  it('any edit to a signed statement invalidates it', async () => {
    const s = await issue({ claims: { env: 'prod' } })
    const check = (edit: Partial<AttestationStatement>) => verifyAttestation({ ...s, ...edit }, opts())
    expect(await check({ claims: { env: 'dev' } })).toEqual({ ok: false, reason: 'invalid-signature' })
    expect(await check({ id: 'att-other' })).toEqual({ ok: false, reason: 'invalid-signature' })
    expect(await check({ expiresAt: s.expiresAt + 1000 })).toEqual({ ok: false, reason: 'invalid-signature' })
    // Swapping in a different measurement is caught by the signature before policy is even consulted.
    expect(await check({ measurements: { image: IMAGE_OK, config: IMAGE_BAD } })).toEqual({ ok: false, reason: 'invalid-signature' })
  })

  it('enforces the validity window, maximum age and lifetime cap', async () => {
    const s = await issue({ lifetimeMs: 60_000 })
    expect(await verifyAttestation(s, opts({ now: NOW + 60_000 }))).toEqual({ ok: false, reason: 'expired' })
    expect(await verifyAttestation(s, opts({ now: NOW - 5 * 60_000 }))).toEqual({ ok: false, reason: 'not-yet-valid' })
    expect(await verifyAttestation(s, opts({ now: NOW + 30_000, maxAgeMs: 10_000 }))).toEqual({ ok: false, reason: 'too-old' })
    // A hand-signed statement that outlives the cap.
    const unsigned = { ...s, expiresAt: s.issuedAt + MAX_ATTESTATION_LIFETIME_MS + 1 }
    const { signature: _s, ...rest } = unsigned
    void _s
    const payload = stableStringify({
      version: rest.version, id: rest.id, subject: rest.subject, measurements: rest.measurements, claims: rest.claims ?? null,
      attester: rest.attester, issuedAt: rest.issuedAt, expiresAt: rest.expiresAt, keyId: rest.keyId,
    })
    const long = { ...unsigned, signature: await signCanonicalPayloadEd25519(payload, attester.privateKey) }
    expect(await verifyAttestation(long, opts())).toEqual({ ok: false, reason: 'lifetime-too-long' })
  })

  it('honours revocation', async () => {
    const s = await issue()
    const revoked = new Set([s.id])
    expect(await verifyAttestation(s, opts({ isRevoked: (id) => revoked.has(id) }))).toEqual({ ok: false, reason: 'revoked' })
  })

  it('checks required claims exactly', async () => {
    const s = await issue({ claims: { env: 'prod', tier: 2 } })
    expect((await verifyAttestation(s, opts({ requiredClaims: { env: 'prod', tier: 2 } }))).ok).toBe(true)
    expect(await verifyAttestation(s, opts({ requiredClaims: { env: 'staging' } }))).toEqual({ ok: false, reason: 'claim-mismatch', detail: 'env' })
    expect(await verifyAttestation(s, opts({ requiredClaims: { tier: '2' } }))).toMatchObject({ reason: 'claim-mismatch' })
    expect(await verifyAttestation(await issue(), opts({ requiredClaims: { env: 'prod' } }))).toMatchObject({ reason: 'claim-mismatch' })
  })

  it('refuses to run with a policy that would pass anything', async () => {
    const s = await issue()
    await expect(verifyAttestation(s, opts({ allowedAttesters: [] }))).rejects.toThrow(/allowedAttesters/)
    await expect(verifyAttestation(s, opts({ requiredMeasurements: {} }))).rejects.toThrow(/requiredMeasurements/)
    await expect(verifyAttestation(s, opts({ requiredMeasurements: { image: [] } }))).rejects.toThrow(/no approved digests/)
  })

  it('null, unsupported and malformed statements fail', async () => {
    expect(await verifyAttestation(null, opts())).toEqual({ ok: false, reason: 'malformed' })
    const s = await issue()
    expect(await verifyAttestation({ ...s, version: 'x' as never }, opts())).toEqual({ ok: false, reason: 'unsupported-version' })
    expect(await verifyAttestation({ ...s, measurements: { image: 'nope' } }, opts())).toEqual({ ok: false, reason: 'malformed' })
  })
})

describe('parseAttestation', () => {
  it('round-trips and drops unknown properties', async () => {
    const s = await issue({ claims: { a: 1 } })
    expect(parseAttestation(JSON.stringify(s))).toEqual(s)
    const parsed = parseAttestation(JSON.stringify({ ...s, isAdmin: true })) as unknown as Record<string, unknown>
    expect(parsed).not.toHaveProperty('isAdmin')
  })

  it.each([undefined, '', 'nope', '[]', '{}', 'x'.repeat(40_000), JSON.stringify({ version: ATTESTATION_VERSION })])('null for junk (%#)', (raw) => {
    expect(parseAttestation(raw as string)).toBeNull()
  })
})

describe('measurement helpers', () => {
  it('digestJson is order-independent and sensitive to content', async () => {
    expect(await digestJson({ a: 1, b: [1, 2] })).toBe(await digestJson({ b: [1, 2], a: 1 }))
    expect(await digestJson({ a: 1 })).not.toBe(await digestJson({ a: 2 }))
    expect(await digestJson({ a: 1 })).toMatch(/^[0-9a-f]{64}$/)
  })

  it('toolPinsDigest ties an attestation to an exact approved tool list', async () => {
    const tools = [{ name: 'a', description: 'x' }, { name: 'b', description: 'y' }]
    const pins = await pinTools('srv', tools, { now: 1 })
    const same = await pinTools('srv', [...tools].reverse(), { now: 999, approvedBy: 'someone' })
    expect(await toolPinsDigest(pins)).toBe(await toolPinsDigest(same)) // approval metadata is not part of the measurement
    const changed = await pinTools('srv', [{ name: 'a', description: 'x!' }, tools[1]], { now: 1 })
    expect(await toolPinsDigest(changed)).not.toBe(await toolPinsDigest(pins))
    expect(await toolPinsDigest(await pinTools('other-srv', tools))).not.toBe(await toolPinsDigest(pins))
  })
})

describe('createAttestedKeyRegistry', () => {
  const base = () => createStaticKeyRegistry({ 'agent.worker': agentKey.publicKey })
  const registry = (over: Record<string, unknown> = {}) => {
    let statement: AttestationStatement | null = null
    const calls = { n: 0 }
    const reg = createAttestedKeyRegistry({
      base: base(),
      attesterKeys: attesterKeys(),
      allowedAttesters: ['ci'],
      requiredMeasurements: { image: [IMAGE_OK] },
      getAttestation: () => {
        calls.n++
        return statement
      },
      now: () => NOW + 1000,
      ...over,
    })
    return { reg, calls, set: (s: AttestationStatement | null) => (statement = s) }
  }

  it('yields the key only for an agent with a valid attestation', async () => {
    const t = registry()
    expect(await t.reg.getPublicKey('agent.worker')).toBeNull() // no statement yet
    t.set(await issue())
    expect(await t.reg.getPublicKey('agent.worker')).toBe(agentKey.publicKey)
  })

  it('an agent on an unapproved build, or attested for another key, has no key', async () => {
    const t = registry()
    t.set(await issue({ measurements: { image: IMAGE_BAD } }))
    expect(await t.reg.getPublicKey('agent.worker')).toBeNull()
    t.set(await issue({ subject: { agent: 'agent.worker', publicKey: otherAgentKey.publicKey } }))
    expect(await t.reg.getPublicKey('agent.worker')).toBeNull()
  })

  it('has no key for senders the base registry does not know, and never asks for their attestation', async () => {
    const t = registry()
    t.set(await issue())
    expect(await t.reg.getPublicKey('agent.unknown')).toBeNull()
    expect(t.calls.n).toBe(0)
  })

  it('fails closed when fetching the statement throws', async () => {
    const reg = createAttestedKeyRegistry({
      base: base(),
      attesterKeys: attesterKeys(),
      allowedAttesters: ['ci'],
      requiredMeasurements: { image: [IMAGE_OK] },
      getAttestation: () => {
        throw new Error('database down')
      },
    })
    expect(await reg.getPublicKey('agent.worker')).toBeNull()
  })

  it('caches a positive result, but never beyond the statement’s own expiry', async () => {
    let t = NOW + 1000
    const state = registry({ now: () => t, cacheMs: 60_000 })
    state.set(await issue({ lifetimeMs: 10_000 }))
    expect(await state.reg.getPublicKey('agent.worker')).toBe(agentKey.publicKey)
    expect(await state.reg.getPublicKey('agent.worker')).toBe(agentKey.publicKey)
    expect(state.calls.n).toBe(1)
    t = NOW + 11_000 // the statement expired although cacheMs has not elapsed
    expect(await state.reg.getPublicKey('agent.worker')).toBeNull()
    expect(state.calls.n).toBe(2)
  })

  it('a cached approval does not carry over to a different key for the same agent (key rotation)', async () => {
    let current = agentKey.publicKey
    const reg = createAttestedKeyRegistry({
      base: { getPublicKey: async () => current },
      attesterKeys: attesterKeys(),
      allowedAttesters: ['ci'],
      requiredMeasurements: { image: [IMAGE_OK] },
      getAttestation: async () => attested, // bound to agentKey only
      cacheMs: 60_000,
      now: () => NOW + 1000,
    })
    const attested = await issue()
    expect(await reg.getPublicKey('agent.worker')).toBe(agentKey.publicKey)
    current = otherAgentKey.publicKey // the registry now maps the agent to a key that was never attested
    expect(await reg.getPublicKey('agent.worker')).toBeNull()
  })

  it('a negative result is not cached: a fixed deployment recovers immediately', async () => {
    const t = registry()
    t.set(await issue({ measurements: { image: IMAGE_BAD } }))
    expect(await t.reg.getPublicKey('agent.worker')).toBeNull()
    t.set(await issue())
    expect(await t.reg.getPublicKey('agent.worker')).toBe(agentKey.publicKey)
  })

  it('makes an unattested agent unable to authenticate at a gateway', async () => {
    const f = vi.fn().mockResolvedValue({ status: 200, text: () => Promise.resolve('ok'), headers: new Headers() })
    vi.stubGlobal('fetch', f)
    const t = registry({ now: undefined })
    const gw = createGateway({
      upstream: 'http://upstream',
      keyRegistry: t.reg,
      defaultPolicy: 'deny',
      replayStore: { check: async () => false },
      policies: [{ path: '/api/**', require: 'ed25519' }],
    })
    const request = async () => {
      const env = createEnvelope({ sender: 'agent.worker', intent: 'TASK', content: 'x', ttlMs: 60_000 })
      const signed = await signEnvelopeEd25519(env, agentKey.privateKey)
      return { method: 'GET', path: '/api/x', headers: { 'x-7h3-envelope': JSON.stringify(signed) } }
    }
    expect((await gw.handle(await request())).status).toBe(401) // valid signature, but no attestation
    // Attested with a fresh clock (the registry uses the real clock here).
    t.set(await issueAttestation({ attesterPrivateKey: attester.privateKey, attester: 'ci', subject: { agent: 'agent.worker', publicKey: agentKey.publicKey }, measurements: { image: IMAGE_OK } }))
    expect((await gw.handle(await request())).status).toBe(200)
  })
})
