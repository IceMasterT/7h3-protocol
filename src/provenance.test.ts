import { describe, it, expect, beforeAll } from 'vitest'
import {
  MAX_PROVENANCE_SOURCES,
  MAX_PROVENANCE_TTL_MS,
  PROVENANCE_VERSION,
  ProvenanceContext,
  deriveTrust,
  effectiveTrust,
  parseProvenance,
  serializeProvenance,
  signProvenance,
  verifyProvenance,
  type ProvenanceClaim,
  type ProvenanceSource,
} from './provenance'
import { bindAction, type BoundAction } from './actionBinding'
import { generateEd25519KeypairBase64Url } from './protocol'
import { createStaticKeyRegistry } from './keyRegistry'

const NOW = 1_800_000_000_000
let keys: { publicKey: string; privateKey: string }
let other: { publicKey: string; privateKey: string }
let action: BoundAction

beforeAll(async () => {
  keys = await generateEd25519KeypairBase64Url()
  other = await generateEd25519KeypairBase64Url()
  action = await bindAction({ method: 'POST', path: '/api/payments', body: '{"amount":5000}' })
})

const trusted: ProvenanceSource = { kind: 'user', id: 'owner', trust: 'trusted' }
const email: ProvenanceSource = { kind: 'email', id: 'msg-123', trust: 'untrusted' }
const registry = () => createStaticKeyRegistry({ 'agent.worker': keys.publicKey })
const opts = () => ({ keyRegistry: registry(), sender: 'agent.worker', action, now: NOW })
const sign = (sources: ProvenanceSource[], over: Partial<Parameters<typeof signProvenance>[0]> = {}) =>
  signProvenance({ senderPrivateKey: keys.privateKey, sender: 'agent.worker', action, sources, now: NOW, ...over })

describe('deriveTrust', () => {
  it('is trusted only when every source is trusted', () => {
    expect(deriveTrust([trusted])).toBe('trusted')
    expect(deriveTrust([trusted, trusted])).toBe('trusted')
    expect(deriveTrust([trusted, email])).toBe('untrusted')
  })
  it('treats "no sources" as untrusted: unknown is not clean', () => {
    expect(deriveTrust([])).toBe('untrusted')
  })
})

describe('ProvenanceContext', () => {
  it('only ever degrades', () => {
    const ctx = new ProvenanceContext().add(trusted)
    expect(ctx.trust()).toBe('trusted')
    ctx.add(email)
    expect(ctx.trust()).toBe('untrusted')
    ctx.add(trusted)
    expect(ctx.trust()).toBe('untrusted')
  })

  it('returns copies so callers cannot mutate the record', () => {
    const ctx = new ProvenanceContext().add(email)
    ctx.sources()[0].trust = 'trusted'
    expect(ctx.trust()).toBe('untrusted')
  })

  it('cannot be made cleaner by flooding it with trusted sources', () => {
    const ctx = new ProvenanceContext()
    for (let i = 0; i < MAX_PROVENANCE_SOURCES; i++) ctx.add({ kind: 'user', id: `u${i}`, trust: 'trusted' })
    ctx.add(email)
    expect(ctx.trust()).toBe('untrusted')
    expect(ctx.sources().length).toBe(MAX_PROVENANCE_SOURCES)
  })

  it('rejects unknown kinds and trust levels', () => {
    expect(() => new ProvenanceContext().add({ kind: 'carrier-pigeon' as never, trust: 'trusted' })).toThrow()
    expect(() => new ProvenanceContext().add({ kind: 'user', trust: 'mostly' as never })).toThrow()
  })
})

describe('signProvenance / verifyProvenance', () => {
  it('verifies a trusted claim bound to the action', async () => {
    const r = await verifyProvenance(await sign([trusted]), opts())
    expect(r.ok).toBe(true)
    expect(effectiveTrust(r)).toBe('trusted')
  })

  it('verifies an untrusted claim and reports it as untrusted', async () => {
    const r = await verifyProvenance(await sign([trusted, email]), opts())
    expect(r.ok).toBe(true)
    expect(effectiveTrust(r)).toBe('untrusted')
  })

  it('cannot be lifted onto a different action', async () => {
    const claim = await sign([trusted])
    const elsewhere = await bindAction({ method: 'POST', path: '/api/payments', body: '{"amount":50000}' })
    expect(await verifyProvenance(claim, { ...opts(), action: elsewhere })).toEqual({ ok: false, reason: 'action-mismatch' })
  })

  it("cannot be presented by a different sender", async () => {
    expect(await verifyProvenance(await sign([trusted]), { ...opts(), sender: 'agent.other' })).toEqual({ ok: false, reason: 'sender-mismatch' })
  })

  it('a claim cannot label itself cleaner than its own sources', async () => {
    const dirty = await sign([email])
    const lie: ProvenanceClaim = { ...dirty, trust: 'trusted' }
    expect(await verifyProvenance(lie, opts())).toEqual({ ok: false, reason: 'trust-inconsistent' })
  })

  it('stripping the untrusted source invalidates the signature', async () => {
    const dirty = await sign([trusted, email])
    const stripped: ProvenanceClaim = { ...dirty, sources: [trusted], trust: 'trusted' }
    expect(await verifyProvenance(stripped, opts())).toEqual({ ok: false, reason: 'invalid-signature' })
  })

  it('rejects a claim signed by someone else', async () => {
    const forged = await sign([trusted], { senderPrivateKey: other.privateKey })
    expect(await verifyProvenance(forged, opts())).toEqual({ ok: false, reason: 'invalid-signature' })
  })

  it('rejects expired, future and over-long claims', async () => {
    const c = await sign([trusted])
    expect(await verifyProvenance(c, { ...opts(), now: c.expiresAt })).toEqual({ ok: false, reason: 'expired' })
    expect(await verifyProvenance(c, { ...opts(), now: c.issuedAt - 120_000 })).toEqual({ ok: false, reason: 'not-yet-valid' })
    expect(await verifyProvenance({ ...c, expiresAt: c.issuedAt + MAX_PROVENANCE_TTL_MS + 1 }, opts())).toEqual({
      ok: false,
      reason: 'ttl-too-long',
    })
  })

  it('rejects when the sender has no key, and on unsupported versions', async () => {
    const c = await sign([trusted])
    expect(await verifyProvenance(c, { ...opts(), keyRegistry: createStaticKeyRegistry({}) })).toEqual({ ok: false, reason: 'no-sender-key' })
    expect(await verifyProvenance({ ...c, version: 'x' as never }, opts())).toEqual({ ok: false, reason: 'unsupported-version' })
  })

  it('a missing or garbled claim is untrusted, never trusted', async () => {
    const missing = await verifyProvenance(parseProvenance(undefined), opts())
    expect(missing.ok).toBe(false)
    expect(effectiveTrust(missing)).toBe('untrusted')
  })

  it('validates inputs at signing time', async () => {
    await expect(sign([trusted], { ttlMs: MAX_PROVENANCE_TTL_MS + 1 })).rejects.toThrow()
    await expect(sign([{ kind: 'nope' as never, trust: 'trusted' }])).rejects.toThrow()
    await expect(sign(Array.from({ length: MAX_PROVENANCE_SOURCES + 1 }, () => trusted))).rejects.toThrow()
  })
})

describe('parseProvenance', () => {
  it('round-trips', async () => {
    const c = await sign([trusted, email])
    expect(parseProvenance(serializeProvenance(c))).toEqual(c)
    expect(c.version).toBe(PROVENANCE_VERSION)
  })

  it.each([undefined, '', 'nope', '[]', '{}', 'x'.repeat(17_000)])('null for junk (%#)', (raw) => {
    expect(parseProvenance(raw as string | undefined)).toBeNull()
  })

  it('null when a source is malformed or there are too many', async () => {
    const c = await sign([trusted])
    expect(parseProvenance(JSON.stringify({ ...c, sources: [{ kind: 'user', trust: 'maybe' }] }))).toBeNull()
    expect(parseProvenance(JSON.stringify({ ...c, sources: [{ kind: 'weird', trust: 'trusted' }] }))).toBeNull()
    expect(parseProvenance(JSON.stringify({ ...c, sources: Array(MAX_PROVENANCE_SOURCES + 1).fill({ kind: 'user', trust: 'trusted' }) }))).toBeNull()
  })
})
