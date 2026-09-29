import { describe, it, expect, beforeAll } from 'vitest'
import {
  APPROVAL_VERSION,
  MAX_APPROVAL_TTL_MS,
  canonicalizeApproval,
  issueApproval,
  parseApproval,
  serializeApproval,
  verifyApproval,
  type ApprovalGrant,
} from './approval'
import { bindAction, sha256Hex, stableStringify, type BoundAction } from './actionBinding'
import { generateEd25519KeypairBase64Url, signCanonicalPayloadEd25519 } from './protocol'
import { MemoryReplayStore } from './replayStores'

let approver: { publicKey: string; privateKey: string }
let stranger: { publicKey: string; privateKey: string }
let action: BoundAction
const NOW = 1_800_000_000_000

beforeAll(async () => {
  approver = await generateEd25519KeypairBase64Url()
  stranger = await generateEd25519KeypairBase64Url()
  action = await bindAction({ method: 'post', path: '/api/payments', body: '{"amount":5000}' })
})

const keys = () => ({ getPublicKey: async (id: string) => (id === 'alice' ? approver.publicKey : null) })
const base = () => ({ approverKeys: keys(), allowedApprovers: ['alice'], subject: 'agent.worker', action, now: NOW })

async function grant(over: Partial<Parameters<typeof issueApproval>[0]> = {}) {
  return issueApproval({
    approverPrivateKey: approver.privateKey,
    approverId: 'alice',
    subject: 'agent.worker',
    action,
    now: NOW,
    ...over,
  })
}

describe('action binding', () => {
  it('upper-cases the method and hashes an absent body as the empty string', async () => {
    const a = await bindAction({ method: 'get', path: '/x' })
    expect(a.method).toBe('GET')
    expect(a.bodySha256).toBe(await sha256Hex(''))
    expect((await bindAction({ method: 'get', path: '/x', body: '' })).bodySha256).toBe(a.bodySha256)
  })

  it('matches the SHA-256 test vector for "abc"', async () => {
    expect(await sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })

  it('rejects a relative path and an empty method', async () => {
    await expect(bindAction({ method: 'GET', path: 'x' })).rejects.toThrow()
    await expect(bindAction({ method: '', path: '/x' })).rejects.toThrow()
  })

  it('stableStringify sorts keys recursively and refuses ambiguous values', () => {
    expect(stableStringify({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: null } })).toBe('{"a":{"c":null,"d":[3,{"y":2,"z":1}]},"b":1}')
    expect(() => stableStringify({ a: undefined })).toThrow()
    expect(() => stableStringify({ a: NaN })).toThrow()
    expect(() => stableStringify({ a: 1n })).toThrow()
  })
})

describe('issueApproval', () => {
  it('produces a grant bound to subject, action and a short window', async () => {
    const g = await grant()
    expect(g.version).toBe(APPROVAL_VERSION)
    expect(g.subject).toBe('agent.worker')
    expect(g.action).toEqual(action)
    expect(g.expiresAt - g.issuedAt).toBeLessThanOrEqual(MAX_APPROVAL_TTL_MS)
  })

  it('accepts raw request parts as well as a bound action', async () => {
    const g = await grant({ action: { method: 'POST', path: '/api/payments', body: '{"amount":5000}' } })
    expect(g.action).toEqual(action)
  })

  it('refuses a ttl above the maximum, a non-positive ttl, and self-approval', async () => {
    await expect(grant({ ttlMs: MAX_APPROVAL_TTL_MS + 1 })).rejects.toThrow(/maximum/)
    await expect(grant({ ttlMs: 0 })).rejects.toThrow()
    await expect(grant({ approverId: 'agent.worker' })).rejects.toThrow(/itself/)
  })
})

describe('verifyApproval', () => {
  it('accepts a fresh grant for exactly the action it names', async () => {
    const r = await verifyApproval(await grant(), base())
    expect(r.ok).toBe(true)
  })

  it.each([
    ['a different subject', { subject: 'agent.other' }, 'subject-mismatch'],
    ['a different verb', { action: async () => ({ ...action, method: 'DELETE' }) }, 'action-mismatch'],
    ['a different path', { action: async () => ({ ...action, path: '/api/admin' }) }, 'action-mismatch'],
    [
      'a different body (amount changed)',
      { action: async () => bindAction({ method: 'POST', path: '/api/payments', body: '{"amount":50000}' }) },
      'action-mismatch',
    ],
  ] as const)('rejects %s', async (_name, change, reason) => {
    const g = await grant()
    const opts = base() as ReturnType<typeof base> & Record<string, unknown>
    if ('subject' in change) opts.subject = change.subject
    if ('action' in change) opts.action = await change.action()
    const r = await verifyApproval(g, opts)
    expect(r).toEqual({ ok: false, reason })
  })

  it('rejects an expired grant and one from the future', async () => {
    const g = await grant()
    expect(await verifyApproval(g, { ...base(), now: g.expiresAt })).toEqual({ ok: false, reason: 'expired' })
    expect(await verifyApproval(g, { ...base(), now: g.issuedAt - 60_000 })).toEqual({ ok: false, reason: 'not-yet-valid' })
  })

  it('tolerates small clock skew but not large', async () => {
    const g = await grant()
    expect((await verifyApproval(g, { ...base(), now: g.issuedAt - 10_000 })).ok).toBe(true)
    expect((await verifyApproval(g, { ...base(), now: g.issuedAt - 31_000 })).ok).toBe(false)
  })

  it('rejects a hand-signed grant that exceeds the ttl cap', async () => {
    const unsigned = {
      version: APPROVAL_VERSION,
      id: 'appr-long',
      approver: 'alice',
      subject: 'agent.worker',
      action,
      issuedAt: NOW,
      expiresAt: NOW + MAX_APPROVAL_TTL_MS + 1,
      keyId: 'alice-key',
    } as const
    const signature = await signCanonicalPayloadEd25519(canonicalizeApproval(unsigned), approver.privateKey)
    expect(await verifyApproval({ ...unsigned, signature }, base())).toEqual({ ok: false, reason: 'ttl-too-long' })
  })

  it('rejects an approver who is not on the allow-list even with a valid signature', async () => {
    const r = await verifyApproval(await grant(), { ...base(), allowedApprovers: ['bob'] })
    expect(r).toEqual({ ok: false, reason: 'approver-not-allowed' })
  })

  it('rejects self-approval that was forged by hand', async () => {
    const unsigned = {
      version: APPROVAL_VERSION,
      id: 'appr-self',
      approver: 'agent.worker',
      subject: 'agent.worker',
      action,
      issuedAt: NOW,
      expiresAt: NOW + 60_000,
      keyId: 'k',
    } as const
    const signature = await signCanonicalPayloadEd25519(canonicalizeApproval(unsigned), approver.privateKey)
    const r = await verifyApproval(
      { ...unsigned, signature },
      { ...base(), allowedApprovers: ['agent.worker'], approverKeys: { getPublicKey: async () => approver.publicKey } },
    )
    expect(r).toEqual({ ok: false, reason: 'self-approval' })
  })

  it('rejects a grant signed by the wrong key', async () => {
    const forged = await grant({ approverPrivateKey: stranger.privateKey })
    expect(await verifyApproval(forged, base())).toEqual({ ok: false, reason: 'invalid-signature' })
  })

  it('rejects when the approver has no registered key', async () => {
    const r = await verifyApproval(await grant(), { ...base(), approverKeys: { getPublicKey: async () => null } })
    expect(r).toEqual({ ok: false, reason: 'no-approver-key' })
  })

  it('a tampered reason or id invalidates the signature', async () => {
    const g = await grant({ reason: 'invoice #442' })
    expect(await verifyApproval({ ...g, reason: 'invoice #999' }, base())).toEqual({ ok: false, reason: 'invalid-signature' })
    expect(await verifyApproval({ ...g, id: 'appr-other' }, base())).toEqual({ ok: false, reason: 'invalid-signature' })
  })

  it('refuses an empty allow-list rather than accepting every approver', async () => {
    await expect(verifyApproval(await grant(), { ...base(), allowedApprovers: [] })).rejects.toThrow(/allowedApprovers/)
  })

  it('rejects null and unsupported versions', async () => {
    expect(await verifyApproval(null, base())).toEqual({ ok: false, reason: 'malformed' })
    const g = await grant()
    expect(await verifyApproval({ ...g, version: '7h3-approval/9' as never }, base())).toEqual({ ok: false, reason: 'unsupported-version' })
  })
})

describe('single use', () => {
  it('consumes the grant on the first valid use and refuses the second', async () => {
    const store = new MemoryReplayStore({ now: () => NOW })
    const g = await grant()
    expect((await verifyApproval(g, { ...base(), replayStore: store })).ok).toBe(true)
    expect(await verifyApproval(g, { ...base(), replayStore: store })).toEqual({ ok: false, reason: 'already-used' })
  })

  it('does not consume the grant when the presentation is otherwise invalid', async () => {
    const store = new MemoryReplayStore({ now: () => NOW })
    const g = await grant()
    // An interceptor tries the grant against a different body first...
    const tampered = await bindAction({ method: 'POST', path: '/api/payments', body: '{"amount":99999}' })
    expect(await verifyApproval(g, { ...base(), action: tampered, replayStore: store })).toEqual({ ok: false, reason: 'action-mismatch' })
    // ...and the legitimate use still works afterwards.
    expect((await verifyApproval(g, { ...base(), replayStore: store })).ok).toBe(true)
  })
})

describe('parseApproval', () => {
  it('round-trips a grant', async () => {
    const g = await grant({ reason: 'ok' })
    expect(parseApproval(serializeApproval(g))).toEqual(g)
  })

  it.each([
    undefined,
    '',
    'not json',
    '[]',
    'null',
    '{}',
    JSON.stringify({ version: APPROVAL_VERSION }),
    'x'.repeat(9000),
  ])('returns null for junk (%#)', (raw) => {
    expect(parseApproval(raw as string | undefined)).toBeNull()
  })

  it('returns null for a bad action or non-integer times', async () => {
    const g = await grant()
    expect(parseApproval(JSON.stringify({ ...g, action: { ...g.action, bodySha256: 'zz' } }))).toBeNull()
    expect(parseApproval(JSON.stringify({ ...g, issuedAt: 1.5 }))).toBeNull()
    expect(parseApproval(JSON.stringify({ ...g, expiresAt: '99' }))).toBeNull()
  })

  it('drops unknown properties so they cannot influence verification', async () => {
    const g = await grant()
    const parsed = parseApproval(JSON.stringify({ ...g, isAdmin: true }))
    expect(parsed).not.toBeNull()
    expect(parsed as unknown as Record<string, unknown>).not.toHaveProperty('isAdmin')
    expect((await verifyApproval(parsed as ApprovalGrant, base())).ok).toBe(true)
  })
})

describe('MemoryReplayStore', () => {
  it('reports first sight as fresh and later sight as replay until expiry', async () => {
    let t = 1000
    const s = new MemoryReplayStore({ now: () => t })
    expect(await s.check('k', 100)).toBe(false)
    expect(await s.check('k', 100)).toBe(true)
    t += 101
    expect(await s.check('k', 100)).toBe(false)
  })

  it('fails closed at capacity instead of evicting a live key', async () => {
    const s = new MemoryReplayStore({ maxEntries: 2, now: () => 1000 })
    expect(await s.check('a', 1000)).toBe(false)
    expect(await s.check('b', 1000)).toBe(false)
    expect(await s.check('c', 1000)).toBe(true) // full: refused, not admitted
    expect(await s.check('a', 1000)).toBe(true) // 'a' was NOT evicted
  })

  it('frees room once entries expire', async () => {
    let t = 0
    const s = new MemoryReplayStore({ maxEntries: 1, now: () => t })
    expect(await s.check('a', 10)).toBe(false)
    t = 11
    expect(await s.check('b', 10)).toBe(false)
    expect(s.size).toBe(1)
  })

  it('validates its arguments', async () => {
    expect(() => new MemoryReplayStore({ maxEntries: 0 })).toThrow()
    await expect(new MemoryReplayStore().check('k', 0)).rejects.toThrow()
  })
})
