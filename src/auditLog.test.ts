import { describe, it, expect, beforeAll } from 'vitest'
import {
  createAuditLog,
  NoopAuditLog,
  verifyAuditChain,
  AUDIT_GENESIS_HASH,
  type AuditEntry,
} from './auditLog'
import { generateEd25519KeypairBase64Url } from './protocol'

let keys: { publicKey: string; privateKey: string }

beforeAll(async () => {
  keys = await generateEd25519KeypairBase64Url()
})

describe('InMemoryAuditLog', () => {
  it('logs and queries entries', async () => {
    const log = createAuditLog(keys.privateKey)
    await log.log({ type: 'verify-ok', sender: 'agent-a', path: '/api/test', method: 'GET' })
    await log.log({ type: 'verify-fail', sender: 'agent-b', path: '/api/test', method: 'POST', failReason: 'invalid-signature' })

    const all = await log.query()
    expect(all).toHaveLength(2)
    expect(log.size()).toBe(2)
  })

  it('query filters by type', async () => {
    const log = createAuditLog(keys.privateKey)
    await log.log({ type: 'verify-ok', sender: 'alice' })
    await log.log({ type: 'verify-fail', sender: 'bob', failReason: 'expired' })
    await log.log({ type: 'rate-limited', sender: 'alice' })

    const oks = await log.query({ type: 'verify-ok' })
    expect(oks).toHaveLength(1)
    expect(oks[0].type).toBe('verify-ok')
  })

  it('query filters by sender', async () => {
    const log = createAuditLog(keys.privateKey)
    await log.log({ type: 'verify-ok', sender: 'alice' })
    await log.log({ type: 'verify-ok', sender: 'bob' })
    await log.log({ type: 'verify-fail', sender: 'alice', failReason: 'expired' })

    const aliceEntries = await log.query({ sender: 'alice' })
    expect(aliceEntries).toHaveLength(2)
    expect(aliceEntries.every(e => e.sender === 'alice')).toBe(true)
  })

  it('query filters by since', async () => {
    const log = createAuditLog(keys.privateKey)
    const before = Date.now()
    await log.log({ type: 'verify-ok', sender: 'alice' })
    await new Promise(r => setTimeout(r, 5))
    const mid = Date.now()
    await log.log({ type: 'verify-ok', sender: 'bob' })

    const recent = await log.query({ since: mid })
    expect(recent).toHaveLength(1)
    expect(recent[0].sender).toBe('bob')

    const all = await log.query({ since: before - 1 })
    expect(all).toHaveLength(2)
  })

  it('query respects limit', async () => {
    const log = createAuditLog(keys.privateKey)
    for (let i = 0; i < 5; i++) {
      await log.log({ type: 'verify-ok', sender: `agent-${i}` })
    }
    const limited = await log.query({ limit: 2 })
    expect(limited).toHaveLength(2)
  })

  it('verify() returns true for valid entry', async () => {
    const log = createAuditLog(keys.privateKey)
    await log.log({ type: 'verify-ok', sender: 'alice', path: '/api/test' })

    const entries = await log.query()
    expect(entries).toHaveLength(1)
    const valid = await log.verify(entries[0], keys.publicKey)
    expect(valid).toBe(true)
  })

  it('verify() returns false for tampered entry', async () => {
    const log = createAuditLog(keys.privateKey)
    await log.log({ type: 'verify-ok', sender: 'alice', path: '/api/test' })

    const entries = await log.query()
    const tampered: AuditEntry = { ...entries[0], sender: 'eve' }
    const valid = await log.verify(tampered, keys.publicKey)
    expect(valid).toBe(false)
  })

  it('verify() returns false with wrong public key', async () => {
    const log = createAuditLog(keys.privateKey)
    await log.log({ type: 'verify-ok', sender: 'alice' })

    const wrongKeys = await generateEd25519KeypairBase64Url()
    const entries = await log.query()
    const valid = await log.verify(entries[0], wrongKeys.publicKey)
    expect(valid).toBe(false)
  })

  it('respects maxEntries by evicting oldest', async () => {
    const log = createAuditLog(keys.privateKey, { maxEntries: 3 })
    for (let i = 0; i < 5; i++) {
      await log.log({ type: 'verify-ok', sender: `agent-${i}` })
    }
    expect(log.size()).toBe(3)
    const entries = await log.query()
    // Should have the last 3 (agents 2, 3, 4)
    expect(entries[0].sender).toBe('agent-2')
  })

  it('entries have id, timestampMs, and entrySignature', async () => {
    const log = createAuditLog(keys.privateKey)
    await log.log({ type: 'response-signed', upstream: 'http://upstream' })

    const entries = await log.query()
    expect(typeof entries[0].id).toBe('string')
    expect(typeof entries[0].timestampMs).toBe('number')
    expect(typeof entries[0].entrySignature).toBe('string')
    expect(entries[0].entrySignature.length).toBeGreaterThan(0)
  })
})

describe('NoopAuditLog', () => {
  it('log does nothing', async () => {
    const log = new NoopAuditLog()
    await log.log({ type: 'verify-ok', sender: 'alice' })
    expect(log.size()).toBe(0)
  })

  it('query returns empty array', async () => {
    const log = new NoopAuditLog()
    const result = await log.query()
    expect(result).toEqual([])
  })

  it('verify always returns false', async () => {
    const log = new NoopAuditLog()
    const fakeEntry = {
      id: 'x',
      timestampMs: Date.now(),
      type: 'verify-ok' as const,
      prevHash: '0'.repeat(64),
      entrySignature: 'fake',
    }
    expect(await log.verify(fakeEntry, 'key')).toBe(false)
  })
})

describe('audit chain — deletion must be detectable', () => {
  async function seeded() {
    const kp = await generateEd25519KeypairBase64Url()
    const log = createAuditLog(kp.privateKey)
    for (const sender of ['a@x', 'b@x', 'ATTACKER@x', 'c@x']) {
      await log.log({ type: 'verify-ok', sender, path: '/api' })
    }
    return { kp, log, entries: await log.query() }
  }

  it('verifies an intact chain', async () => {
    const { kp, entries } = await seeded()
    expect(await verifyAuditChain(entries, kp.publicKey)).toMatchObject({ ok: true, brokenAt: null })
  })

  it('chains the first entry to the genesis hash', async () => {
    const { entries } = await seeded()
    expect(entries[0].prevHash).toBe(AUDIT_GENESIS_HASH)
    expect(new Set(entries.map((e) => e.prevHash)).size).toBe(entries.length)
  })

  it('detects a deleted entry — the case independent signatures miss', async () => {
    const { kp, entries } = await seeded()
    const pruned = entries.filter((e) => e.sender !== 'ATTACKER@x')
    // Every surviving entry still verifies on its own; only the chain notices.
    const result = await verifyAuditChain(pruned, kp.publicKey)
    expect(result.ok).toBe(false)
    expect(result.brokenAt).toBe(2)
  })

  it('detects a modified entry', async () => {
    const { kp, entries } = await seeded()
    const tampered = entries.map((e, i) => (i === 1 ? { ...e, sender: 'innocent@x' } : e))
    expect(await verifyAuditChain(tampered, kp.publicKey)).toMatchObject({ ok: false, brokenAt: 1 })
  })

  it('detects reordering', async () => {
    const { kp, entries } = await seeded()
    const swapped = [...entries]
    ;[swapped[1], swapped[2]] = [swapped[2], swapped[1]]
    expect((await verifyAuditChain(swapped, kp.publicKey)).ok).toBe(false)
  })

  it('rejects an entry forged under a different key', async () => {
    const { entries } = await seeded()
    const other = await generateEd25519KeypairBase64Url()
    expect((await verifyAuditChain(entries, other.publicKey)).ok).toBe(false)
  })
})
