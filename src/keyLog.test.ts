import { describe, it, expect, beforeAll } from 'vitest'
import {
  KEYLOG_GENESIS_HASH,
  KEYLOG_VERSION,
  KeyLog,
  checkpointsConflict,
  createKeyLogRegistry,
  keyChangesFor,
  keyLogEntryHash,
  logExtendsCheckpoint,
  resolveKeyLog,
  signKeyLogEntry,
  verifyCheckpoint,
  verifyKeyLog,
  type KeyLogEntry,
} from './keyLog'
import { generateEd25519KeypairBase64Url } from './protocol'

let op: { publicKey: string; privateKey: string }
let other: { publicKey: string; privateKey: string }
const keys: string[] = []
const T0 = 1_800_000_000_000

beforeAll(async () => {
  op = await generateEd25519KeypairBase64Url()
  other = await generateEd25519KeypairBase64Url()
  for (let i = 0; i < 6; i++) keys.push((await generateEd25519KeypairBase64Url()).publicKey)
})

let clock = T0
const newLog = () => {
  clock = T0
  return new KeyLog({ operator: 'log.example', operatorPrivateKey: op.privateKey, now: () => (clock += 1000) })
}
const verify = (entries: readonly KeyLogEntry[], over: Record<string, unknown> = {}) =>
  verifyKeyLog(entries, { operatorPublicKey: op.publicKey, now: T0 + 3_600_000, ...over })

/** Build a log from hand-signed entries, so verifier rules can be tested with logs the writer would refuse. */
async function forge(specs: Array<Parameters<typeof signKeyLogEntry>[0] & { t?: number }>, signer = op): Promise<KeyLogEntry[]> {
  const out: KeyLogEntry[] = []
  let prev = KEYLOG_GENESIS_HASH
  for (const [i, spec] of specs.entries()) {
    const { t, ...fields } = spec
    const e = await signKeyLogEntry(fields, { operator: 'log.example', operatorPrivateKey: signer.privateKey, index: i, prevHash: prev, timestampMs: t ?? T0 + i * 1000 })
    out.push(e)
    prev = await keyLogEntryHash(e)
  }
  return out
}

describe('KeyLog writer', () => {
  it('records register, rotate and revoke as a verifiable chain', async () => {
    const log = newLog()
    await log.register('agent.a', 'a-1', keys[0])
    await log.register('agent.b', 'b-1', keys[1])
    await log.rotate('agent.a', 'a-2', keys[2])
    await log.revoke('agent.b', 'b-1', 'compromised')
    expect(log.size).toBe(4)
    expect(log.entries[0].prevHash).toBe(KEYLOG_GENESIS_HASH)
    expect(log.entries[1].prevHash).toBe(await keyLogEntryHash(log.entries[0]))
    const v = await verify(log.entries)
    expect(v).toMatchObject({ ok: true, size: 4 })
  })

  it('never records an entry that verification would reject', async () => {
    const log = newLog()
    await log.register('agent.a', 'a-1', keys[0])
    await expect(log.register('agent.a', 'a-2', keys[1])).rejects.toThrow(/already-registered/)
    await expect(log.rotate('agent.zzz', 'z-1', keys[1])).rejects.toThrow(/not-registered/)
    await expect(log.revoke('agent.a', 'nope')).rejects.toThrow(/unknown-key/)
    await expect(log.register('agent.b', 'b-1', keys[0])).rejects.toThrow(/key-reuse/)
    await expect(log.rotate('agent.a', 'a-1', keys[3])).rejects.toThrow(/duplicate-key-id/)
    expect(log.size).toBe(1)
    expect((await verify(log.entries)).ok).toBe(true)
    await log.register('agent.b', 'b-1', keys[1]) // and it still accepts good entries afterwards
    expect(log.size).toBe(2)
  })

  it('keeps timestamps non-decreasing even if the clock steps back', async () => {
    let t = T0 + 10_000
    const log = new KeyLog({ operator: 'log.example', operatorPrivateKey: op.privateKey, now: () => t })
    await log.register('agent.a', 'a-1', keys[0])
    t = T0 // clock went backwards
    await log.register('agent.b', 'b-1', keys[1])
    expect(log.entries[1].timestampMs).toBeGreaterThanOrEqual(log.entries[0].timestampMs)
    expect((await verify(log.entries)).ok).toBe(true)
  })

  it('validates identifiers', async () => {
    const log = newLog()
    await expect(log.register('has space', 'k', keys[0])).rejects.toThrow()
    await expect(log.register('agent.a', '', keys[0])).rejects.toThrow()
  })
})

describe('verifyKeyLog: the chain and signatures', () => {
  const sample = async () => {
    const log = newLog()
    await log.register('agent.a', 'a-1', keys[0])
    await log.register('agent.b', 'b-1', keys[1])
    await log.rotate('agent.a', 'a-2', keys[2])
    return [...log.entries]
  }

  it('detects an altered entry', async () => {
    const e = await sample()
    const tampered = e.map((x, i) => (i === 1 ? { ...x, publicKey: keys[5] } : x))
    expect(await verify(tampered)).toEqual({ ok: false, index: 1, reason: 'invalid-signature' })
  })

  it('detects a deleted entry, a reordered log and a spliced-in entry', async () => {
    const e = await sample()
    expect(await verify([e[0], e[2]])).toMatchObject({ ok: false, reason: 'wrong-index' })
    expect(await verify([e[1], e[0], e[2]])).toMatchObject({ ok: false })
    // A properly chained entry inserted in the middle: it links to e[0], but e[2] still links to the original e[1].
    const extra = await signKeyLogEntry({ type: 'register', subject: 'agent.c', keyId: 'c-1', publicKey: keys[4] }, { operator: 'log.example', operatorPrivateKey: op.privateKey, index: 1, prevHash: await keyLogEntryHash(e[0]), timestampMs: T0 + 5000 })
    expect(await verify([e[0], extra, e[2]])).toMatchObject({ ok: false, index: 2, reason: 'broken-chain' })
    // And one that is not chained to its predecessor is refused where it sits.
    const loose = await signKeyLogEntry({ type: 'register', subject: 'agent.c', keyId: 'c-1', publicKey: keys[4] }, { operator: 'log.example', operatorPrivateKey: op.privateKey, index: 1, prevHash: KEYLOG_GENESIS_HASH, timestampMs: T0 + 5000 })
    expect(await verify([e[0], loose])).toMatchObject({ ok: false, index: 1, reason: 'broken-chain' })
  })

  it('a truncated log is still a valid prefix (deletion of the tail is what checkpoints catch)', async () => {
    const e = await sample()
    expect((await verify(e.slice(0, 2))).ok).toBe(true)
  })

  it('rejects entries signed by anyone but the operator, and entries naming a different operator', async () => {
    const forged = await forge([{ type: 'register', subject: 'agent.a', keyId: 'a-1', publicKey: keys[0] }], other)
    expect(await verify(forged)).toEqual({ ok: false, index: 0, reason: 'invalid-signature' })
    const good = await forge([{ type: 'register', subject: 'agent.a', keyId: 'a-1', publicKey: keys[0] }])
    expect(await verify(good, { operator: 'someone.else' })).toEqual({ ok: false, index: 0, reason: 'wrong-operator' })
  })

  it('rejects entries stamped in the future, and time running backwards', async () => {
    const future = await forge([{ type: 'register', subject: 'agent.a', keyId: 'a-1', publicKey: keys[0], t: T0 + 10 * 3_600_000 }])
    expect(await verify(future)).toEqual({ ok: false, index: 0, reason: 'time-went-backwards' })
    const backwards = await forge([
      { type: 'register', subject: 'agent.a', keyId: 'a-1', publicKey: keys[0], t: T0 + 5000 },
      { type: 'register', subject: 'agent.b', keyId: 'b-1', publicKey: keys[1], t: T0 + 1000 },
    ])
    expect(await verify(backwards)).toEqual({ ok: false, index: 1, reason: 'time-went-backwards' })
  })

  it('rejects malformed entries without throwing', async () => {
    const e = await sample()
    expect(await verify([{ ...e[0], version: 'x' as never }])).toEqual({ ok: false, index: 0, reason: 'malformed' })
    expect(await verify([{ ...e[0], prevHash: 'short' }])).toEqual({ ok: false, index: 0, reason: 'malformed' })
    expect(await verify([null as never])).toEqual({ ok: false, index: 0, reason: 'malformed' })
    await expect(verifyKeyLog(e, { operatorPublicKey: '' })).rejects.toThrow(/operatorPublicKey/)
  })
})

describe('verifyKeyLog: what entries mean', () => {
  const reg = (subject: string, keyId: string, i: number) => ({ type: 'register' as const, subject, keyId, publicKey: keys[i] })
  const rot = (subject: string, keyId: string, i: number) => ({ type: 'rotate' as const, subject, keyId, publicKey: keys[i] })
  const rev = (subject: string, keyId: string) => ({ type: 'revoke' as const, subject, keyId })
  const reason = async (specs: Parameters<typeof forge>[0]) => {
    const r = await verify(await forge(specs))
    return r.ok ? 'ok' : r.reason
  }

  it('a subject cannot have two active keys', async () => {
    expect(await reason([reg('a', 'a-1', 0), reg('a', 'a-2', 1)])).toBe('already-registered')
  })

  it('only a registered subject with an active key can rotate', async () => {
    expect(await reason([rot('a', 'a-1', 0)])).toBe('not-registered')
    expect(await reason([reg('a', 'a-1', 0), rev('a', 'a-1'), rot('a', 'a-2', 1)])).toBe('no-active-key')
  })

  it('only an existing, not-yet-revoked key can be revoked', async () => {
    expect(await reason([rev('a', 'a-1')])).toBe('not-registered')
    expect(await reason([reg('a', 'a-1', 0), rev('a', 'other')])).toBe('unknown-key')
    expect(await reason([reg('a', 'a-1', 0), rev('a', 'a-1'), rev('a', 'a-1')])).toBe('already-revoked')
  })

  it('a revocation carries no public key; register and rotate must', async () => {
    expect(await reason([reg('a', 'a-1', 0), { type: 'revoke', subject: 'a', keyId: 'a-1', publicKey: keys[0] }])).toBe('unexpected-public-key')
    expect(await reason([{ type: 'register', subject: 'a', keyId: 'a-1' }])).toBe('missing-public-key')
  })

  it('key ids are never reused within a subject', async () => {
    expect(await reason([reg('a', 'a-1', 0), rot('a', 'a-1', 1)])).toBe('duplicate-key-id')
  })

  it('a public key identifies one subject, once', async () => {
    expect(await reason([reg('a', 'a-1', 0), reg('b', 'b-1', 0)])).toBe('key-reuse')
    expect(await reason([reg('a', 'a-1', 0), rot('a', 'a-2', 1), rot('a', 'a-3', 0)])).toBe('key-reuse') // a retired key does not come back
  })

  it('a revoked key can never be registered again, by anyone', async () => {
    expect(await reason([reg('a', 'a-1', 0), rev('a', 'a-1'), reg('a', 'a-2', 0)])).toBe('revoked-key-reuse')
    expect(await reason([reg('a', 'a-1', 0), rev('a', 'a-1'), reg('b', 'b-1', 0)])).toBe('revoked-key-reuse')
  })

  it('a subject can register a new key after revoking its old one', async () => {
    expect(await reason([reg('a', 'a-1', 0), rev('a', 'a-1'), reg('a', 'a-2', 1)])).toBe('ok')
  })
})

describe('resolving and monitoring', () => {
  it('reports the active key and the revoked ones', async () => {
    const log = newLog()
    await log.register('agent.a', 'a-1', keys[0])
    await log.rotate('agent.a', 'a-2', keys[1])
    await log.register('agent.b', 'b-1', keys[2])
    await log.revoke('agent.b', 'b-1')
    const r = resolveKeyLog(log.entries)
    expect(r.active.get('agent.a')).toEqual({ keyId: 'a-2', publicKey: keys[1] })
    expect(r.active.has('agent.b')).toBe(false)
    expect([...r.revoked.get('agent.b')!]).toEqual(['b-1'])
  })

  it('lists the changes for one subject since an index: what a monitor watches', async () => {
    const log = newLog()
    await log.register('agent.a', 'a-1', keys[0])
    await log.register('agent.b', 'b-1', keys[1])
    await log.rotate('agent.a', 'a-2', keys[2])
    expect(keyChangesFor(log.entries, 'agent.a').map((e) => e.type)).toEqual(['register', 'rotate'])
    expect(keyChangesFor(log.entries, 'agent.a', 1).map((e) => e.type)).toEqual(['rotate'])
    expect(keyChangesFor(log.entries, 'agent.zzz')).toEqual([])
  })
})

describe('checkpoints: catching a rewritten history', () => {
  it('signs and verifies checkpoints, and rejects forged or altered ones', async () => {
    const log = newLog()
    await log.register('agent.a', 'a-1', keys[0])
    const cp = await log.checkpoint()
    expect(await verifyCheckpoint(cp, { operatorPublicKey: op.publicKey })).toBe(true)
    expect(await verifyCheckpoint(cp, { operatorPublicKey: other.publicKey })).toBe(false)
    expect(await verifyCheckpoint({ ...cp, size: 99 }, { operatorPublicKey: op.publicKey })).toBe(false)
    expect(await verifyCheckpoint({ ...cp, headHash: 'f'.repeat(64) }, { operatorPublicKey: op.publicKey })).toBe(false)
    expect(await verifyCheckpoint({ ...cp, version: 'x' as never }, { operatorPublicKey: op.publicKey })).toBe(false)
    expect(await verifyCheckpoint(cp, { operatorPublicKey: op.publicKey, operator: 'someone.else' })).toBe(false)
    expect(await verifyCheckpoint(null as never, { operatorPublicKey: op.publicKey })).toBe(false)
  })

  it('a log that grew honestly still extends an earlier checkpoint', async () => {
    const log = newLog()
    await log.register('agent.a', 'a-1', keys[0])
    const cp = await log.checkpoint()
    await log.rotate('agent.a', 'a-2', keys[1])
    expect(await logExtendsCheckpoint(cp, log.entries, { operatorPublicKey: op.publicKey, now: T0 + 3_600_000 })).toBe(true)
  })

  it('an operator who rewrites history is caught, even though every entry is validly signed', async () => {
    const honest = newLog()
    await honest.register('agent.a', 'a-1', keys[0])
    await honest.register('agent.b', 'b-1', keys[1])
    const cp = await honest.checkpoint() // a client keeps this

    // The operator quietly swaps agent.b's key in a rewritten log, re-signing everything.
    const rewritten = await forge([
      { type: 'register', subject: 'agent.a', keyId: 'a-1', publicKey: keys[0] },
      { type: 'register', subject: 'agent.b', keyId: 'b-1', publicKey: keys[5] },
      { type: 'register', subject: 'agent.c', keyId: 'c-1', publicKey: keys[4] },
    ])
    expect((await verify(rewritten)).ok).toBe(true) // internally consistent and validly signed...
    expect(await logExtendsCheckpoint(cp, rewritten, { operatorPublicKey: op.publicKey, now: T0 + 3_600_000 })).toBe(false) // ...but not the history the client saw
  })

  it('a log that has been cut shorter than a checkpoint does not extend it', async () => {
    const log = newLog()
    await log.register('agent.a', 'a-1', keys[0])
    await log.register('agent.b', 'b-1', keys[1])
    const cp = await log.checkpoint()
    expect(await logExtendsCheckpoint(cp, log.entries.slice(0, 1), { operatorPublicKey: op.publicKey, now: T0 + 3_600_000 })).toBe(false)
  })

  it('two genuine checkpoints of the same size with different heads prove the operator equivocated', async () => {
    const a = newLog()
    await a.register('agent.x', 'x-1', keys[0])
    const b = new KeyLog({ operator: 'log.example', operatorPrivateKey: op.privateKey, now: () => T0 + 999_000 })
    await b.register('agent.x', 'x-1', keys[1]) // a different key for the same identity
    const [cpA, cpB] = [await a.checkpoint(), await b.checkpoint()]
    expect(cpA.size).toBe(cpB.size)
    expect(await checkpointsConflict(cpA, cpB, { operatorPublicKey: op.publicKey })).toBe(true)
  })

  it('checkpoints are not conflicting when equal, of different size, or not genuine', async () => {
    const log = newLog()
    await log.register('agent.a', 'a-1', keys[0])
    const cp1 = await log.checkpoint()
    await log.register('agent.b', 'b-1', keys[1])
    const cp2 = await log.checkpoint()
    expect(await checkpointsConflict(cp1, cp1, { operatorPublicKey: op.publicKey })).toBe(false)
    expect(await checkpointsConflict(cp1, cp2, { operatorPublicKey: op.publicKey })).toBe(false)
    const forged = { ...cp1, headHash: 'e'.repeat(64) } // same size, different head, but not signed by the operator
    expect(await checkpointsConflict(cp1, forged, { operatorPublicKey: op.publicKey })).toBe(false)
  })
})

describe('createKeyLogRegistry', () => {
  const build = async () => {
    const log = newLog()
    await log.register('agent.a', 'a-1', keys[0])
    await log.register('agent.b', 'b-1', keys[1])
    return log
  }

  it('resolves the active key for each subject and nothing else', async () => {
    const log = await build()
    const reg = createKeyLogRegistry({ entries: () => log.entries, operatorPublicKey: op.publicKey, now: () => T0 + 60_000 })
    expect(await reg.getPublicKey('agent.a')).toBe(keys[0])
    expect(await reg.getPublicKey('agent.b')).toBe(keys[1])
    expect(await reg.getPublicKey('agent.unknown')).toBeNull()
  })

  it('follows rotations and revocations after the refresh interval', async () => {
    const log = await build()
    let t = T0 + 60_000
    const reg = createKeyLogRegistry({ entries: () => log.entries, operatorPublicKey: op.publicKey, refreshMs: 1000, now: () => t })
    expect(await reg.getPublicKey('agent.a')).toBe(keys[0])
    await log.rotate('agent.a', 'a-2', keys[2])
    await log.revoke('agent.b', 'b-1')
    expect(await reg.getPublicKey('agent.a')).toBe(keys[0]) // still inside the refresh window
    t += 2000
    expect(await reg.getPublicKey('agent.a')).toBe(keys[2])
    expect(await reg.getPublicKey('agent.b')).toBeNull()
  })

  it('a log that does not verify yields no keys at all', async () => {
    const log = await build()
    const tampered = log.entries.map((e, i) => (i === 0 ? { ...e, publicKey: keys[5] } : e))
    const reg = createKeyLogRegistry({ entries: () => tampered, operatorPublicKey: op.publicKey, now: () => T0 + 60_000 })
    expect(await reg.getPublicKey('agent.a')).toBeNull()
    expect(await reg.getPublicKey('agent.b')).toBeNull()
    const wrongOperator = createKeyLogRegistry({ entries: () => log.entries, operatorPublicKey: other.publicKey, now: () => T0 + 60_000 })
    expect(await wrongOperator.getPublicKey('agent.a')).toBeNull()
  })

  it('enforces a trusted checkpoint: a rewritten log yields no keys', async () => {
    const log = await build()
    const cp = await log.checkpoint()
    const rewritten = await forge([
      { type: 'register', subject: 'agent.a', keyId: 'a-1', publicKey: keys[5] },
      { type: 'register', subject: 'agent.b', keyId: 'b-1', publicKey: keys[1] },
    ])
    const good = createKeyLogRegistry({ entries: () => log.entries, operatorPublicKey: op.publicKey, trustedCheckpoint: () => cp, now: () => T0 + 60_000 })
    expect(await good.getPublicKey('agent.a')).toBe(keys[0])
    const bad = createKeyLogRegistry({ entries: () => rewritten, operatorPublicKey: op.publicKey, trustedCheckpoint: () => cp, now: () => T0 + 60_000 })
    expect(await bad.getPublicKey('agent.a')).toBeNull()
  })

  it('fails closed when the entries cannot be fetched', async () => {
    const reg = createKeyLogRegistry({
      entries: () => {
        throw new Error('network down')
      },
      operatorPublicKey: op.publicKey,
    })
    expect(await reg.getPublicKey('agent.a')).toBeNull()
  })

  it('exposes the version constant', () => {
    expect(KEYLOG_VERSION).toBe('7h3-keylog/1')
  })
})
