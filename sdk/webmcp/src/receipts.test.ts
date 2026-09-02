import { describe, expect, it } from 'vitest'
import { generateEd25519KeypairBase64Url } from '@7h3/protocol'
import { GENESIS_HASH, ReceiptLog, verifyChain } from './receipts'
import type { Receipt } from './types'

async function seeded(count: number) {
  const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
  const log = new ReceiptLog({ privateKey, keyId: 'k1' })
  for (let i = 0; i < count; i++) {
    await log.append({
      tool: `tool_${i}`,
      scope: 'demo/scope',
      method: i % 2 === 0 ? 'READ' : 'WRITE',
      outcome: i === 1 ? 'refused' : 'allowed',
      reason: i === 1 ? 'scope-not-covered' : undefined,
      grantId: i === 1 ? null : `cap-${i}`,
      inputHash: 'a'.repeat(64),
    })
  }
  return { log, publicKey, privateKey }
}

describe('ReceiptLog', () => {
  it('chains the first entry to the genesis hash', async () => {
    const { log } = await seeded(1)
    expect(log.all()[0].prevHash).toBe(GENESIS_HASH)
    expect(log.all()[0].seq).toBe(0)
  })

  it('links each entry to the hash of its predecessor', async () => {
    const { log, publicKey } = await seeded(4)
    const entries = log.all()
    expect(entries).toHaveLength(4)
    expect(new Set(entries.map((e) => e.prevHash)).size).toBe(4)
    expect(await verifyChain(entries, publicKey)).toMatchObject({ ok: true, brokenAt: null })
  })

  it('exposes the current tip as the next entry prevHash', async () => {
    const { log } = await seeded(2)
    const head = log.head
    await log.append({ tool: 't', scope: 's', method: 'READ', outcome: 'allowed', grantId: null, inputHash: 'b'.repeat(64) })
    expect(log.all()[2].prevHash).toBe(head)
  })
})

describe('verifyChain — tamper detection', () => {
  it('detects an edited field in a historical receipt', async () => {
    const { log, publicKey } = await seeded(4)
    const entries = log.all()
    entries[1] = { ...entries[1], outcome: 'allowed', reason: undefined }

    const result = await verifyChain(entries, publicKey)
    expect(result.ok).toBe(false)
    expect(result.brokenAt).toBe(1)
    expect(result.reason).toBe('bad-signature')
  })

  it('detects a deleted receipt', async () => {
    const { log, publicKey } = await seeded(4)
    const entries = log.all()
    entries.splice(1, 1)

    const result = await verifyChain(entries, publicKey)
    expect(result.ok).toBe(false)
    expect(result.brokenAt).toBe(1)
  })

  it('detects reordered receipts', async () => {
    const { log, publicKey } = await seeded(4)
    const entries = log.all()
    const [a, b] = [entries[1], entries[2]]
    entries[1] = b
    entries[2] = a

    const result = await verifyChain(entries, publicKey)
    expect(result.ok).toBe(false)
    expect(result.brokenAt).toBe(1)
  })

  it('detects a forged receipt appended by a different key', async () => {
    const { log, publicKey } = await seeded(2)
    const attacker = await generateEd25519KeypairBase64Url()
    const forgedLog = new ReceiptLog({ privateKey: attacker.privateKey, keyId: 'k1' })
    await forgedLog.append({ tool: 'exfiltrate', scope: 'money/*', method: 'WRITE', outcome: 'allowed', grantId: 'cap-fake', inputHash: 'c'.repeat(64) })

    const entries: Receipt[] = [...log.all(), { ...forgedLog.all()[0], seq: 2, prevHash: log.head }]

    const result = await verifyChain(entries, publicKey)
    expect(result.ok).toBe(false)
    expect(result.brokenAt).toBe(2)
    expect(result.reason).toBe('bad-signature')
  })

  it('rejects a chain whose prevHash was rewritten to hide a deletion', async () => {
    const { log, publicKey } = await seeded(4)
    const entries = log.all()
    entries.splice(2, 1)
    // Attacker renumbers to make the sequence look contiguous again.
    entries[2] = { ...entries[2], seq: 2 }

    const result = await verifyChain(entries, publicKey)
    expect(result.ok).toBe(false)
  })

  it('verifies an empty chain', async () => {
    const { publicKey } = await seeded(0)
    expect(await verifyChain([], publicKey)).toMatchObject({ ok: true, length: 0 })
  })

  it('round-trips through export() without breaking verification', async () => {
    const { log, publicKey } = await seeded(3)
    const restored = JSON.parse(log.export()) as Receipt[]
    expect(await verifyChain(restored, publicKey)).toMatchObject({ ok: true })
  })
})
