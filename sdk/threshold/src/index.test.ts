import { describe, it, expect } from 'vitest'
import {
  generateBlsKeyPair,
  signEnvelopeBls,
  aggregateSignatures,
  verifyThresholdEnvelope,
  splitPrivateKey,
  reconstructPrivateKey,
  type ThresholdConfig,
  type ThresholdEnvelope,
  type ProtocolEnvelope,
} from './index.js'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeEnvelope(): Omit<ProtocolEnvelope, never> {
  return {
    header: {
      version: '7h3/0.1',
      messageId: 'msg-test-001',
      timestampMs: Date.now(),
      ttlMs: 60_000,
      sender: 'agent-alpha',
      recipient: 'agent-beta',
      nonce: 'nonce-abc',
    },
    body: {
      intent: 'TASK',
      content: 'approve-transaction-001',
    },
  }
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=')
  return new Uint8Array(Buffer.from(padded, 'base64'))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('generateBlsKeyPair', () => {
  it('returns a 48-byte G1 public key and 32-byte private key (base64url)', () => {
    const kp = generateBlsKeyPair()
    expect(kp.publicKey).toBeTypeOf('string')
    expect(kp.privateKey).toBeTypeOf('string')

    const pubBytes = fromBase64Url(kp.publicKey)
    const privBytes = fromBase64Url(kp.privateKey)
    expect(pubBytes.length).toBe(48)
    expect(privBytes.length).toBe(32)
  })
})

describe('3-of-5 threshold round trip', () => {
  it('aggregates 3 signatures and verifies successfully', async () => {
    const config: ThresholdConfig = { m: 3, n: 5 }
    const envelope = makeEnvelope()

    // Generate 5 keypairs
    const keypairs: Array<{ id: string; publicKey: string; privateKey: string }> = []
    for (let i = 0; i < 5; i++) {
      const kp = generateBlsKeyPair()
      keypairs.push({ id: `agent-${i}`, ...kp })
    }

    const publicKeys: Record<string, string> = {}
    for (const kp of keypairs) publicKeys[kp.id] = kp.publicKey

    // Sign with first 3 agents
    const partialSigs = await Promise.all(
      keypairs.slice(0, 3).map((kp) =>
        signEnvelopeBls(envelope, kp.privateKey, kp.id),
      ),
    )

    const thresholdEnvelope = await aggregateSignatures(
      partialSigs,
      publicKeys,
      envelope,
      config,
    )

    expect(thresholdEnvelope.thresholdSignature.alg).toBe('BLS-G2-2')
    expect(thresholdEnvelope.thresholdSignature.signerIds).toHaveLength(3)

    const valid = await verifyThresholdEnvelope(thresholdEnvelope, publicKeys, config)
    expect(valid).toBe(true)
  })

  it('throws when only 2 partial sigs are provided for 3-of-5', async () => {
    const config: ThresholdConfig = { m: 3, n: 5 }
    const envelope = makeEnvelope()

    const keypairs = [generateBlsKeyPair(), generateBlsKeyPair()]
    const ids = ['a0', 'a1']
    const publicKeys: Record<string, string> = {}
    ids.forEach((id, i) => { publicKeys[id] = keypairs[i].publicKey })

    const partialSigs = await Promise.all(
      keypairs.map((kp, i) => signEnvelopeBls(envelope, kp.privateKey, ids[i])),
    )

    await expect(
      aggregateSignatures(partialSigs, publicKeys, envelope, config),
    ).rejects.toThrow('Threshold not met')
  })
})

describe('verifyThresholdEnvelope', () => {
  async function build3of5() {
    const config: ThresholdConfig = { m: 3, n: 5 }
    const envelope = makeEnvelope()
    const keypairs = Array.from({ length: 5 }, (_, i) => ({
      id: `p${i}`,
      ...generateBlsKeyPair(),
    }))
    const publicKeys: Record<string, string> = {}
    for (const kp of keypairs) publicKeys[kp.id] = kp.publicKey

    const partialSigs = await Promise.all(
      keypairs.slice(0, 3).map((kp) =>
        signEnvelopeBls(envelope, kp.privateKey, kp.id),
      ),
    )

    const thresholdEnvelope = await aggregateSignatures(
      partialSigs,
      publicKeys,
      envelope,
      config,
    )

    return { thresholdEnvelope, publicKeys, config }
  }

  it('valid 3-of-5 envelope returns true', async () => {
    const { thresholdEnvelope, publicKeys, config } = await build3of5()
    const result = await verifyThresholdEnvelope(thresholdEnvelope, publicKeys, config)
    expect(result).toBe(true)
  })

  it('tampered envelope body returns false', async () => {
    const { thresholdEnvelope, publicKeys, config } = await build3of5()
    const tampered: ThresholdEnvelope = {
      ...thresholdEnvelope,
      body: { ...thresholdEnvelope.body, content: 'tampered-content-99999' },
    }
    const result = await verifyThresholdEnvelope(tampered, publicKeys, config)
    expect(result).toBe(false)
  })

  it('wrong public keys returns false', async () => {
    const { thresholdEnvelope, config } = await build3of5()
    // Replace all public keys with fresh unrelated ones
    const wrongKeys: Record<string, string> = {}
    for (const id of thresholdEnvelope.thresholdSignature.signerIds) {
      wrongKeys[id] = generateBlsKeyPair().publicKey
    }
    const result = await verifyThresholdEnvelope(thresholdEnvelope, wrongKeys, config)
    expect(result).toBe(false)
  })
})

describe('Shamir Secret Sharing', () => {
  it('splitPrivateKey(key, 3, 5) returns 5 shares', () => {
    const kp = generateBlsKeyPair()
    const shares = splitPrivateKey(kp.privateKey, 3, 5)
    expect(shares).toHaveLength(5)
    for (const s of shares) {
      expect(s).toBeTypeOf('string')
      expect(fromBase64Url(s).length).toBe(33) // 1 index byte + 32 value bytes
    }
  })

  it('reconstructPrivateKey with any 3 shares recovers original key', () => {
    const kp = generateBlsKeyPair()
    const shares = splitPrivateKey(kp.privateKey, 3, 5)

    // Try shares [0,1,2]
    const rec1 = reconstructPrivateKey([shares[0], shares[1], shares[2]], 3)
    expect(rec1).toBe(kp.privateKey)

    // Try shares [1,3,4]
    const rec2 = reconstructPrivateKey([shares[1], shares[3], shares[4]], 3)
    expect(rec2).toBe(kp.privateKey)
  })

  it('different 3-share combinations produce the same key', () => {
    const kp = generateBlsKeyPair()
    const shares = splitPrivateKey(kp.privateKey, 3, 5)

    const rec1 = reconstructPrivateKey([shares[0], shares[2], shares[4]], 3)
    const rec2 = reconstructPrivateKey([shares[1], shares[2], shares[3]], 3)
    expect(rec1).toBe(rec2)
  })

  it('only 2 shares cannot reconstruct the correct key', () => {
    const kp = generateBlsKeyPair()
    const shares = splitPrivateKey(kp.privateKey, 3, 5)

    // With only 2 shares we underdetermine the polynomial — result will be wrong
    const wrong = reconstructPrivateKey([shares[0], shares[1]], 2)
    expect(wrong).not.toBe(kp.privateKey)
  })
})

describe('2-of-2 simple multisig round trip', () => {
  it('both agents sign, aggregate, verify — passes', async () => {
    const config: ThresholdConfig = { m: 2, n: 2 }
    const envelope = makeEnvelope()

    const kp1 = { id: 'alice', ...generateBlsKeyPair() }
    const kp2 = { id: 'bob', ...generateBlsKeyPair() }
    const publicKeys: Record<string, string> = {
      alice: kp1.publicKey,
      bob: kp2.publicKey,
    }

    const partialSigs = await Promise.all([
      signEnvelopeBls(envelope, kp1.privateKey, kp1.id),
      signEnvelopeBls(envelope, kp2.privateKey, kp2.id),
    ])

    const thresholdEnvelope = await aggregateSignatures(
      partialSigs,
      publicKeys,
      envelope,
      config,
    )

    expect(thresholdEnvelope.thresholdSignature.threshold).toEqual(config)
    const valid = await verifyThresholdEnvelope(thresholdEnvelope, publicKeys, config)
    expect(valid).toBe(true)
  })
})
