import { describe, it, expect } from 'vitest'
import {
  generatePqKeyPair,
  signEnvelopePq,
  verifyEnvelopePq,
  signEnvelopeMlDsa65,
  signEnvelopeMlDsa87,
  verifyEnvelopeMlDsa65,
  verifyEnvelopeMlDsa87,
  createEnvelope,
} from './index.js'

// Conformance vector envelope (deterministic for tests)
const baseEnvelope = {
  header: {
    version: '7h3/0.1' as const,
    messageId: 'test-msg-001',
    timestampMs: 1_700_000_000_000,
    ttlMs: 60_000,
    sender: 'agent-alpha',
    recipient: 'agent-beta',
    nonce: 'abc123xyz',
  },
  body: {
    intent: 'TASK' as const,
    content: 'Hello, post-quantum world!',
  },
}

describe('generatePqKeyPair', () => {
  it('1. ML-DSA-65 returns keypair with correct algorithm field', () => {
    const kp = generatePqKeyPair('ML-DSA-65')
    expect(kp.algorithm).toBe('ML-DSA-65')
    expect(typeof kp.publicKey).toBe('string')
    expect(typeof kp.privateKey).toBe('string')
    expect(typeof kp.createdAt).toBe('number')
    expect(kp.publicKey.length).toBeGreaterThan(0)
    expect(kp.privateKey.length).toBeGreaterThan(0)
  })

  it('2. ML-DSA-87 returns keypair', () => {
    const kp = generatePqKeyPair('ML-DSA-87')
    expect(kp.algorithm).toBe('ML-DSA-87')
    expect(typeof kp.publicKey).toBe('string')
    expect(typeof kp.privateKey).toBe('string')
  })

  it('7. ML-DSA-65 public key is correct size (1952 bytes → ~2603 base64url chars)', () => {
    const kp = generatePqKeyPair('ML-DSA-65')
    // base64url: ceil(1952 / 3) * 4 = 2604 chars, minus up to 2 padding = 2603 or 2604
    const decoded = Buffer.from(
      kp.publicKey.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(kp.publicKey.length / 4) * 4, '='),
      'base64'
    )
    expect(decoded.length).toBe(1952)
  })

  it('8. ML-DSA-65 private key is correct size (4032 bytes secretKey)', () => {
    const kp = generatePqKeyPair('ML-DSA-65')
    const decoded = Buffer.from(
      kp.privateKey.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(kp.privateKey.length / 4) * 4, '='),
      'base64'
    )
    expect(decoded.length).toBe(4032)
  })
})

describe('ML-DSA-65 sign/verify', () => {
  it('3. ML-DSA-65 sign + verify round trip', async () => {
    const kp = generatePqKeyPair('ML-DSA-65')
    const signed = await signEnvelopePq(baseEnvelope, kp.privateKey, 'ML-DSA-65')
    expect(signed.signature?.alg).toBe('ML-DSA-65')
    expect(typeof signed.signature?.value).toBe('string')
    expect(signed.signature!.value.length).toBeGreaterThan(0)
    const valid = await verifyEnvelopePq(signed, kp.publicKey)
    expect(valid).toBe(true)
  })

  it('4. ML-DSA-65 verify fails on tampered envelope', async () => {
    const kp = generatePqKeyPair('ML-DSA-65')
    const signed = await signEnvelopePq(baseEnvelope, kp.privateKey, 'ML-DSA-65')
    const tampered = {
      ...signed,
      body: { ...signed.body, content: 'TAMPERED content' },
    }
    const valid = await verifyEnvelopePq(tampered, kp.publicKey)
    expect(valid).toBe(false)
  })
})

describe('ML-DSA-87 sign/verify', () => {
  it('5. ML-DSA-87 sign + verify round trip', async () => {
    const kp = generatePqKeyPair('ML-DSA-87')
    const signed = await signEnvelopePq(baseEnvelope, kp.privateKey, 'ML-DSA-87')
    expect(signed.signature?.alg).toBe('ML-DSA-87')
    const valid = await verifyEnvelopePq(signed, kp.publicKey)
    expect(valid).toBe(true)
  })

  it('6. ML-DSA-87 verify fails with wrong public key', async () => {
    const kp = generatePqKeyPair('ML-DSA-87')
    const wrongKp = generatePqKeyPair('ML-DSA-87')
    const signed = await signEnvelopePq(baseEnvelope, kp.privateKey, 'ML-DSA-87')
    const valid = await verifyEnvelopePq(signed, wrongKp.publicKey)
    expect(valid).toBe(false)
  })
})

describe('algorithm-specific aliases', () => {
  it('signEnvelopeMlDsa65 / verifyEnvelopeMlDsa65 round trip', async () => {
    const kp = generatePqKeyPair('ML-DSA-65')
    const envelope = createEnvelope({
      sender: 'agent-a',
      recipient: 'agent-b',
      intent: 'PING',
      content: 'alias test',
    })
    const signed = await signEnvelopeMlDsa65(envelope, kp.privateKey)
    expect(signed.signature?.alg).toBe('ML-DSA-65')
    const valid = await verifyEnvelopeMlDsa65(signed, kp.publicKey)
    expect(valid).toBe(true)
  })

  it('signEnvelopeMlDsa87 / verifyEnvelopeMlDsa87 round trip', async () => {
    const kp = generatePqKeyPair('ML-DSA-87')
    const envelope = createEnvelope({
      sender: 'agent-a',
      recipient: 'agent-b',
      intent: 'PONG',
      content: 'ml-dsa-87 alias test',
    })
    const signed = await signEnvelopeMlDsa87(envelope, kp.privateKey)
    expect(signed.signature?.alg).toBe('ML-DSA-87')
    const valid = await verifyEnvelopeMlDsa87(signed, kp.publicKey)
    expect(valid).toBe(true)
  })

  it('verifyEnvelopePq returns false when no signature', async () => {
    const unsigned = { ...baseEnvelope }
    const valid = await verifyEnvelopePq(unsigned, 'fakepublickey')
    expect(valid).toBe(false)
  })
})

describe('keyId does not leak private key material', () => {
  it('keyId is not derived from (and does not appear in) the private key', async () => {
    const kp = generatePqKeyPair('ML-DSA-65')
    const signed = await signEnvelopePq(baseEnvelope, kp.privateKey, 'ML-DSA-65')
    const keyId = signed.signature!.keyId
    expect(keyId).not.toBe(kp.privateKey.slice(0, 16))
    expect(kp.privateKey).not.toContain(keyId)
  })

  it('keyId is deterministic and derived from the public key', async () => {
    const kp = generatePqKeyPair('ML-DSA-65')
    const signedA = await signEnvelopePq(baseEnvelope, kp.privateKey, 'ML-DSA-65')
    const signedB = await signEnvelopePq(
      { ...baseEnvelope, header: { ...baseEnvelope.header, messageId: 'test-msg-002' } },
      kp.privateKey,
      'ML-DSA-65',
    )
    // Same keypair -> same keyId across different messages/signatures.
    expect(signedA.signature!.keyId).toBe(signedB.signature!.keyId)

    const otherKp = generatePqKeyPair('ML-DSA-65')
    const signedC = await signEnvelopePq(baseEnvelope, otherKp.privateKey, 'ML-DSA-65')
    expect(signedC.signature!.keyId).not.toBe(signedA.signature!.keyId)
  })
})
