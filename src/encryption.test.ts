import { describe, expect, it } from 'vitest'
import { createEnvelope, generateEd25519KeypairBase64Url, type ProtocolBody } from './protocol.js'
import {
  decryptBody,
  encryptBody,
  generateX25519KeyPair,
  openEnvelope,
  sealEnvelope,
} from './encryption.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEnvelope(body: ProtocolBody) {
  return createEnvelope({
    sender: 'agent-alice',
    recipient: 'agent-bob',
    intent: body.intent,
    content: body.content,
    capability: body.capability,
    correlationId: body.correlationId,
    ttlMs: 60_000,
  })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('generateX25519KeyPair', () => {
  it('returns 32-byte base64url keys (~43 chars, no padding)', () => {
    const kp = generateX25519KeyPair()
    // base64url of 32 bytes = ceil(32 * 4/3) = 43 chars (no padding)
    expect(kp.publicKey).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(kp.privateKey).toMatch(/^[A-Za-z0-9_-]{43}$/)
    // Decoded must be exactly 32 bytes
    expect(Buffer.from(kp.publicKey, 'base64url').length).toBe(32)
    expect(Buffer.from(kp.privateKey, 'base64url').length).toBe(32)
  })
})

describe('sealEnvelope + openEnvelope', () => {
  it('round-trip recovers original body exactly', async () => {
    const recipientKp = generateX25519KeyPair()
    const senderEd = await generateEd25519KeypairBase64Url()

    const originalBody: ProtocolBody = {
      intent: 'TASK',
      content: 'Hello encrypted world!',
      capability: 'some-cap',
      correlationId: 'corr-123',
    }
    const envelope = makeEnvelope(originalBody)

    const sealed = await sealEnvelope(envelope, {
      recipientX25519PublicKey: recipientKp.publicKey,
      senderEd25519PrivateKey: senderEd.privateKey,
    })

    const { body } = await openEnvelope(sealed, {
      recipientX25519PrivateKey: recipientKp.privateKey,
      senderEd25519PublicKey: senderEd.publicKey,
    })

    expect(body.intent).toBe(originalBody.intent)
    expect(body.content).toBe(originalBody.content)
    expect(body.capability).toBe(originalBody.capability)
    expect(body.correlationId).toBe(originalBody.correlationId)
  })

  it('fails with wrong recipient private key (AEAD tag mismatch)', async () => {
    const recipientKp = generateX25519KeyPair()
    const wrongKp = generateX25519KeyPair()
    const senderEd = await generateEd25519KeypairBase64Url()

    // Sign with correct recipient public key but try to open with wrong private key
    // To bypass the signature check we need to seal with wrongKp pubkey too,
    // but the spec says "wrong recipient key" meaning sealed to correct pub key but opened with wrong priv.
    const envelope = makeEnvelope({ intent: 'PING', content: 'secret' })
    const sealed = await sealEnvelope(envelope, {
      recipientX25519PublicKey: recipientKp.publicKey,
      senderEd25519PrivateKey: senderEd.privateKey,
    })

    // We must tamper with the encrypted content to force the wrong key path,
    // but the signature would fail. Instead, bypass openEnvelope and call decryptBody directly
    // with the wrong key — which is what the spec tests.
    expect(() => decryptBody(sealed.body.content, wrongKp.privateKey)).toThrow()
  })

  it('fails if envelope signature is tampered', async () => {
    const recipientKp = generateX25519KeyPair()
    const senderEd = await generateEd25519KeypairBase64Url()

    const envelope = makeEnvelope({ intent: 'PING', content: 'secret' })
    const sealed = await sealEnvelope(envelope, {
      recipientX25519PublicKey: recipientKp.publicKey,
      senderEd25519PrivateKey: senderEd.privateKey,
    })

    // Tamper with the signature value
    const tampered = {
      ...sealed,
      signature: {
        ...sealed.signature!,
        value: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
    }

    await expect(
      openEnvelope(tampered, {
        recipientX25519PrivateKey: recipientKp.privateKey,
        senderEd25519PublicKey: senderEd.publicKey,
      }),
    ).rejects.toThrow('signature verification failed')
  })

  it('fails if ciphertext is tampered (AEAD auth tag fails)', async () => {
    const recipientKp = generateX25519KeyPair()
    const senderEd = await generateEd25519KeypairBase64Url()

    const envelope = makeEnvelope({ intent: 'PING', content: 'secret' })
    const sealed = await sealEnvelope(envelope, {
      recipientX25519PublicKey: recipientKp.publicKey,
      senderEd25519PrivateKey: senderEd.privateKey,
    })

    // Decode the encrypted payload, flip a bit in ciphertext, re-encode
    const payloadJson = Buffer.from(sealed.body.content, 'base64url').toString('utf8')
    const payload = JSON.parse(payloadJson) as { ephemeralPublic: string; nonce: string; ciphertext: string; tag: string }
    const ctBuf = Buffer.from(payload.ciphertext, 'base64url')
    ctBuf[0] ^= 0xff  // flip bits in first byte
    const tamperedPayload = { ...payload, ciphertext: ctBuf.toString('base64url') }
    const tamperedContent = Buffer.from(JSON.stringify(tamperedPayload), 'utf8').toString('base64url')

    // We need to re-sign with the same key for the tamper to get past sig verification
    // Instead: call decryptBody directly with tampered content
    expect(() => decryptBody(tamperedContent, recipientKp.privateKey)).toThrow()
  })

  it('two sealEnvelope calls on same body produce different ciphertexts (ephemeral randomness)', async () => {
    const recipientKp = generateX25519KeyPair()
    const senderEd = await generateEd25519KeypairBase64Url()

    const envelope1 = makeEnvelope({ intent: 'PING', content: 'same content' })
    const envelope2 = makeEnvelope({ intent: 'PING', content: 'same content' })

    const sealed1 = await sealEnvelope(envelope1, {
      recipientX25519PublicKey: recipientKp.publicKey,
      senderEd25519PrivateKey: senderEd.privateKey,
    })
    const sealed2 = await sealEnvelope(envelope2, {
      recipientX25519PublicKey: recipientKp.publicKey,
      senderEd25519PrivateKey: senderEd.privateKey,
    })

    // Different ephemeral keys + different nonces → different ciphertexts
    expect(sealed1.body.content).not.toBe(sealed2.body.content)
  })

  it('encrypted content is opaque (does not contain original body.content as plaintext)', async () => {
    const recipientKp = generateX25519KeyPair()
    const senderEd = await generateEd25519KeypairBase64Url()

    const originalContent = 'super-secret-data-12345'
    const envelope = makeEnvelope({ intent: 'TASK', content: originalContent })

    const sealed = await sealEnvelope(envelope, {
      recipientX25519PublicKey: recipientKp.publicKey,
      senderEd25519PrivateKey: senderEd.privateKey,
    })

    // The encrypted content blob should not contain the original plaintext string
    const encryptedContentDecoded = Buffer.from(sealed.body.content, 'base64url').toString('utf8')
    expect(encryptedContentDecoded).not.toContain(originalContent)
    // Also raw base64url should not contain it
    expect(sealed.body.content).not.toContain(originalContent)
  })

  it('encrypted envelope body has correct structure', async () => {
    const recipientKp = generateX25519KeyPair()
    const senderEd = await generateEd25519KeypairBase64Url()

    const envelope = makeEnvelope({ intent: 'PING', content: 'test' })
    const sealed = await sealEnvelope(envelope, {
      recipientX25519PublicKey: recipientKp.publicKey,
      senderEd25519PrivateKey: senderEd.privateKey,
    })

    expect(sealed.body.intent).toBe('ENCRYPTED')
    expect(sealed.body.capability).toBe('x25519-chacha20poly1305')
    expect(sealed.signature).toBeDefined()
    expect(sealed.signature?.alg).toBe('ED25519')
  })
})

describe('encryptBody + decryptBody', () => {
  it('round-trips a body with all optional fields', () => {
    const kp = generateX25519KeyPair()
    const body: ProtocolBody = { intent: 'RESULT', content: 'data', capability: 'cap', correlationId: 'cid-42' }
    const { encryptedContent } = encryptBody(body, kp.publicKey)
    const decrypted = decryptBody(encryptedContent, kp.privateKey)
    expect(decrypted).toEqual(body)
  })
})
