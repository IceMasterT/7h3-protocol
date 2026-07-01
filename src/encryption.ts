/**
 * E2E Encryption for 7h3 Protocol
 *
 * Uses X25519 Diffie-Hellman key exchange + ChaCha20-Poly1305 AEAD.
 * All operations via Node.js built-in `node:crypto` — zero new dependencies.
 *
 * Architecture:
 *   EncryptedEnvelope = SignedEnvelope where body.content is a base64url-encoded
 *   EncryptedPayload, body.intent = 'ENCRYPTED', body.capability = 'x25519-chacha20poly1305'
 */

import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import {
  signEnvelopeEd25519,
  verifyEnvelopeEd25519,
  type ProtocolBody,
  type ProtocolEnvelope,
} from './protocol.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface X25519KeyPair {
  /** Raw 32-byte X25519 public key, base64url-encoded (no padding) */
  publicKey: string
  /** Raw 32-byte X25519 private key, base64url-encoded (no padding) */
  privateKey: string
}

export interface EncryptedPayload {
  /** Ephemeral X25519 public key (base64url, raw 32 bytes) */
  ephemeralPublic: string
  /** ChaCha20 nonce / HKDF salt (base64url, 12 bytes) */
  nonce: string
  /** Ciphertext without auth tag (base64url) */
  ciphertext: string
  /** 16-byte Poly1305 auth tag (base64url) */
  tag: string
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

function toBase64Url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('base64url')
}

function fromBase64Url(s: string): Buffer {
  return Buffer.from(s, 'base64url')
}

/**
 * X25519 PKCS8 DER header: 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20
 * (RFC 5958 / RFC 8410 encoding for X25519, OID 1.3.101.110 = 2b 65 6e)
 */
const X25519_PKCS8_HEADER = Buffer.from('302e020100300506032b656e04220420', 'hex')

/**
 * X25519 SPKI DER header: 30 2a 30 05 06 03 2b 65 6e 03 21 00
 * (RFC 5480 SubjectPublicKeyInfo for X25519)
 */
const X25519_SPKI_HEADER = Buffer.from('302a300506032b656e032100', 'hex')

function importX25519Private(privRaw32Base64Url: string): KeyObject {
  const rawBytes = fromBase64Url(privRaw32Base64Url)
  // Build PKCS8 DER: fixed 16-byte header + 32-byte raw private key
  const der = Buffer.concat([X25519_PKCS8_HEADER, rawBytes])
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
}

function importX25519Public(pubRaw32Base64Url: string): KeyObject {
  const rawBytes = fromBase64Url(pubRaw32Base64Url)
  // Build SPKI DER: fixed 12-byte header + 32-byte raw public key
  const der = Buffer.concat([X25519_SPKI_HEADER, rawBytes])
  return createPublicKey({ key: der, format: 'der', type: 'spki' })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a fresh X25519 keypair.
 * Both keys are raw 32-byte values encoded as base64url (no padding).
 */
export function generateX25519KeyPair(): X25519KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('x25519')
  const privJwk = privateKey.export({ format: 'jwk' }) as { d: string }
  const pubJwk = publicKey.export({ format: 'jwk' }) as { x: string }
  return {
    publicKey: pubJwk.x,
    privateKey: privJwk.d,
  }
}

/**
 * Perform X25519 DH + HKDF-SHA256 to derive a 32-byte ChaCha20-Poly1305 key.
 *
 * @param privateKeyBase64Url  - raw 32-byte X25519 private key (base64url)
 * @param peerPublicKeyBase64Url - raw 32-byte X25519 public key (base64url)
 * @param nonce - raw 12-byte nonce (base64url); used as HKDF salt
 * @returns 32-byte Buffer ready for use with createCipheriv/createDecipheriv
 */
export function deriveEncryptionKey(
  privateKeyBase64Url: string,
  peerPublicKeyBase64Url: string,
  nonce: string,
): Buffer {
  const privKey = importX25519Private(privateKeyBase64Url)
  const pubKey = importX25519Public(peerPublicKeyBase64Url)

  const sharedSecret = diffieHellman({ privateKey: privKey, publicKey: pubKey })
  const salt = fromBase64Url(nonce)
  const info = Buffer.from('7h3-enc/1', 'utf8')

  const derived = hkdfSync('sha256', sharedSecret, salt, info, 32)
  return Buffer.from(derived)
}

/**
 * Encrypt a ProtocolBody with the recipient's X25519 public key.
 *
 * @returns encryptedContent (base64url-encoded EncryptedPayload JSON) and ephemeralPublic
 */
export function encryptBody(
  body: ProtocolBody,
  recipientX25519PublicKey: string,
): { encryptedContent: string; ephemeralPublic: string } {
  // 1. Generate ephemeral X25519 keypair for forward secrecy
  const ephemeral = generateX25519KeyPair()

  // 2. Generate 12-byte ChaCha nonce (also used as HKDF salt)
  const nonce12 = randomBytes(12)
  const nonceBase64Url = toBase64Url(nonce12)

  // 3. Derive encryption key
  const key = deriveEncryptionKey(ephemeral.privateKey, recipientX25519PublicKey, nonceBase64Url)

  // 4. Encrypt body as JSON
  const plaintext = Buffer.from(JSON.stringify(body), 'utf8')
  const cipher = createCipheriv('chacha20-poly1305', key, nonce12, { authTagLength: 16 })
  const ciphertextBuf = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()

  // 5. Build EncryptedPayload
  const payload: EncryptedPayload = {
    ephemeralPublic: ephemeral.publicKey,
    nonce: nonceBase64Url,
    ciphertext: toBase64Url(ciphertextBuf),
    tag: toBase64Url(tag),
  }

  return {
    encryptedContent: toBase64Url(Buffer.from(JSON.stringify(payload), 'utf8')),
    ephemeralPublic: ephemeral.publicKey,
  }
}

/**
 * Decrypt an encrypted ProtocolBody.
 *
 * @param encryptedContent - base64url-encoded EncryptedPayload
 * @param recipientX25519PrivateKey - raw 32-byte X25519 private key (base64url)
 * @returns decrypted ProtocolBody
 * @throws if AEAD tag verification fails
 */
export function decryptBody(encryptedContent: string, recipientX25519PrivateKey: string): ProtocolBody {
  const payloadJson = fromBase64Url(encryptedContent).toString('utf8')
  const payload = JSON.parse(payloadJson) as EncryptedPayload

  const { ephemeralPublic, nonce, ciphertext, tag } = payload

  // Derive the same key using recipient's private key + ephemeral public key
  const key = deriveEncryptionKey(recipientX25519PrivateKey, ephemeralPublic, nonce)

  const nonce12 = fromBase64Url(nonce)
  const ciphertextBuf = fromBase64Url(ciphertext)
  const tagBuf = fromBase64Url(tag)

  const decipher = createDecipheriv('chacha20-poly1305', key, nonce12, { authTagLength: 16 })
  decipher.setAuthTag(tagBuf)

  const plaintext = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()])
  return JSON.parse(plaintext.toString('utf8')) as ProtocolBody
}

/**
 * Encrypt and sign an envelope (full pipeline).
 *
 * The original body is encrypted; the envelope body is replaced with:
 *   { intent: 'ENCRYPTED', content: <encrypted-payload>, capability: 'x25519-chacha20poly1305' }
 * The modified envelope is then signed with Ed25519.
 */
export async function sealEnvelope(
  envelope: Omit<ProtocolEnvelope, 'signature'>,
  opts: {
    recipientX25519PublicKey: string
    senderEd25519PrivateKey: string
  },
): Promise<ProtocolEnvelope> {
  const { encryptedContent } = encryptBody(envelope.body, opts.recipientX25519PublicKey)

  const encryptedEnvelope: Omit<ProtocolEnvelope, 'signature'> = {
    header: envelope.header,
    body: {
      intent: 'ENCRYPTED' as const,
      content: encryptedContent,
      capability: 'x25519-chacha20poly1305',
      correlationId: envelope.body.correlationId,
    },
  }

  // Sign the envelope containing the encrypted body
  return signEnvelopeEd25519(encryptedEnvelope, opts.senderEd25519PrivateKey)
}

/**
 * Verify signature and decrypt an envelope (full pipeline).
 *
 * Signature is verified FIRST; decryption only proceeds if valid.
 *
 * @returns The signed envelope (with encrypted body) and the decrypted original body
 * @throws if Ed25519 signature invalid or AEAD tag fails
 */
export async function openEnvelope(
  envelope: ProtocolEnvelope,
  opts: {
    recipientX25519PrivateKey: string
    senderEd25519PublicKey: string
  },
): Promise<{ envelope: ProtocolEnvelope; body: ProtocolBody }> {
  // 1. Verify Ed25519 signature FIRST — reject before decrypting
  const valid = await verifyEnvelopeEd25519(envelope, opts.senderEd25519PublicKey)
  if (!valid) {
    throw new Error('7h3/encryption: Ed25519 signature verification failed')
  }

  // 2. Decrypt body
  const body = decryptBody(envelope.body.content, opts.recipientX25519PrivateKey)

  return { envelope, body }
}
