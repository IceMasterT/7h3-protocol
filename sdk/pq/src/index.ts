import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'

// Re-export from @7h3/protocol
export type { ProtocolEnvelope, ProtocolHeader, ProtocolBody } from '@7h3/protocol'
export { canonicalizeEnvelope, createEnvelope } from '@7h3/protocol'

import type { ProtocolEnvelope, ProtocolHeader, ProtocolBody } from '@7h3/protocol'
import { canonicalizeEnvelope } from '@7h3/protocol'

// ─── Types ──────────────────────────────────────────────────────────────────

export type PqAlgorithm = 'ML-DSA-65' | 'ML-DSA-87'

export interface PqKeyPair {
  algorithm: PqAlgorithm
  publicKey: string  // base64url, no padding
  privateKey: string // base64url, no padding (secretKey bytes from noble)
  createdAt: number
}

/**
 * Extended envelope type that carries a PQ signature.
 * Structurally identical to ProtocolEnvelope but alg is widened.
 */
export interface PqProtocolEnvelope {
  header: ProtocolHeader
  body: ProtocolBody
  signature?: {
    alg: PqAlgorithm
    keyId: string
    value: string
  }
}

// ─── Base64url helpers ───────────────────────────────────────────────────────

function toBase64Url(bytes: Uint8Array): string {
  const g = globalThis as unknown as {
    Buffer?: { from: (b: Uint8Array) => { toString: (enc: string) => string } }
  }
  if (g.Buffer) {
    return g.Buffer.from(bytes)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '')
  }
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

async function deriveKeyId(publicKey: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', publicKey.slice())
  return toBase64Url(new Uint8Array(digest)).slice(0, 16)
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=')

  const g = globalThis as unknown as {
    Buffer?: { from: (s: string, enc: string) => Uint8Array }
  }
  if (g.Buffer) {
    return new Uint8Array(g.Buffer.from(padded, 'base64'))
  }
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// ─── Key generation ──────────────────────────────────────────────────────────

export function generatePqKeyPair(algorithm: PqAlgorithm = 'ML-DSA-65'): PqKeyPair {
  const impl = algorithm === 'ML-DSA-65' ? ml_dsa65 : ml_dsa87
  const seed = crypto.getRandomValues(new Uint8Array(32))
  const { publicKey, secretKey } = impl.keygen(seed)
  return {
    algorithm,
    publicKey: toBase64Url(publicKey),
    privateKey: toBase64Url(secretKey),
    createdAt: Date.now(),
  }
}

// ─── Sign ────────────────────────────────────────────────────────────────────

export async function signEnvelopePq(
  envelope: Omit<ProtocolEnvelope, 'signature'>,
  privateKeyBase64Url: string,
  algorithm: PqAlgorithm = 'ML-DSA-65',
): Promise<PqProtocolEnvelope> {
  const impl = algorithm === 'ML-DSA-65' ? ml_dsa65 : ml_dsa87
  const canonical = canonicalizeEnvelope(envelope)
  const message = new TextEncoder().encode(canonical)
  const secretKey = fromBase64Url(privateKeyBase64Url)
  // @noble/post-quantum >=0.4 signature: sign(msg, secretKey, opts?)
  const sigBytes = impl.sign(message, secretKey)
  // keyId is a hash of the PUBLIC key, never the secret key — the secret key
  // must never appear, even partially, in wire-transmitted envelope metadata.
  const publicKey = impl.getPublicKey(secretKey)
  const keyId = await deriveKeyId(publicKey)

  return {
    header: envelope.header,
    body: envelope.body,
    signature: {
      alg: algorithm,
      keyId,
      value: toBase64Url(sigBytes),
    },
  }
}

// ─── Verify ──────────────────────────────────────────────────────────────────

export async function verifyEnvelopePq(
  envelope: PqProtocolEnvelope,
  publicKeyBase64Url: string,
): Promise<boolean> {
  if (!envelope.signature) return false
  const alg = envelope.signature.alg
  if (alg !== 'ML-DSA-65' && alg !== 'ML-DSA-87') return false

  const impl = alg === 'ML-DSA-65' ? ml_dsa65 : ml_dsa87
  const unsigned = { header: envelope.header, body: envelope.body }
  const canonical = canonicalizeEnvelope(unsigned)
  const message = new TextEncoder().encode(canonical)
  const publicKey = fromBase64Url(publicKeyBase64Url)
  const sigBytes = fromBase64Url(envelope.signature.value)

  try {
    // @noble/post-quantum >=0.4 signature: verify(sig, msg, publicKey, opts?)
    return impl.verify(sigBytes, message, publicKey)
  } catch {
    return false
  }
}

// ─── Algorithm-specific aliases ──────────────────────────────────────────────

export async function signEnvelopeMlDsa65(
  envelope: Omit<ProtocolEnvelope, 'signature'>,
  privateKeyBase64Url: string,
): Promise<PqProtocolEnvelope> {
  return signEnvelopePq(envelope, privateKeyBase64Url, 'ML-DSA-65')
}

export async function signEnvelopeMlDsa87(
  envelope: Omit<ProtocolEnvelope, 'signature'>,
  privateKeyBase64Url: string,
): Promise<PqProtocolEnvelope> {
  return signEnvelopePq(envelope, privateKeyBase64Url, 'ML-DSA-87')
}

export async function verifyEnvelopeMlDsa65(
  envelope: PqProtocolEnvelope,
  publicKeyBase64Url: string,
): Promise<boolean> {
  return verifyEnvelopePq(envelope, publicKeyBase64Url)
}

export async function verifyEnvelopeMlDsa87(
  envelope: PqProtocolEnvelope,
  publicKeyBase64Url: string,
): Promise<boolean> {
  return verifyEnvelopePq(envelope, publicKeyBase64Url)
}
