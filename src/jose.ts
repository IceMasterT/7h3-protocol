/**
 * Minimal JOSE primitives shared by DPoP (`./dpop`) and Agent Card signatures
 * (`./agentIdentity`): base64url, public-JWK validation, RFC 7638 thumbprints and
 * raw JWS signature creation/verification for `ES256` and `EdDSA`.
 *
 * Deliberately small and strict. It supports exactly two algorithms and refuses
 * everything else, including `none` and every symmetric algorithm.
 */

export type JwsAlg = 'ES256' | 'EdDSA'

export interface JosePublicJwk {
  kty: 'EC' | 'OKP'
  crv: 'P-256' | 'Ed25519'
  x: string
  y?: string
}

const encoder = new TextEncoder()

export function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle
  if (!s) throw new Error('WebCrypto (crypto.subtle) is required')
  return s
}

export const toBuffer = (u: Uint8Array): ArrayBuffer => u.slice().buffer as ArrayBuffer

export function bytesToB64u(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Strict base64url decode: only the URL-safe alphabet, no padding, no impossible lengths. */
export function b64uToBytes(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null
  try {
    const std = s.replace(/-/g, '+').replace(/_/g, '/')
    const bin = atob(std + '='.repeat((4 - (std.length % 4)) % 4))
    return Uint8Array.from(bin, (c) => c.charCodeAt(0))
  } catch {
    return null
  }
}

/** Members that mark a JWK as carrying private or symmetric key material. */
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv']

/** True only for a well-formed PUBLIC P-256 or Ed25519 JWK. */
export function isPublicJwk(value: unknown): value is JosePublicJwk {
  if (typeof value !== 'object' || value === null) return false
  const j = value as Record<string, unknown>
  if (PRIVATE_MEMBERS.some((m) => m in j)) return false
  const b64u43 = (v: unknown): boolean => typeof v === 'string' && /^[A-Za-z0-9_-]{43}$/.test(v)
  if (j.kty === 'EC') return j.crv === 'P-256' && b64u43(j.x) && b64u43(j.y)
  if (j.kty === 'OKP') return j.crv === 'Ed25519' && b64u43(j.x) && j.y === undefined
  return false
}

export const algForJwk = (jwk: JosePublicJwk): JwsAlg => (jwk.kty === 'EC' ? 'ES256' : 'EdDSA')

/** RFC 7638 JWK SHA-256 thumbprint (base64url). */
export async function jwkThumbprint(jwk: JosePublicJwk): Promise<string> {
  if (!isPublicJwk(jwk)) throw new Error('jwkThumbprint: not a public P-256 or Ed25519 JWK')
  const canonical =
    jwk.kty === 'EC'
      ? `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
      : `{"crv":"${jwk.crv}","kty":"OKP","x":"${jwk.x}"}`
  return bytesToB64u(new Uint8Array(await subtle().digest('SHA-256', encoder.encode(canonical))))
}

const importAlg = (jwk: { kty?: string }) => (jwk.kty === 'EC' ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'Ed25519' })
const signAlg = (alg: JwsAlg) => (alg === 'ES256' ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'Ed25519' })

/** Sign `signingInput` with a private JWK. ES256 signatures are the raw r||s form JWS requires. */
export async function jwsSign(alg: JwsAlg, privateJwk: JsonWebKey, signingInput: string): Promise<Uint8Array> {
  const key = await subtle().importKey('jwk', privateJwk, importAlg(privateJwk), false, ['sign'])
  return new Uint8Array(await subtle().sign(signAlg(alg), key, toBuffer(encoder.encode(signingInput))))
}

export type JwsVerifyOutcome = 'valid' | 'invalid' | 'bad-key'

/**
 * Verify a raw JWS signature. `bad-key` means the key could not be used at all (for
 * example a point that is not on the curve); `invalid` means the signature did not match.
 */
export async function jwsVerify(jwk: JosePublicJwk, signingInput: Uint8Array, signature: Uint8Array): Promise<JwsVerifyOutcome> {
  try {
    const key = await subtle().importKey('jwk', jwk as JsonWebKey, importAlg(jwk), false, ['verify'])
    if (jwk.kty === 'EC' && signature.length !== 64) return 'invalid'
    return (await subtle().verify(signAlg(algForJwk(jwk)), key, toBuffer(signature), toBuffer(signingInput))) ? 'valid' : 'invalid'
  } catch {
    return 'bad-key'
  }
}
