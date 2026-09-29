/**
 * DPoP: Demonstrating Proof of Possession (RFC 9449).
 *
 * A bearer token is valid for whoever holds it, so a stolen token is as good as the
 * real thing. A DPoP-bound token is tied to a key the client holds: every request
 * carries a short-lived proof signed with that key, naming the exact method and URL
 * and (for API calls) hashing the access token. A thief with only the token cannot
 * produce proofs.
 *
 * This module signs and verifies DPoP proofs. It fits 7h3's agent model directly:
 * an agent's OAuth token stops being a transferable secret.
 *
 * Algorithms: `ES256` (P-256) and `EdDSA` (Ed25519). Symmetric algorithms and
 * `none` are refused, as the RFC requires.
 *
 * Verification follows RFC 9449 §4.3 in full and is strict about everything that
 * is easy to get subtly wrong: the proof's own key must not carry private members;
 * `htm`/`htu` must match the request actually received (query and fragment
 * ignored); the proof must be fresh and single-use; when a token is presented,
 * `ath` must be its SHA-256 and the proof key's thumbprint must equal the token's
 * `cnf.jkt`.
 */

import {
  algForJwk,
  b64uToBytes,
  bytesToB64u,
  isPublicJwk,
  jwkThumbprint,
  jwsSign,
  jwsVerify,
  subtle,
  toBuffer,
  type JosePublicJwk,
  type JwsAlg,
} from './jose'
import type { ReplayStore } from './replayStores'

export const DPOP_HEADER = 'dpop'
export const DPOP_NONCE_HEADER = 'dpop-nonce'
export const DPOP_TYP = 'dpop+jwt'
export type DpopAlg = JwsAlg

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

/** A public P-256 or Ed25519 JWK (RFC 7517). */
export type DpopPublicJwk = JosePublicJwk

/** RFC 7638 JWK SHA-256 thumbprint, base64url: the value of `cnf.jkt`. */
export const dpopJwkThumbprint = jwkThumbprint

/** `ath` claim value: base64url SHA-256 of the access token. */
export async function accessTokenHash(accessToken: string): Promise<string> {
  return bytesToB64u(new Uint8Array(await subtle().digest('SHA-256', encoder.encode(accessToken))))
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

export interface DpopKeyPair {
  alg: DpopAlg
  publicJwk: DpopPublicJwk
  /** Private JWK (contains `d`). Keep it out of logs and token requests. */
  privateJwk: JsonWebKey
}

export async function generateDpopKeyPair(alg: DpopAlg = 'ES256'): Promise<DpopKeyPair> {
  const algorithm = alg === 'ES256' ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'Ed25519' }
  const pair = (await subtle().generateKey(algorithm, true, ['sign', 'verify'])) as CryptoKeyPair
  const privateJwk = await subtle().exportKey('jwk', pair.privateKey)
  const pub = await subtle().exportKey('jwk', pair.publicKey)
  const publicJwk: DpopPublicJwk =
    alg === 'ES256' ? { kty: 'EC', crv: 'P-256', x: pub.x!, y: pub.y! } : { kty: 'OKP', crv: 'Ed25519', x: pub.x! }
  return { alg, publicJwk, privateJwk }
}

// ---------------------------------------------------------------------------
// Creating proofs
// ---------------------------------------------------------------------------

/** The `htu` value for a URL: the URI without query and fragment. */
export function dpopHtu(url: string): string {
  const u = new URL(url)
  return `${u.protocol}//${u.host}${u.pathname}`
}

function normalizeHtu(value: string): string | null {
  try {
    const u = new URL(value)
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null
    return `${u.protocol}//${u.host}${u.pathname}`
  } catch {
    return null
  }
}

export interface CreateDpopProofOptions {
  key: DpopKeyPair
  method: string
  /** The request URL. Query and fragment are dropped. */
  url: string
  /** The access token this proof accompanies (adds `ath`). */
  accessToken?: string
  /** A nonce the server supplied in `DPoP-Nonce`. */
  nonce?: string
  /** Unix seconds; defaults to now. */
  iat?: number
  jti?: string
}

export async function createDpopProof(opts: CreateDpopProofOptions): Promise<string> {
  const { key } = opts
  const iat = opts.iat ?? Math.floor(Date.now() / 1000)
  const jti = opts.jti ?? bytesToB64u(crypto.getRandomValues(new Uint8Array(16)))
  const header = { typ: DPOP_TYP, alg: key.alg, jwk: key.publicJwk }
  const payload: Record<string, unknown> = { jti, htm: opts.method.toUpperCase(), htu: dpopHtu(opts.url), iat }
  if (opts.nonce !== undefined) payload.nonce = opts.nonce
  if (opts.accessToken !== undefined) payload.ath = await accessTokenHash(opts.accessToken)

  const signingInput = `${bytesToB64u(encoder.encode(JSON.stringify(header)))}.${bytesToB64u(encoder.encode(JSON.stringify(payload)))}`
  return `${signingInput}.${bytesToB64u(await jwsSign(key.alg, key.privateJwk, signingInput))}`
}

/** `Authorization` header value for a DPoP-bound token. */
export const dpopAuthorization = (accessToken: string): string => `DPoP ${accessToken}`

/** Extract the token from `Authorization: DPoP <token>`; `null` for any other scheme or shape. */
export function parseDpopAuthorization(header: string | undefined): string | null {
  if (typeof header !== 'string') return null
  const m = /^DPoP ([A-Za-z0-9\-._~+/]+=*)$/i.exec(header.trim())
  return m ? m[1] : null
}

// ---------------------------------------------------------------------------
// Verifying proofs
// ---------------------------------------------------------------------------

export type DpopFailure =
  | 'missing-proof'
  | 'multiple-proofs'
  | 'malformed'
  | 'bad-typ'
  | 'unsupported-alg'
  | 'bad-jwk'
  | 'unsupported-critical-header'
  | 'invalid-signature'
  | 'missing-claim'
  | 'htm-mismatch'
  | 'htu-mismatch'
  | 'not-yet-valid'
  | 'expired'
  | 'nonce-required'
  | 'nonce-mismatch'
  | 'ath-required'
  | 'ath-mismatch'
  | 'key-not-bound'
  | 'replayed'

export interface DpopClaims {
  jti: string
  htm: string
  htu: string
  iat: number
  nonce?: string
  ath?: string
}

export type DpopVerifyResult =
  | { ok: true; jkt: string; jwk: DpopPublicJwk; claims: DpopClaims }
  | { ok: false; reason: DpopFailure }

export interface VerifyDpopProofOptions {
  method: string
  /** The URL the request was actually received at (scheme, host, path). Query/fragment are ignored. */
  url: string
  /** The access token presented with the request, if any: enables the `ath` and key-binding checks. */
  accessToken?: string
  /**
   * The key thumbprint the access token is bound to (its `cnf.jkt`). Required
   * whenever `accessToken` is given: a proof that is valid but made with a different
   * key than the token is bound to is exactly what DPoP exists to reject.
   */
  expectedJkt?: string
  /** Server-issued nonce policy. Return `true` if the value is currently acceptable. */
  nonce?: { required: boolean; validate: (nonce: string) => boolean | Promise<boolean> }
  allowedAlgs?: readonly DpopAlg[]
  /** Maximum proof age in ms (default 60 s). */
  maxAgeMs?: number
  clockSkewMs?: number
  /** Single-use enforcement for `jti`. Strongly recommended. */
  replayStore?: ReplayStore
  now?: number
}

const MAX_PROOF_BYTES = 8 * 1024

function parseJsonObject(bytes: Uint8Array): Record<string, unknown> | null {
  try {
    const v = JSON.parse(decoder.decode(bytes)) as unknown
    return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/**
 * Verify a DPoP proof. `proofs` is the list of `DPoP` header values received:
 * exactly one is required (RFC 9449 §4.3 item 1).
 */
export async function verifyDpopProof(proofs: string | readonly string[] | undefined, opts: VerifyDpopProofOptions): Promise<DpopVerifyResult> {
  const list = proofs === undefined ? [] : typeof proofs === 'string' ? [proofs] : [...proofs]
  if (list.length === 0 || list[0] === '') return { ok: false, reason: 'missing-proof' }
  if (list.length > 1) return { ok: false, reason: 'multiple-proofs' }
  const jwt = list[0]
  if (jwt.length > MAX_PROOF_BYTES) return { ok: false, reason: 'malformed' }

  const parts = jwt.split('.')
  if (parts.length !== 3) return { ok: false, reason: 'malformed' }
  const headerBytes = b64uToBytes(parts[0])
  const payloadBytes = b64uToBytes(parts[1])
  const sigBytes = b64uToBytes(parts[2])
  if (!headerBytes || !payloadBytes || !sigBytes) return { ok: false, reason: 'malformed' }
  const header = parseJsonObject(headerBytes)
  const payload = parseJsonObject(payloadBytes)
  if (!header || !payload) return { ok: false, reason: 'malformed' }

  if (header.typ !== DPOP_TYP) return { ok: false, reason: 'bad-typ' }
  if ('crit' in header) return { ok: false, reason: 'unsupported-critical-header' }
  const allowed = opts.allowedAlgs ?? (['ES256', 'EdDSA'] as const)
  if (header.alg !== 'ES256' && header.alg !== 'EdDSA') return { ok: false, reason: 'unsupported-alg' }
  if (!allowed.includes(header.alg)) return { ok: false, reason: 'unsupported-alg' }
  if (!isPublicJwk(header.jwk)) return { ok: false, reason: 'bad-jwk' }
  const jwk = header.jwk
  // The key type must agree with the declared algorithm; otherwise a verifier could be steered.
  if (algForJwk(jwk) !== header.alg) return { ok: false, reason: 'bad-jwk' }

  // Signature over `header.payload` with the key the proof itself carries.
  const outcome = await jwsVerify(jwk, encoder.encode(`${parts[0]}.${parts[1]}`), sigBytes)
  if (outcome === 'bad-key') return { ok: false, reason: 'bad-jwk' } // e.g. a point not on the curve
  if (outcome !== 'valid') return { ok: false, reason: 'invalid-signature' }

  const str = (v: unknown): v is string => typeof v === 'string' && v.length > 0
  if (!str(payload.jti) || payload.jti.length > 256 || !str(payload.htm) || !str(payload.htu) || typeof payload.iat !== 'number' || !Number.isSafeInteger(payload.iat)) {
    return { ok: false, reason: 'missing-claim' }
  }
  if ((payload.nonce !== undefined && !str(payload.nonce)) || (payload.ath !== undefined && !str(payload.ath))) return { ok: false, reason: 'missing-claim' }
  const claims: DpopClaims = {
    jti: payload.jti,
    htm: payload.htm,
    htu: payload.htu,
    iat: payload.iat,
    ...(payload.nonce !== undefined ? { nonce: payload.nonce as string } : {}),
    ...(payload.ath !== undefined ? { ath: payload.ath as string } : {}),
  }

  if (claims.htm !== opts.method.toUpperCase()) return { ok: false, reason: 'htm-mismatch' }
  const wantHtu = normalizeHtu(opts.url)
  const gotHtu = normalizeHtu(claims.htu)
  if (wantHtu === null || gotHtu === null || wantHtu !== gotHtu) return { ok: false, reason: 'htu-mismatch' }

  const now = opts.now ?? Date.now()
  const skewS = Math.ceil((opts.clockSkewMs ?? 30_000) / 1000)
  const maxAgeS = Math.ceil((opts.maxAgeMs ?? 60_000) / 1000)
  const nowS = Math.floor(now / 1000)
  if (claims.iat > nowS + skewS) return { ok: false, reason: 'not-yet-valid' }
  if (nowS - claims.iat > maxAgeS + skewS) return { ok: false, reason: 'expired' }

  if (opts.nonce) {
    if (claims.nonce === undefined) {
      if (opts.nonce.required) return { ok: false, reason: 'nonce-required' }
    } else if (!(await opts.nonce.validate(claims.nonce))) {
      return { ok: false, reason: 'nonce-mismatch' }
    }
  }

  const jkt = await dpopJwkThumbprint(jwk)
  if (opts.accessToken !== undefined) {
    if (opts.expectedJkt === undefined) throw new Error('verifyDpopProof: expectedJkt (the token\'s cnf.jkt) is required when accessToken is given')
    if (claims.ath === undefined) return { ok: false, reason: 'ath-required' }
    if (claims.ath !== (await accessTokenHash(opts.accessToken))) return { ok: false, reason: 'ath-mismatch' }
    if (jkt !== opts.expectedJkt) return { ok: false, reason: 'key-not-bound' }
  }

  // Consume last, and only for an otherwise fully valid proof.
  if (opts.replayStore) {
    const ttl = (maxAgeS + 2 * skewS) * 1000
    if (await opts.replayStore.check(`7h3:dpop:${jkt}:${claims.jti}`, ttl)) return { ok: false, reason: 'replayed' }
  }
  return { ok: true, jkt, jwk, claims }
}

// ---------------------------------------------------------------------------
// Server-provided nonces (RFC 9449 §8)
// ---------------------------------------------------------------------------

/**
 * Stateless rotating nonces: `<issuedAtSeconds>.<HMAC-SHA256(secret, issuedAtSeconds)>`.
 * A server that hands these out can require the client to include one, which
 * bounds how long a pre-generated proof is usable and defeats proofs minted ahead of time.
 */
export class DpopNonceIssuer {
  private key: Promise<CryptoKey>

  constructor(
    secret: string | Uint8Array,
    private readonly options: { lifetimeMs?: number; now?: () => number } = {},
  ) {
    const raw = typeof secret === 'string' ? encoder.encode(secret) : secret
    if (raw.length < 16) throw new Error('DpopNonceIssuer: secret must be at least 16 bytes')
    this.key = subtle().importKey('raw', toBuffer(raw), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  }

  private async mac(issued: string): Promise<string> {
    return bytesToB64u(new Uint8Array(await subtle().sign('HMAC', await this.key, encoder.encode(issued))))
  }

  /** A nonce valid for `lifetimeMs` (default 5 minutes). Send it in the `DPoP-Nonce` response header. */
  async issue(): Promise<string> {
    const issued = String(Math.floor((this.options.now?.() ?? Date.now()) / 1000))
    return `${issued}.${await this.mac(issued)}`
  }

  async validate(nonce: string): Promise<boolean> {
    const m = /^(\d{1,12})\.([A-Za-z0-9_-]{43})$/.exec(nonce)
    if (!m) return false
    const expected = await this.mac(m[1])
    let diff = expected.length === m[2].length ? 0 : 1
    for (let i = 0; i < Math.min(expected.length, m[2].length); i++) diff |= expected.charCodeAt(i) ^ m[2].charCodeAt(i)
    if (diff !== 0) return false
    const ageMs = (this.options.now?.() ?? Date.now()) - Number(m[1]) * 1000
    return ageMs >= -30_000 && ageMs <= (this.options.lifetimeMs ?? 5 * 60_000)
  }
}

/** Access-token confirmation claim for a DPoP-bound token (RFC 9449 §6.1). */
export const dpopConfirmation = (jkt: string): { cnf: { jkt: string } } => ({ cnf: { jkt } })
