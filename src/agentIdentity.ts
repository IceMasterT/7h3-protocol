/**
 * Agent identity: who is this agent, and is this key really theirs?
 *
 * 7h3 messages prove that a holder of a private key signed them. This module covers
 * the other half: binding a key to an identity in ways other ecosystems already use.
 *
 *   - **Signed Agent Cards** — A2A-compatible JWS signatures over an RFC 8785 (JCS)
 *     canonical Agent Card, so a client can check that a card really comes from the
 *     agent's operator, and that a valid card was not lifted onto someone else's host.
 *   - **`did:key`** — self-certifying identifiers for Ed25519 keys: no registry, no
 *     lookup, no network. The identity IS the key.
 *   - **SPIFFE IDs** — parsing and policy for workload identities.
 *
 * Trust caveat that applies to all of it: a signature proves possession of a key. It
 * proves who the operator is only relative to the keys you have decided to trust
 * (`resolveKey`, an allow-list of trust domains, a pinned issuer). Nothing here
 * decides that for you.
 */

import { stableStringify } from './actionBinding'
import {
  algForJwk,
  b64uToBytes,
  bytesToB64u,
  isPublicJwk,
  jwsSign,
  jwsVerify,
  type JosePublicJwk,
  type JwsAlg,
} from './jose'
import type { KeyRegistry } from './keyRegistry'

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

// ---------------------------------------------------------------------------
// JSON Canonicalization Scheme (RFC 8785)
// ---------------------------------------------------------------------------

/**
 * RFC 8785 canonical JSON: object members sorted by UTF-16 code unit, no
 * whitespace, ECMAScript number and string serialization. Throws on values JSON
 * cannot represent (non-finite numbers, `undefined`, functions, bigint).
 */
export const canonicalizeJcs = stableStringify

// ---------------------------------------------------------------------------
// base58btc and did:key
// ---------------------------------------------------------------------------

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const B58_INDEX = new Map([...B58].map((c, i) => [c, i]))

export function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  let out = ''
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out
    n /= 58n
  }
  return '1'.repeat(zeros) + out
}

/** Strict base58btc decode: `null` on any character outside the alphabet. */
export function base58btcDecode(text: string): Uint8Array | null {
  let zeros = 0
  while (zeros < text.length && text[zeros] === '1') zeros++
  let n = 0n
  for (const c of text) {
    const v = B58_INDEX.get(c)
    if (v === undefined) return null
    n = n * 58n + BigInt(v)
  }
  const bytes: number[] = []
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn))
    n >>= 8n
  }
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes])
}

/** ASN.1 prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410); the key is the last 32 bytes. */
const SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
/** multicodec varint for `ed25519-pub` (0xed) and `x25519-pub` (0xec). */
const MULTICODEC_ED25519 = [0xed, 0x01]
const MULTICODEC_X25519 = [0xec, 0x01]

function rawFromSpki(spkiBase64Url: string): Uint8Array {
  const der = b64uToBytes(spkiBase64Url)
  if (!der || der.length !== SPKI_PREFIX.length + 32 || !SPKI_PREFIX.every((b, i) => der[i] === b)) {
    throw new Error('not an Ed25519 SubjectPublicKeyInfo')
  }
  return der.slice(SPKI_PREFIX.length)
}

function spkiFromRaw(raw: Uint8Array): string {
  const der = new Uint8Array(SPKI_PREFIX.length + 32)
  der.set(SPKI_PREFIX)
  der.set(raw, SPKI_PREFIX.length)
  return bytesToB64u(der)
}

const multibase = (codec: number[], raw: Uint8Array): string => 'z' + base58btcEncode(Uint8Array.from([...codec, ...raw]))

function fromMultibase(value: string, codec: number[]): Uint8Array | null {
  if (!value.startsWith('z')) return null
  const bytes = base58btcDecode(value.slice(1))
  if (!bytes || bytes.length !== codec.length + 32) return null
  if (!codec.every((b, i) => bytes[i] === b)) return null
  return bytes.slice(codec.length)
}

/** `did:key` for an Ed25519 public key given as SPKI base64url. */
export function didKeyFromEd25519(spkiBase64Url: string): string {
  return `did:key:${multibase(MULTICODEC_ED25519, rawFromSpki(spkiBase64Url))}`
}

/**
 * The Ed25519 public key (SPKI base64url) a `did:key` identifies, or `null` when
 * the string is not a well-formed Ed25519 `did:key`. A `#fragment` (a key
 * reference) is accepted and ignored. Anything else — a different method, another
 * key type, extra path or query — is refused rather than guessed at.
 */
export function ed25519FromDidKey(did: string): string | null {
  const m = /^did:key:(z[1-9A-HJ-NP-Za-km-z]+)(?:#(z[1-9A-HJ-NP-Za-km-z]+))?$/.exec(did)
  if (!m) return null
  if (m[2] !== undefined && m[2] !== m[1]) return null // for did:key the fragment is the same multibase value
  const raw = fromMultibase(m[1], MULTICODEC_ED25519)
  return raw ? spkiFromRaw(raw) : null
}

// Curve25519 field arithmetic for the Ed25519 -> X25519 birational map.
const P = (1n << 255n) - 19n
const mod = (a: bigint): bigint => ((a % P) + P) % P
function powMod(base: bigint, exp: bigint): bigint {
  let result = 1n
  let b = mod(base)
  let e = exp
  while (e > 0n) {
    if (e & 1n) result = mod(result * b)
    b = mod(b * b)
    e >>= 1n
  }
  return result
}

/**
 * The X25519 (Montgomery) public key equivalent to an Ed25519 public key, so one
 * identity can do both signing and key agreement: `u = (1 + y) / (1 - y) mod p`.
 * Returned as 32 raw bytes, base64url. Throws for the one point where the map is
 * undefined (`y = 1`, the identity element).
 */
export function ed25519PublicToX25519(spkiBase64Url: string): string {
  const raw = rawFromSpki(spkiBase64Url)
  const yBytes = raw.slice()
  yBytes[31] &= 0x7f // drop the sign bit of x
  let y = 0n
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(yBytes[i])
  const denominator = mod(1n - y)
  if (denominator === 0n) throw new Error('ed25519PublicToX25519: point has no Montgomery form')
  const u = mod((1n + y) * powMod(denominator, P - 2n))
  const out = new Uint8Array(32)
  let v = u
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return bytesToB64u(out)
}

export interface DidKeyDocument {
  '@context': string[]
  id: string
  verificationMethod: Array<{ id: string; type: 'Multikey'; controller: string; publicKeyMultibase: string }>
  authentication: string[]
  assertionMethod: string[]
  capabilityInvocation: string[]
  capabilityDelegation: string[]
  keyAgreement: Array<{ id: string; type: 'Multikey'; controller: string; publicKeyMultibase: string }>
}

/** The DID document a `did:key` expands to. Purely derived: there is nothing to look up. */
export function didKeyDocument(did: string): DidKeyDocument | null {
  const spki = ed25519FromDidKey(did)
  if (!spki) return null
  const base = did.split('#')[0]
  const fragment = base.slice('did:key:'.length)
  const vm = `${base}#${fragment}`
  const x25519 = multibase(MULTICODEC_X25519, b64uToBytes(ed25519PublicToX25519(spki))!)
  return {
    '@context': ['https://www.w3.org/ns/did/v1.1'],
    id: base,
    verificationMethod: [{ id: vm, type: 'Multikey', controller: base, publicKeyMultibase: fragment }],
    authentication: [vm],
    assertionMethod: [vm],
    capabilityInvocation: [vm],
    capabilityDelegation: [vm],
    keyAgreement: [{ id: `${base}#${x25519}`, type: 'Multikey', controller: base, publicKeyMultibase: x25519 }],
  }
}

/**
 * A {@link KeyRegistry} for senders identified by `did:key`. The identity is the key,
 * so no lookup is needed. This authenticates that a message came from the holder of
 * that key. It says nothing about who that holder is: anyone can mint a `did:key`.
 * Combine with an allow-list (`allowedSenders`, an approver list, an attestation)
 * before granting anything.
 */
export function createDidKeyRegistry(): KeyRegistry {
  return { getPublicKey: async (senderId) => ed25519FromDidKey(senderId) }
}

// ---------------------------------------------------------------------------
// SPIFFE IDs
// ---------------------------------------------------------------------------

export interface SpiffeId {
  trustDomain: string
  /** Empty string for the trust domain's own ID; otherwise begins with `/`. */
  path: string
}

/**
 * Parse a SPIFFE ID (`spiffe://trust-domain/path`) per the SPIFFE ID specification:
 * lower-case trust domain of `[a-z0-9.-_]`, path segments of `[A-Za-z0-9.-_]` with no
 * empty, `.` or `..` segments, and no userinfo, port, query or fragment. Returns
 * `null` for anything else, including over-long IDs.
 */
export function parseSpiffeId(id: string): SpiffeId | null {
  if (typeof id !== 'string' || id.length > 2048) return null
  const m = /^spiffe:\/\/([a-z0-9._-]+)((?:\/[A-Za-z0-9._-]+)*)$/.exec(id)
  if (!m) return null
  const path = m[2]
  for (const seg of path.split('/').slice(1)) {
    if (seg === '.' || seg === '..') return null
  }
  return { trustDomain: m[1], path }
}

export interface SpiffePolicy {
  /** Trust domains whose IDs are acceptable. Required and non-empty. */
  trustDomains: readonly string[]
  /** If set, the path must equal one of these or sit beneath it (`/ns/prod` allows `/ns/prod/agent-1`). */
  pathPrefixes?: readonly string[]
}

export function isSpiffeIdAllowed(id: string, policy: SpiffePolicy): boolean {
  if (policy.trustDomains.length === 0) throw new Error('isSpiffeIdAllowed: trustDomains must not be empty')
  const parsed = parseSpiffeId(id)
  if (!parsed || !policy.trustDomains.includes(parsed.trustDomain)) return false
  if (!policy.pathPrefixes) return true
  return policy.pathPrefixes.some((p) => parsed.path === p || parsed.path.startsWith(p.endsWith('/') ? p : `${p}/`))
}

// ---------------------------------------------------------------------------
// Agent Card signatures (A2A §8.4: JWS over the RFC 8785 canonical card)
// ---------------------------------------------------------------------------

export interface AgentCardSignature {
  /** base64url of the JWS protected header JSON. */
  protected: string
  /** base64url of the signature. */
  signature: string
  header?: Record<string, unknown>
}

export type SignedAgentCard<T extends Record<string, unknown> = Record<string, unknown>> = T & { signatures: AgentCardSignature[] }

/** What gets signed: the card without its `signatures`, canonicalized. */
function cardPayload(card: Record<string, unknown>): string {
  const { signatures: _omit, ...rest } = card
  void _omit
  return canonicalizeJcs(rest)
}

const signingInput = (protectedB64: string, payload: string): string => `${protectedB64}.${bytesToB64u(encoder.encode(payload))}`

export interface SignAgentCardOptions {
  alg?: JwsAlg
  /** Private JWK (contains `d`). */
  privateJwk: JsonWebKey
  /** Key id placed in the protected header; the verifier's `resolveKey` receives it. */
  keyId: string
  /** URL of a JWKS holding the public key. A hint only: verifiers must not fetch it blindly. */
  jku?: string
}

/**
 * Sign an Agent Card. The caller supplies the card exactly as it should be
 * published; A2A's field-presence rules (omit unset optional fields and defaults
 * before canonicalizing) are the caller's to apply, because they depend on the card
 * schema version. Existing signatures are kept, so a card can carry one per key
 * during rotation.
 */
export async function signAgentCard<T extends Record<string, unknown>>(card: T, opts: SignAgentCardOptions): Promise<SignedAgentCard<T>> {
  const alg: JwsAlg = opts.alg ?? (opts.privateJwk.kty === 'EC' ? 'ES256' : 'EdDSA')
  const header: Record<string, unknown> = { alg, typ: 'JOSE', kid: opts.keyId, ...(opts.jku ? { jku: opts.jku } : {}) }
  const protectedB64 = bytesToB64u(encoder.encode(JSON.stringify(header)))
  const sig = await jwsSign(alg, opts.privateJwk, signingInput(protectedB64, cardPayload(card)))
  const existing = Array.isArray(card.signatures) ? (card.signatures as AgentCardSignature[]) : []
  return { ...card, signatures: [...existing, { protected: protectedB64, signature: bytesToB64u(sig) }] }
}

export type AgentCardFailure =
  | 'no-signature'
  | 'too-many-signatures'
  | 'no-valid-signature'
  | 'origin-mismatch'
  | 'not-a-card'

export type AgentCardVerifyResult =
  | { ok: true; keyIds: string[] }
  | { ok: false; reason: AgentCardFailure; detail?: string }

export interface VerifyAgentCardOptions {
  /**
   * Resolve a `kid` (and the optional `jku` hint) to a trusted PUBLIC JWK. Return
   * `null` if the key is unknown, expired or revoked: such signatures are skipped.
   * The verifier never fetches `jku` itself; fetching an attacker-supplied URL is an
   * SSRF vector, so any fetching happens in here, behind your allow-list.
   */
  resolveKey: (keyId: string, jku: string | undefined) => Promise<JosePublicJwk | null> | JosePublicJwk | null
  /**
   * The origin the card was fetched from (e.g. `https://agent.example.com`). When set,
   * the card must declare an endpoint on that origin. Without this a valid signed card
   * can be copied onto an attacker's host and presented as theirs.
   */
  expectedOrigin?: string
  /** Require every signature present to verify, not just one (default false: rotation-friendly). */
  requireAll?: boolean
  allowedAlgs?: readonly JwsAlg[]
}

const MAX_SIGNATURES = 8
const MAX_PROTECTED_BYTES = 2048

/** Endpoint origins a card declares, across the field names A2A versions have used. */
function cardOrigins(card: Record<string, unknown>): Set<string> {
  const urls: unknown[] = [card.url]
  for (const key of ['supportedInterfaces', 'additionalInterfaces']) {
    const list = card[key]
    if (Array.isArray(list)) for (const item of list) if (typeof item === 'object' && item !== null) urls.push((item as { url?: unknown }).url)
  }
  const origins = new Set<string>()
  for (const u of urls) {
    if (typeof u !== 'string') continue
    try {
      const parsed = new URL(u)
      if (parsed.protocol === 'https:' || parsed.protocol === 'http:') origins.add(parsed.origin)
    } catch {
      // not a URL: ignore
    }
  }
  return origins
}

export async function verifyAgentCard(card: unknown, opts: VerifyAgentCardOptions): Promise<AgentCardVerifyResult> {
  if (typeof card !== 'object' || card === null || Array.isArray(card)) return { ok: false, reason: 'not-a-card' }
  const c = card as Record<string, unknown>
  const sigs = c.signatures
  if (!Array.isArray(sigs) || sigs.length === 0) return { ok: false, reason: 'no-signature' }
  if (sigs.length > MAX_SIGNATURES) return { ok: false, reason: 'too-many-signatures' }

  if (opts.expectedOrigin !== undefined) {
    let origin: string
    try {
      origin = new URL(opts.expectedOrigin).origin
    } catch {
      throw new Error('verifyAgentCard: expectedOrigin must be a URL')
    }
    if (!cardOrigins(c).has(origin)) return { ok: false, reason: 'origin-mismatch', detail: origin }
  }

  let payload: string
  try {
    payload = cardPayload(c)
  } catch {
    return { ok: false, reason: 'not-a-card' }
  }
  const allowed = opts.allowedAlgs ?? (['ES256', 'EdDSA'] as const)

  const verified: string[] = []
  let failures = 0
  for (const entry of sigs as unknown[]) {
    const kid = await verifyOne(entry, payload, allowed, opts)
    if (kid) verified.push(kid)
    else failures++
  }
  if (verified.length === 0) return { ok: false, reason: 'no-valid-signature' }
  if (opts.requireAll && failures > 0) return { ok: false, reason: 'no-valid-signature', detail: `${failures} signature(s) failed` }
  return { ok: true, keyIds: verified }
}

async function verifyOne(entry: unknown, payload: string, allowed: readonly JwsAlg[], opts: VerifyAgentCardOptions): Promise<string | null> {
  if (typeof entry !== 'object' || entry === null) return null
  const e = entry as { protected?: unknown; signature?: unknown }
  if (typeof e.protected !== 'string' || typeof e.signature !== 'string' || e.protected.length > MAX_PROTECTED_BYTES) return null
  const headerBytes = b64uToBytes(e.protected)
  const sigBytes = b64uToBytes(e.signature)
  if (!headerBytes || !sigBytes) return null
  let header: Record<string, unknown>
  try {
    const parsed = JSON.parse(decoder.decode(headerBytes)) as unknown
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null
    header = parsed as Record<string, unknown>
  } catch {
    return null
  }
  if ('crit' in header) return null
  if (header.alg !== 'ES256' && header.alg !== 'EdDSA') return null
  if (!allowed.includes(header.alg)) return null
  if (typeof header.kid !== 'string' || header.kid.length === 0 || header.kid.length > 512) return null
  const jku = typeof header.jku === 'string' ? header.jku : undefined

  const jwk = await opts.resolveKey(header.kid, jku)
  if (!jwk || !isPublicJwk(jwk)) return null
  // The algorithm must be the one the trusted key is for, whatever the header says.
  if (algForJwk(jwk) !== header.alg) return null
  return (await jwsVerify(jwk, encoder.encode(signingInput(e.protected, payload)), sigBytes)) === 'valid' ? header.kid : null
}
