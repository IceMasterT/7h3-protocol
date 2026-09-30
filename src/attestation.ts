/**
 * Workload attestation: a signed statement that a particular agent key belongs to a
 * particular build.
 *
 * A signature on a message proves someone holding a private key sent it. It does not
 * prove WHAT is running with that key: the approved container image, the reviewed
 * agent configuration, the pinned tool list. An attestation closes that gap. A party
 * you trust (a CI system, a deployment pipeline, a verifier service) signs a statement
 * "agent A, using public key K, was measured as {image: …, config: …}". A verifier then
 * checks the statement and compares the measurements against an allow-list of digests it
 * approves.
 *
 * WHAT THIS IS — and is not.
 *
 *   7h3 verifies statements signed by an attester you trust. It does not verify
 *   hardware attestation evidence (SGX, SEV-SNP, TDX, TPM quotes) itself: if you use
 *   those, a verifier service checks the evidence and signs a statement, and 7h3
 *   consumes that. An attestation is exactly as trustworthy as its attester: a
 *   compromised attester can vouch for anything.
 *
 * Everything fails closed. A verifier without an attester allow-list or without any
 * required measurement is a programming error and throws, so "attestation is
 * enabled" can never mean "any statement from anyone passes".
 */

import { randomHex, signCanonicalPayloadEd25519, verifyCanonicalPayloadEd25519, MAX_CLOCK_SKEW_MS } from './protocol'
import { sha256Hex, stableStringify } from './actionBinding'
import type { KeyRegistry } from './keyRegistry'
import type { ToolPinSet } from './mcpToolPinning'

export const ATTESTATION_VERSION = '7h3-attest/1'
/** A statement should describe a deployment, not stand in for one forever. */
export const MAX_ATTESTATION_LIFETIME_MS = 24 * 60 * 60_000
export const DEFAULT_ATTESTATION_LIFETIME_MS = 60 * 60_000

export type ClaimValue = string | number | boolean

export interface AttestationStatement {
  version: typeof ATTESTATION_VERSION
  id: string
  subject: {
    /** The agent identity (a message `sender`). */
    agent: string
    /** The agent's public key (SPKI base64url) this statement binds to the measurements. */
    publicKey: string
  }
  /**
   * Named measurements as lower-case hex SHA-256 or SHA-512 digests. Conventional
   * names: `image` (container or binary digest), `config`, `policy`, `toolPins`
   * (see {@link toolPinsDigest}), `sbom`, `model`. The names are the deployment's own.
   */
  measurements: Record<string, string>
  /** Additional facts the attester vouches for (environment, tenant, …). Covered by the signature. */
  claims?: Record<string, ClaimValue>
  attester: string
  issuedAt: number
  expiresAt: number
  keyId: string
  signature: string
}

const DIGEST = /^(?:[0-9a-f]{64}|[0-9a-f]{128})$/
const MAX_MEASUREMENTS = 32
const MAX_CLAIMS = 32
const NAME = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/

/** SHA-256 of a JSON value's RFC 8785 canonical form: a stable measurement for structured data. */
export async function digestJson(value: unknown): Promise<string> {
  return sha256Hex(stableStringify(value))
}

/** The measurement to use for "this agent is configured with exactly these approved tool pins". */
export async function toolPinsDigest(pins: ToolPinSet): Promise<string> {
  return digestJson({ server: pins.server, pins: pins.pins.map((p) => ({ name: p.name, digest: p.digest })) })
}

function canonicalize(s: Omit<AttestationStatement, 'signature'>): string {
  return stableStringify({
    version: s.version,
    id: s.id,
    subject: { agent: s.subject.agent, publicKey: s.subject.publicKey },
    measurements: s.measurements,
    claims: s.claims ?? null,
    attester: s.attester,
    issuedAt: s.issuedAt,
    expiresAt: s.expiresAt,
    keyId: s.keyId,
  })
}

export interface IssueAttestationOptions {
  attesterPrivateKey: string
  attester: string
  subject: { agent: string; publicKey: string }
  measurements: Record<string, string>
  claims?: Record<string, ClaimValue>
  lifetimeMs?: number
  keyId?: string
  now?: number
}

export async function issueAttestation(opts: IssueAttestationOptions): Promise<AttestationStatement> {
  const lifetime = opts.lifetimeMs ?? DEFAULT_ATTESTATION_LIFETIME_MS
  if (!Number.isFinite(lifetime) || lifetime <= 0 || lifetime > MAX_ATTESTATION_LIFETIME_MS) {
    throw new Error(`issueAttestation: lifetimeMs must be in (0, ${MAX_ATTESTATION_LIFETIME_MS}]`)
  }
  if (!opts.attester || !opts.subject.agent || !opts.subject.publicKey) throw new Error('issueAttestation: attester and subject are required')
  const names = Object.keys(opts.measurements)
  if (names.length === 0 || names.length > MAX_MEASUREMENTS) throw new Error('issueAttestation: 1..32 measurements are required')
  for (const [k, v] of Object.entries(opts.measurements)) {
    if (!NAME.test(k)) throw new Error(`issueAttestation: invalid measurement name '${k}'`)
    if (!DIGEST.test(v)) throw new Error(`issueAttestation: measurement '${k}' must be a lower-case hex SHA-256 or SHA-512 digest`)
  }
  for (const [k, v] of Object.entries(opts.claims ?? {})) {
    if (!NAME.test(k)) throw new Error(`issueAttestation: invalid claim name '${k}'`)
    if (typeof v === 'number' && !Number.isFinite(v)) throw new Error(`issueAttestation: claim '${k}' must be finite`)
  }
  if (Object.keys(opts.claims ?? {}).length > MAX_CLAIMS) throw new Error('issueAttestation: too many claims')

  const now = opts.now ?? Date.now()
  const unsigned: Omit<AttestationStatement, 'signature'> = {
    version: ATTESTATION_VERSION,
    id: `att-${now}-${randomHex(8)}`,
    subject: { agent: opts.subject.agent, publicKey: opts.subject.publicKey },
    measurements: { ...opts.measurements },
    ...(opts.claims ? { claims: { ...opts.claims } } : {}),
    attester: opts.attester,
    issuedAt: now,
    expiresAt: now + lifetime,
    keyId: opts.keyId ?? `${opts.attester}-key`,
  }
  return { ...unsigned, signature: await signCanonicalPayloadEd25519(canonicalize(unsigned), opts.attesterPrivateKey) }
}

export type AttestationFailure =
  | 'malformed'
  | 'unsupported-version'
  | 'attester-not-allowed'
  | 'lifetime-too-long'
  | 'not-yet-valid'
  | 'expired'
  | 'too-old'
  | 'subject-mismatch'
  | 'key-mismatch'
  | 'no-attester-key'
  | 'invalid-signature'
  | 'revoked'
  | 'measurement-missing'
  | 'measurement-not-approved'
  | 'claim-mismatch'

export type AttestationVerifyResult =
  | { ok: true; statement: AttestationStatement }
  | { ok: false; reason: AttestationFailure; detail?: string }

export interface VerifyAttestationOptions {
  /** Public keys of attesters (a registry separate from your agents' registry). */
  attesterKeys: Pick<KeyRegistry, 'getPublicKey'>
  /** Attesters you trust. Required and non-empty. */
  allowedAttesters: readonly string[]
  /** The agent the message came from. */
  agent: string
  /** The key that agent's messages are verified with. The statement must bind to exactly this key. */
  agentPublicKey: string
  /**
   * For each measurement you care about, the digests you approve. Every named
   * measurement must be present and match one of them. Required and non-empty:
   * a statement that is authentic but constrains nothing must not pass as "attested".
   */
  requiredMeasurements: Readonly<Record<string, readonly string[]>>
  /** Facts that must match exactly. */
  requiredClaims?: Readonly<Record<string, ClaimValue>>
  /** Maximum age since issuance, in ms. */
  maxAgeMs?: number
  /** Return true for a statement id that has been withdrawn. */
  isRevoked?: (id: string) => boolean | Promise<boolean>
  now?: number
  clockSkewMs?: number
}

function isStatement(value: unknown): value is AttestationStatement {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  const str = (x: unknown): x is string => typeof x === 'string' && x.length > 0
  const time = (x: unknown): x is number => typeof x === 'number' && Number.isSafeInteger(x) && x > 0
  const rec = (x: unknown, check: (y: unknown) => boolean, max: number): boolean =>
    typeof x === 'object' && x !== null && !Array.isArray(x) && Object.keys(x).length <= max && Object.values(x).every(check)
  const subject = v.subject as Record<string, unknown> | undefined
  return (
    str(v.version) &&
    str(v.id) &&
    typeof subject === 'object' &&
    subject !== null &&
    str(subject.agent) &&
    str(subject.publicKey) &&
    rec(v.measurements, (d) => typeof d === 'string' && DIGEST.test(d), MAX_MEASUREMENTS) &&
    Object.keys(v.measurements as object).every((k) => NAME.test(k)) &&
    (v.claims === undefined ||
      (rec(v.claims, (c) => typeof c === 'string' || typeof c === 'boolean' || (typeof c === 'number' && Number.isFinite(c)), MAX_CLAIMS) &&
        Object.keys(v.claims as object).every((k) => NAME.test(k)))) &&
    str(v.attester) &&
    time(v.issuedAt) &&
    time(v.expiresAt) &&
    str(v.keyId) &&
    str(v.signature)
  )
}

/** Parse untrusted JSON into a statement, or `null`. Never throws. */
export function parseAttestation(raw: string | unknown): AttestationStatement | null {
  let value: unknown = raw
  if (typeof raw === 'string') {
    if (raw.length > 32 * 1024) return null
    try {
      value = JSON.parse(raw)
    } catch {
      return null
    }
  }
  if (!isStatement(value)) return null
  const v = value
  return {
    version: v.version,
    id: v.id,
    subject: { agent: v.subject.agent, publicKey: v.subject.publicKey },
    measurements: { ...v.measurements },
    ...(v.claims ? { claims: { ...v.claims } } : {}),
    attester: v.attester,
    issuedAt: v.issuedAt,
    expiresAt: v.expiresAt,
    keyId: v.keyId,
    signature: v.signature,
  }
}

export async function verifyAttestation(statement: AttestationStatement | null, opts: VerifyAttestationOptions): Promise<AttestationVerifyResult> {
  if (opts.allowedAttesters.length === 0) throw new Error('verifyAttestation: allowedAttesters must not be empty')
  if (Object.keys(opts.requiredMeasurements).length === 0) throw new Error('verifyAttestation: requiredMeasurements must not be empty')
  for (const [name, digests] of Object.entries(opts.requiredMeasurements)) {
    if (digests.length === 0) throw new Error(`verifyAttestation: requiredMeasurements['${name}'] lists no approved digests`)
  }
  if (statement === null || !isStatement(statement)) return { ok: false, reason: 'malformed' }
  if (statement.version !== ATTESTATION_VERSION) return { ok: false, reason: 'unsupported-version' }
  if (!opts.allowedAttesters.includes(statement.attester)) return { ok: false, reason: 'attester-not-allowed' }

  const now = opts.now ?? Date.now()
  const skew = opts.clockSkewMs ?? MAX_CLOCK_SKEW_MS
  if (statement.expiresAt <= statement.issuedAt || statement.expiresAt - statement.issuedAt > MAX_ATTESTATION_LIFETIME_MS) {
    return { ok: false, reason: 'lifetime-too-long' }
  }
  if (statement.issuedAt > now + skew) return { ok: false, reason: 'not-yet-valid' }
  if (now >= statement.expiresAt) return { ok: false, reason: 'expired' }
  if (opts.maxAgeMs !== undefined && now - statement.issuedAt > opts.maxAgeMs) return { ok: false, reason: 'too-old' }

  if (statement.subject.agent !== opts.agent) return { ok: false, reason: 'subject-mismatch' }
  if (statement.subject.publicKey !== opts.agentPublicKey) return { ok: false, reason: 'key-mismatch' }

  const attesterKey = await opts.attesterKeys.getPublicKey(statement.attester)
  if (!attesterKey) return { ok: false, reason: 'no-attester-key' }
  const { signature, ...unsigned } = statement
  if (!(await verifyCanonicalPayloadEd25519(canonicalize(unsigned), signature, attesterKey))) return { ok: false, reason: 'invalid-signature' }

  if (opts.isRevoked && (await opts.isRevoked(statement.id))) return { ok: false, reason: 'revoked' }

  for (const [name, approved] of Object.entries(opts.requiredMeasurements)) {
    const actual = statement.measurements[name]
    if (actual === undefined) return { ok: false, reason: 'measurement-missing', detail: name }
    if (!approved.includes(actual)) return { ok: false, reason: 'measurement-not-approved', detail: name }
  }
  for (const [name, expected] of Object.entries(opts.requiredClaims ?? {})) {
    if (statement.claims?.[name] !== expected) return { ok: false, reason: 'claim-mismatch', detail: name }
  }
  return { ok: true, statement }
}

// ---------------------------------------------------------------------------
// Registry wrapper
// ---------------------------------------------------------------------------

export interface AttestedKeyRegistryOptions extends Omit<VerifyAttestationOptions, 'agent' | 'agentPublicKey' | 'now'> {
  /** The registry that maps a sender to its public key. */
  base: Pick<KeyRegistry, 'getPublicKey'>
  /** Where to obtain the statement for an agent (a database, the agent's own endpoint, a header). */
  getAttestation: (agent: string) => Promise<AttestationStatement | null> | AttestationStatement | null
  /** How long a positive result is reused, in ms (default 30 s; never past the statement's expiry). */
  cacheMs?: number
  maxCacheEntries?: number
  now?: () => number
}

/**
 * A {@link KeyRegistry} that only yields keys for agents with a valid attestation. Use
 * it as the gateway's `keyRegistry` and an agent that is not running an approved
 * build simply has no key: its messages fail signature verification with "no key",
 * exactly like an unknown sender. Fails closed on every error.
 */
export function createAttestedKeyRegistry(options: AttestedKeyRegistryOptions): KeyRegistry {
  const now = options.now ?? Date.now
  const cacheMs = options.cacheMs ?? 30_000
  const maxEntries = options.maxCacheEntries ?? 1000
  const cache = new Map<string, { key: string; until: number }>()

  return {
    async getPublicKey(sender: string): Promise<string | null> {
      const key = await options.base.getPublicKey(sender)
      if (!key) return null
      const t = now()
      const hit = cache.get(sender)
      if (hit && hit.key === key && hit.until > t) return key

      try {
        const statement = await options.getAttestation(sender)
        const result = await verifyAttestation(statement, { ...options, agent: sender, agentPublicKey: key, now: t })
        if (!result.ok) {
          cache.delete(sender)
          return null
        }
        if (cache.size >= maxEntries) cache.delete(cache.keys().next().value as string)
        cache.set(sender, { key, until: Math.min(t + cacheMs, result.statement.expiresAt) })
        return key
      } catch {
        cache.delete(sender)
        return null
      }
    },
  }
}
