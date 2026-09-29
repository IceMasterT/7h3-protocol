/**
 * Signed provenance claims: a tamper-evident statement of where the inputs to an
 * action came from, so a policy can treat "an agent acting on a stranger's email"
 * differently from "an agent acting on its owner's instruction".
 *
 * WHAT THIS IS — and is not.
 *
 *   7h3 does not detect prompt injection. Nothing here inspects content. A claim
 *   carries a label that the SENDER'S RUNTIME asserts, signs, and binds to one
 *   action. Its value is that (a) the label cannot be altered or lifted onto a
 *   different action in transit, (b) the sender is accountable for it, and (c) a
 *   gateway can enforce policy on it — most usefully by demanding a human
 *   approval ({@link ./approval}) whenever untrusted material fed an action.
 *
 *   The label is only as good as the taint tracking that produced it. It MUST be
 *   computed by deterministic code that sees the data flow (see
 *   {@link ProvenanceContext}) and never by the model: a model that can write its
 *   own label can write "trusted".
 *
 * Verification fails closed: a missing, malformed, expired, mis-bound or badly
 * signed claim is treated as UNTRUSTED, never as trusted.
 */

import { signCanonicalPayloadEd25519, verifyCanonicalPayloadEd25519, MAX_CLOCK_SKEW_MS } from './protocol'
import { type BoundAction, actionsEqual, isBoundAction, stableStringify } from './actionBinding'
import type { KeyRegistry } from './keyRegistry'

export const PROVENANCE_HEADER = 'x-7h3-provenance'
export const PROVENANCE_VERSION = '7h3-prov/1'
/** Claims describe one imminent action; they are not long-lived credentials. */
export const MAX_PROVENANCE_TTL_MS = 5 * 60_000
export const DEFAULT_PROVENANCE_TTL_MS = 60_000
export const MAX_PROVENANCE_SOURCES = 64

export type TrustLevel = 'trusted' | 'untrusted'
export type SourceKind = 'user' | 'system' | 'agent' | 'tool' | 'email' | 'web' | 'file' | 'other'

const SOURCE_KINDS: readonly SourceKind[] = ['user', 'system', 'agent', 'tool', 'email', 'web', 'file', 'other']

export interface ProvenanceSource {
  kind: SourceKind
  /** Opaque reference (message id, URL, path). Never the content itself. */
  id?: string
  trust: TrustLevel
}

export interface ProvenanceClaim {
  version: typeof PROVENANCE_VERSION
  /** The agent asserting the claim; its key signs it. */
  sender: string
  action: BoundAction
  sources: ProvenanceSource[]
  /** Derived from `sources`; verification recomputes and rejects a mismatch. */
  trust: TrustLevel
  issuedAt: number
  expiresAt: number
  keyId: string
  signature: string
}

export type ProvenanceFailure =
  | 'missing'
  | 'malformed'
  | 'unsupported-version'
  | 'sender-mismatch'
  | 'trust-inconsistent'
  | 'ttl-too-long'
  | 'not-yet-valid'
  | 'expired'
  | 'action-mismatch'
  | 'no-sender-key'
  | 'invalid-signature'

export type ProvenanceVerifyResult = { ok: true; claim: ProvenanceClaim } | { ok: false; reason: ProvenanceFailure }

/**
 * Overall trust of a set of sources. Conservative on purpose: trusted only when
 * there is at least one source and every source is trusted. No sources means the
 * runtime knows nothing about the inputs, which is not the same as "clean".
 */
export function deriveTrust(sources: readonly ProvenanceSource[]): TrustLevel {
  if (sources.length === 0) return 'untrusted'
  return sources.every((s) => s.trust === 'trusted') ? 'trusted' : 'untrusted'
}

/**
 * Deterministic taint accumulator for the agent runtime. Register every input
 * that influences an action as it enters the context; ask it for the sources when
 * the action is about to be sent. Trust only ever degrades within a context:
 * once an untrusted source is recorded the context stays untrusted.
 */
export class ProvenanceContext {
  private readonly items: ProvenanceSource[] = []

  add(source: ProvenanceSource): this {
    if (!SOURCE_KINDS.includes(source.kind)) throw new Error(`ProvenanceContext: unknown source kind '${source.kind}'`)
    if (source.trust !== 'trusted' && source.trust !== 'untrusted') throw new Error('ProvenanceContext: invalid trust level')
    if (this.items.length >= MAX_PROVENANCE_SOURCES) {
      // Never drop a source silently: collapse the overflow into one untrusted marker
      // if any dropped input was untrusted, so the label cannot get cleaner by volume.
      const last = this.items[this.items.length - 1]
      if (source.trust === 'untrusted' && last.trust === 'trusted') {
        this.items[this.items.length - 1] = { kind: 'other', id: 'overflow', trust: 'untrusted' }
      }
      return this
    }
    this.items.push({ kind: source.kind, ...(source.id === undefined ? {} : { id: source.id }), trust: source.trust })
    return this
  }

  sources(): ProvenanceSource[] {
    return this.items.map((s) => ({ ...s }))
  }

  trust(): TrustLevel {
    return deriveTrust(this.items)
  }
}

function canonicalizeClaim(claim: Omit<ProvenanceClaim, 'signature'>): string {
  return stableStringify({
    version: claim.version,
    sender: claim.sender,
    action: { method: claim.action.method, path: claim.action.path, bodySha256: claim.action.bodySha256 },
    sources: claim.sources.map((s) => (s.id === undefined ? { kind: s.kind, trust: s.trust } : { kind: s.kind, id: s.id, trust: s.trust })),
    trust: claim.trust,
    issuedAt: claim.issuedAt,
    expiresAt: claim.expiresAt,
    keyId: claim.keyId,
  })
}

export interface SignProvenanceOptions {
  senderPrivateKey: string
  sender: string
  action: BoundAction
  sources: readonly ProvenanceSource[]
  ttlMs?: number
  keyId?: string
  now?: number
}

export async function signProvenance(opts: SignProvenanceOptions): Promise<ProvenanceClaim> {
  const ttlMs = opts.ttlMs ?? DEFAULT_PROVENANCE_TTL_MS
  if (!Number.isFinite(ttlMs) || ttlMs <= 0 || ttlMs > MAX_PROVENANCE_TTL_MS) {
    throw new Error(`signProvenance: ttlMs must be in (0, ${MAX_PROVENANCE_TTL_MS}]`)
  }
  if (!opts.sender) throw new Error('signProvenance: sender is required')
  if (!isBoundAction(opts.action)) throw new Error('signProvenance: malformed action')
  if (opts.sources.length > MAX_PROVENANCE_SOURCES) throw new Error('signProvenance: too many sources')
  for (const s of opts.sources) {
    if (!SOURCE_KINDS.includes(s.kind) || (s.trust !== 'trusted' && s.trust !== 'untrusted')) {
      throw new Error('signProvenance: invalid source')
    }
  }
  const now = opts.now ?? Date.now()
  const sources = opts.sources.map((s) => ({ kind: s.kind, ...(s.id === undefined ? {} : { id: s.id }), trust: s.trust }))
  const unsigned: Omit<ProvenanceClaim, 'signature'> = {
    version: PROVENANCE_VERSION,
    sender: opts.sender,
    action: { method: opts.action.method.toUpperCase(), path: opts.action.path, bodySha256: opts.action.bodySha256 },
    sources,
    trust: deriveTrust(sources),
    issuedAt: now,
    expiresAt: now + ttlMs,
    keyId: opts.keyId ?? `${opts.sender}-key`,
  }
  const signature = await signCanonicalPayloadEd25519(canonicalizeClaim(unsigned), opts.senderPrivateKey)
  return { ...unsigned, signature }
}

export function serializeProvenance(claim: ProvenanceClaim): string {
  return JSON.stringify(claim)
}

const MAX_HEADER_BYTES = 16 * 1024

/** Parse an untrusted header value; `null` for anything not structurally valid. */
export function parseProvenance(raw: string | undefined): ProvenanceClaim | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_HEADER_BYTES) return null
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    return null
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const v = value as Record<string, unknown>
  const str = (x: unknown): x is string => typeof x === 'string' && x.length > 0
  const time = (x: unknown): x is number => typeof x === 'number' && Number.isSafeInteger(x) && x > 0
  if (
    !str(v.version) ||
    !str(v.sender) ||
    !isBoundAction(v.action) ||
    !Array.isArray(v.sources) ||
    v.sources.length > MAX_PROVENANCE_SOURCES ||
    (v.trust !== 'trusted' && v.trust !== 'untrusted') ||
    !time(v.issuedAt) ||
    !time(v.expiresAt) ||
    !str(v.keyId) ||
    !str(v.signature)
  ) {
    return null
  }
  const sources: ProvenanceSource[] = []
  for (const s of v.sources as unknown[]) {
    if (typeof s !== 'object' || s === null) return null
    const o = s as Record<string, unknown>
    if (!SOURCE_KINDS.includes(o.kind as SourceKind)) return null
    if (o.trust !== 'trusted' && o.trust !== 'untrusted') return null
    if (o.id !== undefined && typeof o.id !== 'string') return null
    sources.push({ kind: o.kind as SourceKind, ...(o.id === undefined ? {} : { id: o.id as string }), trust: o.trust })
  }
  return {
    version: v.version as typeof PROVENANCE_VERSION,
    sender: v.sender,
    action: { method: v.action.method, path: v.action.path, bodySha256: v.action.bodySha256 },
    sources,
    trust: v.trust,
    issuedAt: v.issuedAt,
    expiresAt: v.expiresAt,
    keyId: v.keyId,
    signature: v.signature,
  }
}

export interface VerifyProvenanceOptions {
  keyRegistry: Pick<KeyRegistry, 'getPublicKey'>
  /** The authenticated sender of the request. The claim must be from this sender. */
  sender: string
  /** The action actually being performed. */
  action: BoundAction
  now?: number
  clockSkewMs?: number
}

export async function verifyProvenance(claim: ProvenanceClaim | null, opts: VerifyProvenanceOptions): Promise<ProvenanceVerifyResult> {
  if (claim === null) return { ok: false, reason: 'malformed' }
  if (claim.version !== PROVENANCE_VERSION) return { ok: false, reason: 'unsupported-version' }
  if (claim.sender !== opts.sender) return { ok: false, reason: 'sender-mismatch' }
  // A claim may not label itself cleaner than its own sources.
  if (claim.trust !== deriveTrust(claim.sources)) return { ok: false, reason: 'trust-inconsistent' }

  const now = opts.now ?? Date.now()
  const skew = opts.clockSkewMs ?? MAX_CLOCK_SKEW_MS
  if (claim.expiresAt <= claim.issuedAt || claim.expiresAt - claim.issuedAt > MAX_PROVENANCE_TTL_MS) {
    return { ok: false, reason: 'ttl-too-long' }
  }
  if (claim.issuedAt > now + skew) return { ok: false, reason: 'not-yet-valid' }
  if (now >= claim.expiresAt) return { ok: false, reason: 'expired' }
  if (!actionsEqual(claim.action, opts.action)) return { ok: false, reason: 'action-mismatch' }

  const publicKey = await opts.keyRegistry.getPublicKey(claim.sender)
  if (!publicKey) return { ok: false, reason: 'no-sender-key' }
  const { signature, ...unsigned } = claim
  if (!(await verifyCanonicalPayloadEd25519(canonicalizeClaim(unsigned), signature, publicKey))) {
    return { ok: false, reason: 'invalid-signature' }
  }
  return { ok: true, claim }
}

/** Trust to enforce policy with: a claim that did not verify is untrusted. */
export function effectiveTrust(result: ProvenanceVerifyResult): TrustLevel {
  return result.ok ? result.claim.trust : 'untrusted'
}
