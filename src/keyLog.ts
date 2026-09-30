/**
 * An append-only, signed log of key registrations, rotations and revocations.
 *
 * The problem. A key registry is a table of "identity → public key". Whoever runs it
 * can silently swap a key, and nobody would ever know. That is exactly how an
 * operator (or an attacker who has compromised one) impersonates an agent. A key log
 * makes changes visible: every change is an entry, entries are hash-chained and
 * signed by the log operator, and the operator signs periodic checkpoints
 * (`size`, `headHash`). Anyone holding an earlier checkpoint can verify that the log
 * they see now still begins with exactly the history that checkpoint committed to;
 * anyone watching can list every key change for an identity they care about.
 *
 * WHAT THIS IS — and is not.
 *
 *   A hash chain with a single signing operator, plus signed checkpoints. It is
 *   tamper-EVIDENT, not tamper-proof: it cannot stop a malicious operator from
 *   publishing a bad key, it makes that visible to monitors, and it makes a rewrite
 *   of history detectable to anyone who kept a checkpoint. It is NOT a Merkle-tree
 *   transparency log: there are no O(log n) inclusion or consistency proofs, so
 *   verification is linear in the log size. Split-view attacks (showing different
 *   logs to different parties) are only detectable if parties compare checkpoints;
 *   {@link checkpointsConflict} turns two conflicting signed checkpoints into
 *   transferable evidence of operator equivocation, but something must exchange them.
 *
 * Verification enforces the semantics, not only the chain: a subject cannot have two
 * active keys, only a registered subject can rotate, only an existing key can be
 * revoked, and a revoked public key can never be registered again.
 */

import { signCanonicalPayloadEd25519, verifyCanonicalPayloadEd25519, MAX_CLOCK_SKEW_MS } from './protocol'
import { sha256Hex, stableStringify } from './actionBinding'
import type { KeyRegistry } from './keyRegistry'

export const KEYLOG_VERSION = '7h3-keylog/1'
export const KEYLOG_GENESIS_HASH = '0'.repeat(64)

export type KeyLogEntryType = 'register' | 'rotate' | 'revoke'

export interface KeyLogEntry {
  version: typeof KEYLOG_VERSION
  index: number
  type: KeyLogEntryType
  /** The identity the key belongs to (a message `sender`). */
  subject: string
  keyId: string
  /** SPKI base64url. Present for `register` and `rotate`; absent for `revoke`. */
  publicKey?: string
  reason?: string
  timestampMs: number
  /** Hash of the previous entry, or {@link KEYLOG_GENESIS_HASH}. Inside the signature. */
  prevHash: string
  operator: string
  signature: string
}

export interface KeyLogCheckpoint {
  version: typeof KEYLOG_VERSION
  operator: string
  size: number
  headHash: string
  timestampMs: number
  signature: string
}

const NAME = /^[A-Za-z0-9@._:/#-]{1,256}$/
const HASH = /^[0-9a-f]{64}$/

function entryPayload(e: Omit<KeyLogEntry, 'signature'>): string {
  return stableStringify({
    version: e.version,
    index: e.index,
    type: e.type,
    subject: e.subject,
    keyId: e.keyId,
    publicKey: e.publicKey ?? null,
    reason: e.reason ?? null,
    timestampMs: e.timestampMs,
    prevHash: e.prevHash,
    operator: e.operator,
  })
}

/** What the next entry chains to: SHA-256 over the full, signed entry. */
export async function keyLogEntryHash(e: KeyLogEntry): Promise<string> {
  const { signature, ...rest } = e
  return sha256Hex(`${entryPayload(rest)}.${signature}`)
}

function checkpointPayload(c: Omit<KeyLogCheckpoint, 'signature'>): string {
  return stableStringify({ version: c.version, operator: c.operator, size: c.size, headHash: c.headHash, timestampMs: c.timestampMs })
}

export interface SignKeyLogEntryOptions {
  operator: string
  operatorPrivateKey: string
  index: number
  prevHash: string
  timestampMs: number
}

/**
 * Low-level: sign one entry with explicit position and predecessor. It does NOT check
 * the log's rules. {@link KeyLog} is the normal way to write, and it refuses entries
 * that verification would reject; this exists for tools and for testing verifiers.
 */
export async function signKeyLogEntry(
  fields: { type: KeyLogEntryType; subject: string; keyId: string; publicKey?: string; reason?: string },
  opts: SignKeyLogEntryOptions,
): Promise<KeyLogEntry> {
  const unsigned: Omit<KeyLogEntry, 'signature'> = {
    version: KEYLOG_VERSION,
    index: opts.index,
    type: fields.type,
    subject: fields.subject,
    keyId: fields.keyId,
    ...(fields.publicKey === undefined ? {} : { publicKey: fields.publicKey }),
    ...(fields.reason === undefined ? {} : { reason: fields.reason }),
    timestampMs: opts.timestampMs,
    prevHash: opts.prevHash,
    operator: opts.operator,
  }
  return { ...unsigned, signature: await signCanonicalPayloadEd25519(entryPayload(unsigned), opts.operatorPrivateKey) }
}

export interface KeyLogOptions {
  operator: string
  operatorPrivateKey: string
  now?: () => number
}

/** The operator's writer. Holds the private key; publish `entries` and checkpoints. */
export class KeyLog {
  private readonly log: KeyLogEntry[] = []
  private head = KEYLOG_GENESIS_HASH
  private readonly state = new KeyLogState()
  private readonly now: () => number

  constructor(private readonly options: KeyLogOptions) {
    this.now = options.now ?? Date.now
  }

  get entries(): readonly KeyLogEntry[] {
    return this.log
  }

  get size(): number {
    return this.log.length
  }

  private async append(fields: { type: KeyLogEntryType; subject: string; keyId: string; publicKey?: string; reason?: string }): Promise<KeyLogEntry> {
    if (!NAME.test(fields.subject) || !NAME.test(fields.keyId)) throw new Error('KeyLog: subject and keyId must be 1-256 of [A-Za-z0-9@._:/#-]')
    const last = this.log[this.log.length - 1]
    const entry = await signKeyLogEntry(fields, {
      operator: this.options.operator,
      operatorPrivateKey: this.options.operatorPrivateKey,
      index: this.log.length,
      prevHash: this.head,
      timestampMs: Math.max(this.now(), last ? last.timestampMs : 0), // never goes backwards
    })
    // Refuse to record something verification would reject: the log must always verify.
    const broken = this.state.apply(entry)
    if (broken) throw new Error(`KeyLog: ${broken} at index ${entry.index}`)
    this.log.push(entry)
    this.head = await keyLogEntryHash(entry)
    return entry
  }

  register(subject: string, keyId: string, publicKey: string): Promise<KeyLogEntry> {
    return this.append({ type: 'register', subject, keyId, publicKey })
  }

  rotate(subject: string, keyId: string, publicKey: string): Promise<KeyLogEntry> {
    return this.append({ type: 'rotate', subject, keyId, publicKey })
  }

  revoke(subject: string, keyId: string, reason?: string): Promise<KeyLogEntry> {
    return this.append({ type: 'revoke', subject, keyId, ...(reason === undefined ? {} : { reason }) })
  }

  /** A signed commitment to the log as it stands now. */
  async checkpoint(): Promise<KeyLogCheckpoint> {
    const unsigned: Omit<KeyLogCheckpoint, 'signature'> = {
      version: KEYLOG_VERSION,
      operator: this.options.operator,
      size: this.log.length,
      headHash: this.head,
      timestampMs: this.now(),
    }
    return { ...unsigned, signature: await signCanonicalPayloadEd25519(checkpointPayload(unsigned), this.options.operatorPrivateKey) }
  }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export type KeyLogFailure =
  | 'malformed'
  | 'wrong-index'
  | 'broken-chain'
  | 'wrong-operator'
  | 'invalid-signature'
  | 'time-went-backwards'
  | 'duplicate-key-id'
  | 'already-registered'
  | 'not-registered'
  | 'no-active-key'
  | 'unknown-key'
  | 'already-revoked'
  | 'revoked-key-reuse'
  | 'key-reuse'
  | 'missing-public-key'
  | 'unexpected-public-key'

export type KeyLogVerifyResult =
  | { ok: true; size: number; headHash: string }
  | { ok: false; index: number; reason: KeyLogFailure }

interface SubjectState {
  active?: { keyId: string; publicKey: string }
  /** keyId -> publicKey for every key this subject ever had. */
  keys: Map<string, string>
  revokedKeyIds: Set<string>
}

/** The rules' running state. One instance per log being read or written. */
class KeyLogState {
  readonly subjects = new Map<string, SubjectState>()
  /** publicKey -> the subject that first used it. A key identifies one subject, once, forever. */
  readonly keyOwner = new Map<string, string>()
  readonly revokedPublicKeys = new Set<string>()

  /** Apply one entry's meaning. Returns the rule it breaks, or `null` (and updates the state). */
  apply(e: KeyLogEntry): KeyLogFailure | null {
    let s = this.subjects.get(e.subject)
    if (e.type === 'revoke') {
      if (e.publicKey !== undefined) return 'unexpected-public-key'
      if (!s) return 'not-registered'
      const publicKey = s.keys.get(e.keyId)
      if (publicKey === undefined) return 'unknown-key'
      if (s.revokedKeyIds.has(e.keyId)) return 'already-revoked'
      s.revokedKeyIds.add(e.keyId)
      this.revokedPublicKeys.add(publicKey)
      if (s.active?.keyId === e.keyId) s.active = undefined
      return null
    }
    if (e.publicKey === undefined) return 'missing-public-key'
    if (!s) {
      if (e.type === 'rotate') return 'not-registered'
      s = { keys: new Map(), revokedKeyIds: new Set() }
    }
    if (e.type === 'register' && s.active) return 'already-registered'
    if (e.type === 'rotate' && !s.active) return 'no-active-key'
    if (s.keys.has(e.keyId)) return 'duplicate-key-id'
    if (this.revokedPublicKeys.has(e.publicKey)) return 'revoked-key-reuse'
    if (this.keyOwner.has(e.publicKey)) return 'key-reuse'
    this.subjects.set(e.subject, s)
    s.keys.set(e.keyId, e.publicKey)
    this.keyOwner.set(e.publicKey, e.subject)
    s.active = { keyId: e.keyId, publicKey: e.publicKey }
    return null
  }
}

export interface VerifyKeyLogOptions {
  /** The operator's public key (SPKI base64url). */
  operatorPublicKey: string
  /** The operator the log must name. */
  operator?: string
  /** Reject entries stamped further in the future than this beyond `now` (default 30 s skew). */
  now?: number
  clockSkewMs?: number
}

function wellFormed(e: unknown): e is KeyLogEntry {
  if (typeof e !== 'object' || e === null) return false
  const v = e as Record<string, unknown>
  return (
    v.version === KEYLOG_VERSION &&
    typeof v.index === 'number' &&
    Number.isSafeInteger(v.index) &&
    v.index >= 0 &&
    (v.type === 'register' || v.type === 'rotate' || v.type === 'revoke') &&
    typeof v.subject === 'string' &&
    NAME.test(v.subject) &&
    typeof v.keyId === 'string' &&
    NAME.test(v.keyId) &&
    (v.publicKey === undefined || (typeof v.publicKey === 'string' && v.publicKey.length > 0 && v.publicKey.length < 512)) &&
    (v.reason === undefined || (typeof v.reason === 'string' && v.reason.length < 1024)) &&
    typeof v.timestampMs === 'number' &&
    Number.isSafeInteger(v.timestampMs) &&
    typeof v.prevHash === 'string' &&
    HASH.test(v.prevHash) &&
    typeof v.operator === 'string' &&
    NAME.test(v.operator) &&
    typeof v.signature === 'string' &&
    v.signature.length > 0
  )
}

/**
 * Verify a whole log: sequence, hash chain, operator signatures, non-decreasing
 * timestamps, and the semantic rules for registering, rotating and revoking keys.
 */
export async function verifyKeyLog(entries: readonly KeyLogEntry[], opts: VerifyKeyLogOptions): Promise<KeyLogVerifyResult> {
  if (!opts.operatorPublicKey) throw new Error('verifyKeyLog: operatorPublicKey is required')
  const state = new KeyLogState()
  let prev = KEYLOG_GENESIS_HASH
  let lastTime = 0
  const now = opts.now ?? Date.now()
  const skew = opts.clockSkewMs ?? MAX_CLOCK_SKEW_MS

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]
    const fail = (reason: KeyLogFailure): KeyLogVerifyResult => ({ ok: false, index: i, reason })
    if (!wellFormed(e)) return fail('malformed')
    if (e.index !== i) return fail('wrong-index')
    if (e.prevHash !== prev) return fail('broken-chain')
    if (opts.operator !== undefined && e.operator !== opts.operator) return fail('wrong-operator')
    const { signature, ...rest } = e
    if (!(await verifyCanonicalPayloadEd25519(entryPayload(rest), signature, opts.operatorPublicKey))) return fail('invalid-signature')
    if (e.timestampMs > now + skew) return fail('time-went-backwards') // stamped in the future
    if (e.timestampMs < lastTime) return fail('time-went-backwards')
    lastTime = e.timestampMs
    const broken = state.apply(e)
    if (broken) return fail(broken)
    prev = await keyLogEntryHash(e)
  }
  return { ok: true, size: entries.length, headHash: prev }
}

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

export async function verifyCheckpoint(cp: KeyLogCheckpoint, opts: { operatorPublicKey: string; operator?: string }): Promise<boolean> {
  if (typeof cp !== 'object' || cp === null || cp.version !== KEYLOG_VERSION) return false
  if (!Number.isSafeInteger(cp.size) || cp.size < 0 || typeof cp.headHash !== 'string' || !HASH.test(cp.headHash)) return false
  if (typeof cp.signature !== 'string' || typeof cp.operator !== 'string' || !Number.isSafeInteger(cp.timestampMs)) return false
  if (opts.operator !== undefined && cp.operator !== opts.operator) return false
  const { signature, ...rest } = cp
  try {
    return await verifyCanonicalPayloadEd25519(checkpointPayload(rest), signature, opts.operatorPublicKey)
  } catch {
    return false
  }
}

/**
 * Does `entries` still begin with exactly the history `checkpoint` committed to? A log
 * that was rewritten after the checkpoint (an entry changed, dropped or reordered)
 * fails here even though the operator can re-sign everything.
 */
export async function logExtendsCheckpoint(
  checkpoint: KeyLogCheckpoint,
  entries: readonly KeyLogEntry[],
  opts: { operatorPublicKey: string; now?: number },
): Promise<boolean> {
  if (!(await verifyCheckpoint(checkpoint, { operatorPublicKey: opts.operatorPublicKey }))) return false
  if (entries.length < checkpoint.size) return false
  const verdict = await verifyKeyLog(entries.slice(0, checkpoint.size), { operatorPublicKey: opts.operatorPublicKey, now: opts.now })
  return verdict.ok && verdict.size === checkpoint.size && verdict.headHash === checkpoint.headHash
}

/**
 * Two validly signed checkpoints of the same size with different heads are proof the
 * operator showed two different logs (equivocation). Returns true only when both are
 * genuine and they conflict; the pair is transferable evidence.
 */
export async function checkpointsConflict(a: KeyLogCheckpoint, b: KeyLogCheckpoint, opts: { operatorPublicKey: string }): Promise<boolean> {
  if (a.size !== b.size || a.headHash === b.headHash) return false
  return (await verifyCheckpoint(a, opts)) && (await verifyCheckpoint(b, opts))
}

// ---------------------------------------------------------------------------
// Reading the log
// ---------------------------------------------------------------------------

export interface ResolvedKeys {
  /** The single currently active key per subject. */
  active: Map<string, { keyId: string; publicKey: string }>
  revoked: Map<string, Set<string>>
}

/** Current state from a log. Call {@link verifyKeyLog} first: this trusts its input. */
export function resolveKeyLog(entries: readonly KeyLogEntry[]): ResolvedKeys {
  const active = new Map<string, { keyId: string; publicKey: string }>()
  const revoked = new Map<string, Set<string>>()
  for (const e of entries) {
    if (e.type === 'revoke') {
      if (!revoked.has(e.subject)) revoked.set(e.subject, new Set())
      revoked.get(e.subject)!.add(e.keyId)
      if (active.get(e.subject)?.keyId === e.keyId) active.delete(e.subject)
    } else if (e.publicKey !== undefined) {
      active.set(e.subject, { keyId: e.keyId, publicKey: e.publicKey })
    }
  }
  return { active, revoked }
}

/** Entries from `fromIndex` on that concern `subject`: what a monitor watches for. */
export function keyChangesFor(entries: readonly KeyLogEntry[], subject: string, fromIndex = 0): KeyLogEntry[] {
  return entries.filter((e) => e.index >= fromIndex && e.subject === subject)
}

export interface KeyLogRegistryOptions {
  /** Returns the current published entries (fetch, cache, or read from storage). */
  entries: () => Promise<readonly KeyLogEntry[]> | readonly KeyLogEntry[]
  operatorPublicKey: string
  operator?: string
  /** A checkpoint you already hold. The log must still extend it, or every lookup fails. */
  trustedCheckpoint?: () => Promise<KeyLogCheckpoint | null> | KeyLogCheckpoint | null
  /** Re-verify at most this often (default 30 s). */
  refreshMs?: number
  now?: () => number
}

/**
 * A {@link KeyRegistry} backed by a verified key log. Every refresh verifies the whole
 * chain and (if you hold one) that it still extends your checkpoint. Anything that
 * fails verification makes every lookup return `null` — a log that does not verify is
 * not evidence of any key.
 */
export function createKeyLogRegistry(options: KeyLogRegistryOptions): KeyRegistry {
  const now = options.now ?? Date.now
  const refreshMs = options.refreshMs ?? 30_000
  let cached: { resolved: ResolvedKeys | null; at: number } | undefined

  async function load(): Promise<ResolvedKeys | null> {
    const t = now()
    if (cached && t - cached.at < refreshMs) return cached.resolved
    let resolved: ResolvedKeys | null = null
    try {
      const entries = await options.entries()
      const verdict = await verifyKeyLog(entries, { operatorPublicKey: options.operatorPublicKey, operator: options.operator, now: t })
      const cp = options.trustedCheckpoint ? await options.trustedCheckpoint() : null
      if (verdict.ok && (!cp || (await logExtendsCheckpoint(cp, entries, { operatorPublicKey: options.operatorPublicKey, now: t })))) {
        resolved = resolveKeyLog(entries)
      }
    } catch {
      resolved = null
    }
    cached = { resolved, at: t }
    return resolved
  }

  return {
    async getPublicKey(senderId: string): Promise<string | null> {
      const state = await load()
      return state?.active.get(senderId)?.publicKey ?? null
    },
  }
}
