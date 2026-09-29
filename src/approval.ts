/**
 * Step-up approval: a human (or another authority) countersigns ONE specific
 * action before an agent may perform it.
 *
 * A capability token says what an agent MAY do. An approval grant says a named
 * approver looked at THIS action and allowed it once. The grant is bound to:
 *
 *   - the acting agent (`subject`) — it cannot be lent to another agent;
 *   - the exact action (`method`, normalized `path`, SHA-256 of the body) — it
 *     cannot be replayed against a different route, verb or amount;
 *   - a short validity window — at most {@link MAX_APPROVAL_TTL_MS};
 *   - a single use — consumed through a {@link ReplayStore}.
 *
 * Separation of duties is enforced: an agent can never approve itself.
 *
 * Verification is ordered so that a request which fails any check does NOT
 * consume the grant: a grant is spent only by a request that is otherwise fully
 * valid. An attacker who intercepts a grant and presents it with a different
 * body therefore cannot burn the legitimate use.
 */

import { signCanonicalPayloadEd25519, verifyCanonicalPayloadEd25519, randomHex, MAX_CLOCK_SKEW_MS } from './protocol'
import type { ReplayStore } from './replayStores'
import {
  type ActionInput,
  type BoundAction,
  actionsEqual,
  bindAction,
  isBoundAction,
  stableStringify,
} from './actionBinding'

export const APPROVAL_HEADER = 'x-7h3-approval'
export const APPROVAL_VERSION = '7h3-approval/1'
/** An approval is meant to be acted on now, not stockpiled. */
export const MAX_APPROVAL_TTL_MS = 10 * 60_000
export const DEFAULT_APPROVAL_TTL_MS = 2 * 60_000

export interface ApprovalGrant {
  version: typeof APPROVAL_VERSION
  id: string
  /** Identity of the approver. Looked up in the approver key registry. */
  approver: string
  /** The agent this approval authorizes. */
  subject: string
  action: BoundAction
  /** Free text shown to the approver / kept in audit trails. Covered by the signature. */
  reason?: string
  issuedAt: number
  expiresAt: number
  keyId: string
  signature: string
}

export type ApprovalFailure =
  | 'malformed'
  | 'unsupported-version'
  | 'approver-not-allowed'
  | 'self-approval'
  | 'ttl-too-long'
  | 'not-yet-valid'
  | 'expired'
  | 'subject-mismatch'
  | 'action-mismatch'
  | 'no-approver-key'
  | 'invalid-signature'
  | 'already-used'

export type ApprovalVerifyResult = { ok: true; grant: ApprovalGrant } | { ok: false; reason: ApprovalFailure }

export interface ApproverKeyLookup {
  getPublicKey(approverId: string): Promise<string | null>
}

function unsignedForm(grant: Omit<ApprovalGrant, 'signature'>): Omit<ApprovalGrant, 'signature'> {
  // Build explicitly so an extra property smuggled onto a parsed object can never
  // end up covered by (or excluded from) the signature.
  const base: Omit<ApprovalGrant, 'signature'> = {
    version: grant.version,
    id: grant.id,
    approver: grant.approver,
    subject: grant.subject,
    action: { method: grant.action.method, path: grant.action.path, bodySha256: grant.action.bodySha256 },
    issuedAt: grant.issuedAt,
    expiresAt: grant.expiresAt,
    keyId: grant.keyId,
  }
  return grant.reason === undefined ? base : { ...base, reason: grant.reason }
}

/** Canonical bytes a grant's signature covers. */
export function canonicalizeApproval(grant: Omit<ApprovalGrant, 'signature'>): string {
  return stableStringify(unsignedForm(grant))
}

export interface IssueApprovalOptions {
  approverPrivateKey: string
  approverId: string
  /** The agent being authorized. */
  subject: string
  /** The action being approved. Either the raw request parts or an already-bound action. */
  action: ActionInput | BoundAction
  ttlMs?: number
  reason?: string
  keyId?: string
  now?: number
}

function isBound(a: ActionInput | BoundAction): a is BoundAction {
  return typeof (a as BoundAction).bodySha256 === 'string'
}

export async function issueApproval(opts: IssueApprovalOptions): Promise<ApprovalGrant> {
  const ttlMs = opts.ttlMs ?? DEFAULT_APPROVAL_TTL_MS
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new Error('issueApproval: ttlMs must be positive')
  if (ttlMs > MAX_APPROVAL_TTL_MS) {
    throw new Error(`issueApproval: ttlMs ${ttlMs} exceeds the ${MAX_APPROVAL_TTL_MS} ms maximum`)
  }
  if (!opts.approverId || !opts.subject) throw new Error('issueApproval: approverId and subject are required')
  if (opts.approverId === opts.subject) throw new Error('issueApproval: an agent cannot approve itself')

  const action = isBound(opts.action) ? opts.action : await bindAction(opts.action)
  if (!isBoundAction(action)) throw new Error('issueApproval: malformed action')

  const now = opts.now ?? Date.now()
  const unsigned: Omit<ApprovalGrant, 'signature'> = {
    version: APPROVAL_VERSION,
    id: `appr-${now}-${randomHex(8)}`,
    approver: opts.approverId,
    subject: opts.subject,
    action: { method: action.method.toUpperCase(), path: action.path, bodySha256: action.bodySha256 },
    ...(opts.reason === undefined ? {} : { reason: opts.reason }),
    issuedAt: now,
    expiresAt: now + ttlMs,
    keyId: opts.keyId ?? `${opts.approverId}-key`,
  }
  const signature = await signCanonicalPayloadEd25519(canonicalizeApproval(unsigned), opts.approverPrivateKey)
  return { ...unsigned, signature }
}

/** Serialize for the {@link APPROVAL_HEADER} header. */
export function serializeApproval(grant: ApprovalGrant): string {
  return JSON.stringify(grant)
}

const MAX_HEADER_BYTES = 8 * 1024

/**
 * Parse an untrusted header value. Returns `null` for anything that is not a
 * structurally valid grant; it never throws and never returns a partially
 * validated object.
 */
export function parseApproval(raw: string | undefined): ApprovalGrant | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_HEADER_BYTES) return null
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    return null
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const v = value as Record<string, unknown>
  const isNonEmpty = (x: unknown): x is string => typeof x === 'string' && x.length > 0
  const isTime = (x: unknown): x is number => typeof x === 'number' && Number.isSafeInteger(x) && x > 0
  if (
    !isNonEmpty(v.version) ||
    !isNonEmpty(v.id) ||
    !isNonEmpty(v.approver) ||
    !isNonEmpty(v.subject) ||
    !isBoundAction(v.action) ||
    !isTime(v.issuedAt) ||
    !isTime(v.expiresAt) ||
    !isNonEmpty(v.keyId) ||
    !isNonEmpty(v.signature) ||
    (v.reason !== undefined && typeof v.reason !== 'string')
  ) {
    return null
  }
  return {
    version: v.version as typeof APPROVAL_VERSION,
    id: v.id,
    approver: v.approver,
    subject: v.subject,
    action: { method: v.action.method, path: v.action.path, bodySha256: v.action.bodySha256 },
    ...(v.reason === undefined ? {} : { reason: v.reason }),
    issuedAt: v.issuedAt,
    expiresAt: v.expiresAt,
    keyId: v.keyId,
    signature: v.signature,
  }
}

export interface VerifyApprovalOptions {
  approverKeys: ApproverKeyLookup
  /**
   * Approvers permitted to authorize this action. Required and non-empty: a
   * verifier that accepts "any approver with a registered key" would let any
   * registered principal approve anything.
   */
  allowedApprovers: readonly string[]
  /** The agent that is about to act. Must equal the grant's subject. */
  subject: string
  /** The action actually being performed, reduced from the real request. */
  action: BoundAction
  /**
   * Single-use enforcement. Strongly recommended; without it a grant can be
   * presented repeatedly until it expires.
   */
  replayStore?: ReplayStore
  now?: number
  clockSkewMs?: number
}

export async function verifyApproval(grant: ApprovalGrant | null, opts: VerifyApprovalOptions): Promise<ApprovalVerifyResult> {
  if (opts.allowedApprovers.length === 0) {
    // Programmer error, not a runtime condition: never quietly accept everyone.
    throw new Error('verifyApproval: allowedApprovers must not be empty')
  }
  if (grant === null) return { ok: false, reason: 'malformed' }
  if (grant.version !== APPROVAL_VERSION) return { ok: false, reason: 'unsupported-version' }
  if (!opts.allowedApprovers.includes(grant.approver)) return { ok: false, reason: 'approver-not-allowed' }
  if (grant.approver === grant.subject) return { ok: false, reason: 'self-approval' }

  const now = opts.now ?? Date.now()
  const skew = opts.clockSkewMs ?? MAX_CLOCK_SKEW_MS
  if (grant.expiresAt <= grant.issuedAt || grant.expiresAt - grant.issuedAt > MAX_APPROVAL_TTL_MS) {
    return { ok: false, reason: 'ttl-too-long' }
  }
  if (grant.issuedAt > now + skew) return { ok: false, reason: 'not-yet-valid' }
  if (now >= grant.expiresAt) return { ok: false, reason: 'expired' }

  if (grant.subject !== opts.subject) return { ok: false, reason: 'subject-mismatch' }
  if (!actionsEqual(grant.action, opts.action)) return { ok: false, reason: 'action-mismatch' }

  const publicKey = await opts.approverKeys.getPublicKey(grant.approver)
  if (!publicKey) return { ok: false, reason: 'no-approver-key' }

  const { signature, ...unsigned } = grant
  const valid = await verifyCanonicalPayloadEd25519(canonicalizeApproval(unsigned), signature, publicKey)
  if (!valid) return { ok: false, reason: 'invalid-signature' }

  // Consume last, and only for an otherwise fully valid presentation.
  if (opts.replayStore) {
    const remaining = Math.max(1, grant.expiresAt - now)
    const replayed = await opts.replayStore.check(`7h3:approval:${grant.id}`, remaining + skew)
    if (replayed) return { ok: false, reason: 'already-used' }
  }
  return { ok: true, grant }
}
