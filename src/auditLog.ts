import {
  randomHex,
  signCanonicalPayloadEd25519,
  verifyCanonicalPayloadEd25519,
} from './protocol'

export type AuditEventType =
  | 'verify-ok'
  | 'verify-fail'
  | 'rate-limited'
  | 'sender-denied'
  | 'response-signed'

export interface AuditEntry {
  id: string
  timestampMs: number
  type: AuditEventType
  sender?: string
  path?: string
  method?: string
  envelopeId?: string
  failReason?: string
  upstream?: string
  responseStatus?: number
  /**
   * SHA-256 of the preceding entry, or 64 zeros for the first.
   *
   * Without this, entries are signed independently, which detects modification
   * but NOT deletion: an attacker who can write to the log removes the entries
   * covering their activity and every remaining entry still verifies. Chaining
   * makes the log tamper-evident as a whole — see verifyAuditChain.
   */
  prevHash: string
  entrySignature: string // Ed25519 sig over the entry (minus entrySignature itself)
}

/** Genesis value for `prevHash`, so entry 0 is chained like every other entry. */
export const AUDIT_GENESIS_HASH = '0'.repeat(64)

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** SHA-256 over a complete, signed entry — what the next entry chains to. */
export async function auditEntryHash(entry: AuditEntry): Promise<string> {
  return sha256Hex(canonicalAuditPayload(entry) + entry.entrySignature)
}

/**
 * Produce a canonical payload string from an AuditEntry, excluding entrySignature.
 * Uses explicit key order and omits undefined fields for determinism.
 */
function canonicalAuditPayload(entry: Omit<AuditEntry, 'entrySignature'> & { entrySignature?: string }): string {
  const parts: string[] = [
    `"id":${JSON.stringify(entry.id)}`,
    `"timestampMs":${entry.timestampMs}`,
    `"type":${JSON.stringify(entry.type)}`,
  ]
  if (entry.sender !== undefined) parts.push(`"sender":${JSON.stringify(entry.sender)}`)
  if (entry.path !== undefined) parts.push(`"path":${JSON.stringify(entry.path)}`)
  if (entry.method !== undefined) parts.push(`"method":${JSON.stringify(entry.method)}`)
  if (entry.envelopeId !== undefined) parts.push(`"envelopeId":${JSON.stringify(entry.envelopeId)}`)
  if (entry.failReason !== undefined) parts.push(`"failReason":${JSON.stringify(entry.failReason)}`)
  if (entry.upstream !== undefined) parts.push(`"upstream":${JSON.stringify(entry.upstream)}`)
  if (entry.responseStatus !== undefined) parts.push(`"responseStatus":${entry.responseStatus}`)
  // Inside the signature, so a rewritten link invalidates the entry itself.
  parts.push(`"prevHash":${JSON.stringify(entry.prevHash)}`)
  return `{${parts.join(',')}}`
}

export interface AuditLogger {
  log(event: Omit<AuditEntry, 'id' | 'timestampMs' | 'entrySignature' | 'prevHash'>): Promise<void>
  query(opts?: { type?: AuditEventType; sender?: string; since?: number; limit?: number }): Promise<AuditEntry[]>
  verify(entry: AuditEntry, publicKey: string): Promise<boolean>
}

class InMemoryAuditLog implements AuditLogger {
  private entries: AuditEntry[] = []
  private tip: string = AUDIT_GENESIS_HASH
  private privateKey: string
  private maxEntries: number

  constructor(privateKey: string, maxEntries = 10_000) {
    this.privateKey = privateKey
    this.maxEntries = maxEntries
  }

  async log(event: Omit<AuditEntry, 'id' | 'timestampMs' | 'entrySignature' | 'prevHash'>): Promise<void> {
    const id = `audit-${Date.now()}-${randomHex(5)}`
    const timestampMs = Date.now()

    const partial: Omit<AuditEntry, 'entrySignature'> = {
      id,
      timestampMs,
      ...event,
      prevHash: this.tip,
    }
    const payload = canonicalAuditPayload(partial)
    const entrySignature = await signCanonicalPayloadEd25519(payload, this.privateKey)

    const entry: AuditEntry = { ...partial, entrySignature }

    if (this.entries.length >= this.maxEntries) {
      this.entries.shift()
    }
    this.entries.push(entry)
    this.tip = await auditEntryHash(entry)
  }

  async query(opts?: {
    type?: AuditEventType
    sender?: string
    since?: number
    limit?: number
  }): Promise<AuditEntry[]> {
    let results = [...this.entries]

    if (opts?.type !== undefined) {
      results = results.filter(e => e.type === opts.type)
    }
    if (opts?.sender !== undefined) {
      results = results.filter(e => e.sender === opts.sender)
    }
    if (opts?.since !== undefined) {
      results = results.filter(e => e.timestampMs >= opts.since!)
    }
    if (opts?.limit !== undefined) {
      results = results.slice(-opts.limit)
    }

    return results
  }

  async verify(entry: AuditEntry, publicKey: string): Promise<boolean> {
    const partial: Omit<AuditEntry, 'entrySignature'> = {
      id: entry.id,
      timestampMs: entry.timestampMs,
      type: entry.type,
      sender: entry.sender,
      path: entry.path,
      method: entry.method,
      envelopeId: entry.envelopeId,
      failReason: entry.failReason,
      upstream: entry.upstream,
      prevHash: entry.prevHash,
      responseStatus: entry.responseStatus,
    }
    const payload = canonicalAuditPayload(partial)
    return verifyCanonicalPayloadEd25519(payload, entry.entrySignature, publicKey)
  }

  size(): number {
    return this.entries.length
  }
}

class NoopAuditLog implements AuditLogger {
  async log(_event: Omit<AuditEntry, 'id' | 'timestampMs' | 'entrySignature' | 'prevHash'>): Promise<void> {}
  async query(_opts?: {
    type?: AuditEventType
    sender?: string
    since?: number
    limit?: number
  }): Promise<AuditEntry[]> {
    return []
  }
  async verify(_entry: AuditEntry, _publicKey: string): Promise<boolean> {
    return false
  }
  size(): number {
    return 0
  }
}

export interface AuditChainVerification {
  ok: boolean
  length: number
  /** Index of the first entry that failed, or null when the chain verifies. */
  brokenAt: number | null
  reason?: string
}

/**
 * Verify an audit log end to end.
 *
 * Checks, for each entry in order, that `prevHash` matches the running hash of
 * the previous entry and that the Ed25519 signature is valid. Verifying entries
 * one at a time catches modification but not deletion — every surviving entry
 * still verifies on its own — which is exactly what this closes.
 */
export async function verifyAuditChain(
  entries: AuditEntry[],
  publicKey: string,
): Promise<AuditChainVerification> {
  let expectedPrev = AUDIT_GENESIS_HASH

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]

    if (entry.prevHash !== expectedPrev) {
      return { ok: false, length: entries.length, brokenAt: i, reason: 'prev-hash-mismatch' }
    }

    const { entrySignature, ...unsigned } = entry
    const valid = await verifyCanonicalPayloadEd25519(
      canonicalAuditPayload(unsigned as Omit<AuditEntry, 'entrySignature'>),
      entrySignature,
      publicKey,
    )
    if (!valid) {
      return { ok: false, length: entries.length, brokenAt: i, reason: 'bad-signature' }
    }

    expectedPrev = await auditEntryHash(entry)
  }

  return { ok: true, length: entries.length, brokenAt: null }
}

export function createAuditLog(privateKey: string, opts?: { maxEntries?: number }): InMemoryAuditLog {
  return new InMemoryAuditLog(privateKey, opts?.maxEntries)
}

export { InMemoryAuditLog, NoopAuditLog }
