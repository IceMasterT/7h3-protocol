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
  entrySignature: string // Ed25519 sig over the entry (minus entrySignature itself)
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
  return `{${parts.join(',')}}`
}

export interface AuditLogger {
  log(event: Omit<AuditEntry, 'id' | 'timestampMs' | 'entrySignature'>): Promise<void>
  query(opts?: { type?: AuditEventType; sender?: string; since?: number; limit?: number }): Promise<AuditEntry[]>
  verify(entry: AuditEntry, publicKey: string): Promise<boolean>
}

class InMemoryAuditLog implements AuditLogger {
  private entries: AuditEntry[] = []
  private privateKey: string
  private maxEntries: number

  constructor(privateKey: string, maxEntries = 10_000) {
    this.privateKey = privateKey
    this.maxEntries = maxEntries
  }

  async log(event: Omit<AuditEntry, 'id' | 'timestampMs' | 'entrySignature'>): Promise<void> {
    const id = `audit-${Date.now()}-${randomHex(5)}`
    const timestampMs = Date.now()

    const partial: Omit<AuditEntry, 'entrySignature'> = { id, timestampMs, ...event }
    const payload = canonicalAuditPayload(partial)
    const entrySignature = await signCanonicalPayloadEd25519(payload, this.privateKey)

    const entry: AuditEntry = { ...partial, entrySignature }

    if (this.entries.length >= this.maxEntries) {
      this.entries.shift()
    }
    this.entries.push(entry)
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
  async log(_event: Omit<AuditEntry, 'id' | 'timestampMs' | 'entrySignature'>): Promise<void> {}
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

export function createAuditLog(privateKey: string, opts?: { maxEntries?: number }): InMemoryAuditLog {
  return new InMemoryAuditLog(privateKey, opts?.maxEntries)
}

export { InMemoryAuditLog, NoopAuditLog }
