/**
 * Hash-chained, Ed25519-signed receipts for WebMCP tool calls.
 *
 * Every invocation is recorded — allowed *and* refused. Each receipt carries the
 * hash of its predecessor, so the log is tamper-evident as a whole rather than
 * entry by entry: editing or deleting any historical receipt breaks every
 * receipt that follows it, and `verifyChain` reports the exact index where the
 * chain first fails.
 *
 * This is a deliberate strengthening of `@7h3/protocol`'s `InMemoryAuditLog`,
 * which signs entries independently and therefore cannot detect deletion of a
 * whole entry.
 */

import { signCanonicalPayloadEd25519, verifyCanonicalPayloadEd25519 } from '@7h3/protocol'
import { canonicalJson, sha256Hex } from './crypto'
import type { ChainVerification, Receipt } from './types'

/** Genesis value for `prevHash`, so entry 0 is chained like every other entry. */
export const GENESIS_HASH = '0'.repeat(64)

/** Canonical signing payload for a receipt: every field except the signature. */
export function canonicalReceiptPayload(receipt: Omit<Receipt, 'signature'>): string {
  return canonicalJson(receipt)
}

/** SHA-256 over a complete, signed receipt — this is what the next entry chains to. */
export async function receiptHash(receipt: Receipt): Promise<string> {
  return sha256Hex(canonicalJson(receipt))
}

export interface AppendReceiptInput {
  tool: string
  scope: string
  method: 'READ' | 'WRITE'
  outcome: Receipt['outcome']
  reason?: Receipt['reason']
  detail?: string
  grantId: string | null
  inputHash: string
}

/**
 * An append-only receipt log.
 *
 * Kept in memory: a page's chain lives for the session and is exported by the
 * user. Swapping in durable storage is a matter of persisting `entries` — the
 * chain verifies identically wherever it is stored, which is the point.
 */
export class ReceiptLog {
  private entries: Receipt[] = []
  private readonly privateKey: string
  private readonly keyId: string
  private readonly now: () => number
  private tip: string = GENESIS_HASH

  constructor(opts: { privateKey: string; keyId: string; now?: () => number }) {
    this.privateKey = opts.privateKey
    this.keyId = opts.keyId
    this.now = opts.now ?? (() => Date.now())
  }

  /** Append and sign a receipt, chaining it to the current tip. */
  async append(input: AppendReceiptInput): Promise<Receipt> {
    const seq = this.entries.length
    const unsigned: Omit<Receipt, 'signature'> = {
      seq,
      id: `rcpt-${seq}-${this.tip.slice(0, 8)}`,
      timestampMs: this.now(),
      prevHash: this.tip,
      keyId: this.keyId,
      ...input,
    }

    const signature = await signCanonicalPayloadEd25519(
      canonicalReceiptPayload(unsigned),
      this.privateKey,
    )
    const receipt: Receipt = { ...unsigned, signature }

    this.entries.push(receipt)
    this.tip = await receiptHash(receipt)
    return receipt
  }

  /** All receipts, oldest first. Returns a copy — the log is append-only. */
  all(): Receipt[] {
    return [...this.entries]
  }

  get length(): number {
    return this.entries.length
  }

  /** Current chain tip; the `prevHash` the next receipt will carry. */
  get head(): string {
    return this.tip
  }

  /** Serialize the chain for export. */
  export(): string {
    return JSON.stringify(this.entries, null, 2)
  }
}

/**
 * Verify a receipt chain end to end.
 *
 * Checks, for every entry in order: the sequence number is contiguous, the
 * `prevHash` matches the running hash of the previous entry, and the Ed25519
 * signature is valid under `publicKey`. Reports the first failing index so a UI
 * can point at the exact receipt that was tampered with.
 */
export async function verifyChain(
  entries: Receipt[],
  publicKey: string,
): Promise<ChainVerification> {
  let expectedPrev = GENESIS_HASH

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]

    if (entry.seq !== i) {
      return { ok: false, length: entries.length, brokenAt: i, reason: `seq-mismatch: expected ${i}, got ${entry.seq}` }
    }
    if (entry.prevHash !== expectedPrev) {
      return { ok: false, length: entries.length, brokenAt: i, reason: 'prev-hash-mismatch' }
    }

    const { signature, ...unsigned } = entry
    const sigOk = await verifyCanonicalPayloadEd25519(
      canonicalReceiptPayload(unsigned),
      signature,
      publicKey,
    )
    if (!sigOk) {
      return { ok: false, length: entries.length, brokenAt: i, reason: 'bad-signature' }
    }

    expectedPrev = await receiptHash(entry)
  }

  return { ok: true, length: entries.length, brokenAt: null }
}
