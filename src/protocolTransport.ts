import {
  createEnvelope,
  signEnvelopeHmac,
  validateEnvelope,
  canonicalizeEnvelope,
  verifyCanonicalPayloadSignature,
  type SignatureVerificationMaterial,
  type IntentKind,
  type ProtocolDiagnostic,
  type ProtocolEnvelope,
} from './protocol'
import { decodeEnvelopeBinary, encodeEnvelopeBinary } from './protocolBinary'
import { InMemoryReplayCache, type ReplayCache } from './protocolReplay'

export type WireFormat = 'json' | 'compact' | 'binary'
export type BatchWireFormat = Exclude<WireFormat, 'binary'>

interface CompactSignature {
  a?: 'HS256' | 'ED25519'
  k: string
  v: string
}

interface CompactEnvelope {
  v: 'aip/0.1'
  mid: string
  ts: number
  ttl: number
  s: string
  n: string
  i: IntentKind
  c: string
  r?: string
  cap?: string
  cid?: string
  sig?: CompactSignature
}

export interface ReceiveEnvelopeOptions {
  nowMs?: number
  requireSignature?: boolean
  maxClockSkewMs?: number
  replayCache?: ReplayCache
  verificationMaterialCache?: VerificationMaterialCache
  secretResolver?: (keyId: string, sender: string) => string | undefined | Promise<string | undefined>
  signatureResolver?: (
    signature: NonNullable<ProtocolEnvelope['signature']>,
    sender: string,
  ) => SignatureVerificationMaterial | undefined | Promise<SignatureVerificationMaterial | undefined>
  telemetry?: (event: TransportTelemetryEvent) => void | Promise<void>
}

export interface ReceiveEnvelopeBatchOptions extends ReceiveEnvelopeOptions {
  batchConcurrency?: number
}

export interface TransportTelemetryEvent {
  phase:
    | 'decoded'
    | 'rejected_clock_skew'
    | 'rejected_validation'
    | 'rejected_replay'
    | 'rejected_missing_signature'
    | 'rejected_missing_material'
    | 'rejected_bad_signature'
    | 'batch_summary'
    | 'accepted'
  nowMs: number
  sender?: string
  messageId?: string
  reason?: string
}

export interface ReceiveEnvelopeResult {
  ok: boolean
  diagnostics: ProtocolDiagnostic[]
  envelope: ProtocolEnvelope | null
}

export interface VerificationMaterialCache {
  get(key: string, nowMs?: number): SignatureVerificationMaterial | undefined
  set(key: string, material: SignatureVerificationMaterial, expiresAtMs: number): void
  delete?(key: string): void
}

export class InMemoryVerificationMaterialCache implements VerificationMaterialCache {
  private readonly entries = new Map<string, { expiresAtMs: number; material: SignatureVerificationMaterial }>()

  private readonly maxEntries: number

  constructor(maxEntries = 512) {
    this.maxEntries = maxEntries
  }

  get(key: string, nowMs = Date.now()): SignatureVerificationMaterial | undefined {
    const entry = this.entries.get(key)
    if (!entry) return undefined
    if (entry.expiresAtMs <= nowMs) {
      this.entries.delete(key)
      return undefined
    }
    return entry.material
  }

  set(key: string, material: SignatureVerificationMaterial, expiresAtMs: number): void {
    if (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value as string | undefined
      if (oldest) this.entries.delete(oldest)
    }
    this.entries.set(key, { expiresAtMs, material })
  }

  delete(key: string): void {
    this.entries.delete(key)
  }
}

function verificationMaterialCacheKey(signature: NonNullable<ProtocolEnvelope['signature']>, sender: string): string {
  return `${sender}|${signature.alg}|${signature.keyId}`
}

function isProtocolEnvelope(value: unknown): value is ProtocolEnvelope {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<ProtocolEnvelope>
  return Boolean(candidate.header && candidate.body)
}

function isCompactEnvelope(value: unknown): value is CompactEnvelope {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<CompactEnvelope>
  return candidate.v === 'aip/0.1' && typeof candidate.mid === 'string' && typeof candidate.i === 'string'
}

function compactToEnvelope(compact: CompactEnvelope): ProtocolEnvelope {
  return {
    header: {
      version: compact.v,
      messageId: compact.mid,
      timestampMs: compact.ts,
      ttlMs: compact.ttl,
      sender: compact.s,
      recipient: compact.r,
      nonce: compact.n,
    },
    body: {
      intent: compact.i,
      content: compact.c,
      capability: compact.cap,
      correlationId: compact.cid,
    },
    signature: compact.sig
      ? {
          alg: compact.sig.a ?? 'HS256',
          keyId: compact.sig.k,
          value: compact.sig.v,
        }
      : undefined,
  }
}

function envelopeToCompact(envelope: ProtocolEnvelope): CompactEnvelope {
  return {
    v: envelope.header.version,
    mid: envelope.header.messageId,
    ts: envelope.header.timestampMs,
    ttl: envelope.header.ttlMs,
    s: envelope.header.sender,
    r: envelope.header.recipient,
    n: envelope.header.nonce,
    i: envelope.body.intent,
    c: envelope.body.content,
    cap: envelope.body.capability,
    cid: envelope.body.correlationId,
    sig: envelope.signature
      ? {
          a: envelope.signature.alg,
          k: envelope.signature.keyId,
          v: envelope.signature.value,
        }
      : undefined,
  }
}

export type WireEnvelope = string | Uint8Array

export function decodeEnvelope(raw: WireEnvelope): ReceiveEnvelopeResult {
  if (raw instanceof Uint8Array) {
    return decodeEnvelopeBinary(raw)
  }

  try {
    const parsed = JSON.parse(raw) as unknown
    if (isCompactEnvelope(parsed)) {
      return { ok: true, diagnostics: [], envelope: compactToEnvelope(parsed) }
    }
    if (isProtocolEnvelope(parsed)) {
      return { ok: true, diagnostics: [], envelope: parsed }
    }
    return {
      ok: false,
      diagnostics: [{ level: 'error', message: 'Envelope JSON shape is not recognized' }],
      envelope: null,
    }
  } catch {
    return {
      ok: false,
      diagnostics: [{ level: 'error', message: 'Invalid JSON envelope' }],
      envelope: null,
    }
  }
}

export function encodeEnvelope(envelope: ProtocolEnvelope, format: 'binary'): Uint8Array
export function encodeEnvelope(envelope: ProtocolEnvelope, format?: 'json' | 'compact'): string
export function encodeEnvelope(envelope: ProtocolEnvelope, format: WireFormat): WireEnvelope
export function encodeEnvelope(envelope: ProtocolEnvelope, format: WireFormat = 'json'): WireEnvelope {
  if (format === 'binary') {
    return encodeEnvelopeBinary(envelope)
  }
  if (format === 'compact') {
    return JSON.stringify(envelopeToCompact(envelope))
  }
  return JSON.stringify(envelope)
}

export function encodeEnvelopeBatch(envelopes: ProtocolEnvelope[], format: BatchWireFormat = 'compact'): string {
  if (format === 'compact') {
    return JSON.stringify(envelopes.map(envelopeToCompact))
  }
  return JSON.stringify(envelopes)
}

export function decodeEnvelopeBatch(raw: string): ReceiveEnvelopeResult[] {
  try {
    const parsed = JSON.parse(raw) as unknown
    if (!Array.isArray(parsed)) {
      return [
        {
          ok: false,
          diagnostics: [{ level: 'error', message: 'Batch payload must be a JSON array' }],
          envelope: null,
        },
      ]
    }

    return parsed.map((entry): ReceiveEnvelopeResult => {
      if (isCompactEnvelope(entry)) {
        return { ok: true, diagnostics: [], envelope: compactToEnvelope(entry) }
      }
      if (isProtocolEnvelope(entry)) {
        return { ok: true, diagnostics: [], envelope: entry }
      }
      return {
        ok: false,
        diagnostics: [{ level: 'error', message: 'Batch item has unrecognized envelope shape' }],
        envelope: null,
      }
    })
  } catch {
    return [
      {
        ok: false,
        diagnostics: [{ level: 'error', message: 'Invalid JSON batch payload' }],
        envelope: null,
      },
    ]
  }
}

export async function receiveEnvelope(
  input: WireEnvelope | ProtocolEnvelope,
  options: ReceiveEnvelopeOptions = {},
): Promise<ReceiveEnvelopeResult> {
  const nowMs = options.nowMs ?? Date.now()
  const requireSignature = options.requireSignature ?? true
  const maxClockSkewMs = options.maxClockSkewMs ?? 30_000

  async function emitTelemetry(event: Omit<TransportTelemetryEvent, 'nowMs'>): Promise<void> {
    if (!options.telemetry) return
    await options.telemetry({
      nowMs,
      ...event,
    })
  }

  const decoded = typeof input === 'string' || input instanceof Uint8Array ? decodeEnvelope(input) : { ok: true, diagnostics: [], envelope: input }
  if (!decoded.ok || !decoded.envelope) return decoded

  await emitTelemetry({
    phase: 'decoded',
    sender: decoded.envelope.header.sender,
    messageId: decoded.envelope.header.messageId,
  })

  if (decoded.envelope.header.timestampMs > nowMs + maxClockSkewMs) {
    const message = 'Message timestamp exceeds allowed clock skew'
    const diagnostics: ProtocolDiagnostic[] = [{ level: 'error', message }]
    await emitTelemetry({
      phase: 'rejected_clock_skew',
      sender: decoded.envelope.header.sender,
      messageId: decoded.envelope.header.messageId,
      reason: message,
    })
    return { ok: false, diagnostics, envelope: decoded.envelope }
  }

  const diagnostics: ProtocolDiagnostic[] = [...validateEnvelope(decoded.envelope, nowMs)]
  if (diagnostics.some((d) => d.level === 'error')) {
    await emitTelemetry({
      phase: 'rejected_validation',
      sender: decoded.envelope.header.sender,
      messageId: decoded.envelope.header.messageId,
      reason: diagnostics.find((d) => d.level === 'error')?.message,
    })
    return { ok: false, diagnostics, envelope: decoded.envelope }
  }

  if (!decoded.envelope.signature) {
    if (requireSignature) {
      diagnostics.push({ level: 'error', message: 'Missing signature' })
      await emitTelemetry({
        phase: 'rejected_missing_signature',
        sender: decoded.envelope.header.sender,
        messageId: decoded.envelope.header.messageId,
        reason: 'Missing signature',
      })
      return { ok: false, diagnostics, envelope: decoded.envelope }
    }
    await emitTelemetry({
      phase: 'accepted',
      sender: decoded.envelope.header.sender,
      messageId: decoded.envelope.header.messageId,
    })
    return { ok: true, diagnostics, envelope: decoded.envelope }
  }

  let verificationMaterial: SignatureVerificationMaterial | undefined
  const signature = decoded.envelope.signature
  const cacheKey = verificationMaterialCacheKey(signature, decoded.envelope.header.sender)
  if (options.verificationMaterialCache) {
    verificationMaterial = options.verificationMaterialCache.get(cacheKey, nowMs)
  }

  if (options.signatureResolver) {
    verificationMaterial =
      verificationMaterial ?? (await options.signatureResolver(signature, decoded.envelope.header.sender))
  }

  if (!verificationMaterial && signature.alg === 'HS256' && options.secretResolver) {
    const secret = await options.secretResolver(signature.keyId, decoded.envelope.header.sender)
    if (secret) {
      verificationMaterial = { alg: 'HS256', secret }
    }
  }

  if (verificationMaterial && options.verificationMaterialCache) {
    const expiresAtMs = Math.max(nowMs + 1, decoded.envelope.header.timestampMs + decoded.envelope.header.ttlMs)
    options.verificationMaterialCache.set(cacheKey, verificationMaterial, expiresAtMs)
  }

  if (!verificationMaterial) {
    diagnostics.push({ level: 'error', message: 'No signature verification material found for keyId/sender' })
    await emitTelemetry({
      phase: 'rejected_missing_material',
      sender: decoded.envelope.header.sender,
      messageId: decoded.envelope.header.messageId,
      reason: 'No signature verification material found for keyId/sender',
    })
    return { ok: false, diagnostics, envelope: decoded.envelope }
  }

  const canonicalPayload = canonicalizeEnvelope({ header: decoded.envelope.header, body: decoded.envelope.body })
  const isValid = await verifyCanonicalPayloadSignature(canonicalPayload, decoded.envelope.signature, verificationMaterial)
  if (!isValid) {
    diagnostics.push({ level: 'error', message: 'Signature verification failed' })
    await emitTelemetry({
      phase: 'rejected_bad_signature',
      sender: decoded.envelope.header.sender,
      messageId: decoded.envelope.header.messageId,
      reason: 'Signature verification failed',
    })
    return { ok: false, diagnostics, envelope: decoded.envelope }
  }

  if (options.replayCache) {
    const replay = await options.replayCache.consume(decoded.envelope, nowMs)
    if (!replay.ok) {
      diagnostics.push({ level: 'error', message: replay.reason ?? 'Replay detected' })
      await emitTelemetry({
        phase: 'rejected_replay',
        sender: decoded.envelope.header.sender,
        messageId: decoded.envelope.header.messageId,
        reason: replay.reason,
      })
      return { ok: false, diagnostics, envelope: decoded.envelope }
    }
  }

  await emitTelemetry({
    phase: 'accepted',
    sender: decoded.envelope.header.sender,
    messageId: decoded.envelope.header.messageId,
  })

  return { ok: true, diagnostics, envelope: decoded.envelope }
}

export async function receiveEnvelopeBatch(
  input: string | Array<WireEnvelope | ProtocolEnvelope>,
  options: ReceiveEnvelopeBatchOptions = {},
): Promise<ReceiveEnvelopeResult[]> {
  const concurrency = Math.max(1, Math.floor(options.batchConcurrency ?? Number.POSITIVE_INFINITY))
  const receiveItems = async (items: Array<WireEnvelope | ProtocolEnvelope | ReceiveEnvelopeResult>): Promise<ReceiveEnvelopeResult[]> => {
    const results: ReceiveEnvelopeResult[] = new Array(items.length)
    let nextIndex = 0
    const workerCount = Number.isFinite(concurrency) ? Math.min(concurrency, items.length) : items.length
    await Promise.all(
      Array.from({ length: workerCount }, async () => {
        while (nextIndex < items.length) {
          const index = nextIndex
          nextIndex += 1
          const item = items[index]
          if (item && typeof item === 'object' && 'ok' in item && 'diagnostics' in item && 'envelope' in item) {
            results[index] = item
          } else {
            results[index] = await receiveEnvelope(item as WireEnvelope | ProtocolEnvelope, options)
          }
        }
      }),
    )
    await options.telemetry?.({
      phase: 'batch_summary',
      nowMs: options.nowMs ?? Date.now(),
      reason: `items=${items.length};accepted=${results.filter((result) => result?.ok).length}`,
    })
    return results
  }

  if (typeof input === 'string') {
    const decoded = decodeEnvelopeBatch(input)
    return receiveItems(decoded.map((item) => (item.ok && item.envelope ? item.envelope : item)))
  }

  return receiveItems(input)
}

export class SessionTransport {
  private readonly options: ReceiveEnvelopeOptions

  constructor(options: Omit<ReceiveEnvelopeOptions, 'replayCache'> & { replayCache?: ReplayCache } = {}) {
    this.options = {
      ...options,
      replayCache: options.replayCache ?? new InMemoryReplayCache(),
      verificationMaterialCache: options.verificationMaterialCache ?? new InMemoryVerificationMaterialCache(),
    }
  }

  receive(input: WireEnvelope | ProtocolEnvelope, nowMs = Date.now()): Promise<ReceiveEnvelopeResult> {
    return receiveEnvelope(input, { ...this.options, nowMs })
  }

  receiveBatch(input: string | Array<WireEnvelope | ProtocolEnvelope>, nowMs = Date.now()): Promise<ReceiveEnvelopeResult[]> {
    return receiveEnvelopeBatch(input, { ...this.options, nowMs })
  }
}

export async function createSignedMessage(input: {
  sender: string
  recipient?: string
  intent: IntentKind
  content: string
  capability?: string
  correlationId?: string
  ttlMs?: number
  messageId?: string
  nonce?: string
  nowMs?: number
  secret: string
  keyId?: string
}): Promise<ProtocolEnvelope> {
  const unsigned = createEnvelope(input)
  return signEnvelopeHmac(unsigned, input.secret, input.keyId)
}
