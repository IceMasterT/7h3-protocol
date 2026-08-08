import {
  signCanonicalPayloadEd25519,
  verifyCanonicalPayloadEd25519,
  signCanonicalPayloadHmac,
  verifyCanonicalPayloadHmac,
  generateEd25519KeypairBase64Url,
} from './protocol'

export const WEBHOOK_SIG_HEADER = 'x-7h3-sig'
export const WEBHOOK_TS_HEADER = 'x-7h3-ts'
export const WEBHOOK_DEFAULT_TTL_MS = 300_000  // 5 minutes

/**
 * A verified webhook signature is otherwise valid to replay any number of
 * times until it ages out of maxAgeMs — the signature+timestamp cover
 * authenticity and freshness, but nothing dedupes delivery. A replayCache
 * closes that gap. The Ed25519/HMAC signature is deterministic per
 * (timestampMs, body, key), so it doubles as a stable dedup key — no wire
 * format change needed.
 */
export interface WebhookReplayCache {
  /** Returns true if this key was successfully reserved (first use), false if already seen. */
  consume(key: string, expiresAtMs: number, nowMs: number): boolean | Promise<boolean>
}

/** Bounded in-memory WebhookReplayCache — single process only, does not survive a restart. */
export class InMemoryWebhookReplayCache implements WebhookReplayCache {
  private readonly seen = new Map<string, number>()
  private readonly maxEntries: number

  constructor(maxEntries = 10_000) {
    this.maxEntries = maxEntries
  }

  private prune(nowMs: number): void {
    for (const [key, expiresAt] of this.seen) {
      if (expiresAt <= nowMs) this.seen.delete(key)
    }
  }

  consume(key: string, expiresAtMs: number, nowMs: number): boolean {
    this.prune(nowMs)
    const existing = this.seen.get(key)
    if (existing !== undefined && existing > nowMs) return false
    if (this.seen.size >= this.maxEntries) {
      const oldest = this.seen.keys().next().value as string | undefined
      if (oldest !== undefined) this.seen.delete(oldest)
    }
    this.seen.set(key, expiresAtMs)
    return true
  }
}

// What gets signed: "${timestampMs}.${rawBody}" — binds time AND content
function webhookSigningPayload(timestampMs: number, body: string): string {
  return `${timestampMs}.${body}`
}

export interface WebhookSignOptions {
  privateKey: string  // Ed25519 PKCS8 base64url
  ttlMs?: number      // default 5 min
}

export interface WebhookSignHmacOptions {
  secret: string
  ttlMs?: number
}

export interface WebhookVerifyOptions {
  publicKey: string   // Ed25519 SPKI base64url
  maxAgeMs?: number   // default 5 min
  /** Optional — rejects a signature that's already been consumed within its TTL window. */
  replayCache?: WebhookReplayCache
}

export interface WebhookVerifyHmacOptions {
  secret: string
  maxAgeMs?: number
  /** Optional — rejects a signature that's already been consumed within its TTL window. */
  replayCache?: WebhookReplayCache
}

export interface WebhookHeaders {
  [WEBHOOK_SIG_HEADER]: string
  [WEBHOOK_TS_HEADER]: string
}

// Sign a webhook payload with Ed25519
export async function signWebhook(
  payload: string | Uint8Array,
  opts: WebhookSignOptions
): Promise<WebhookHeaders> {
  const body = typeof payload === 'string' ? payload : new TextDecoder().decode(payload)
  const timestampMs = Date.now()
  const signingPayload = webhookSigningPayload(timestampMs, body)
  const sig = await signCanonicalPayloadEd25519(signingPayload, opts.privateKey)
  return { [WEBHOOK_SIG_HEADER]: sig, [WEBHOOK_TS_HEADER]: String(timestampMs) }
}

// Sign with HMAC shared secret
export async function signWebhookHmac(
  payload: string | Uint8Array,
  opts: WebhookSignHmacOptions
): Promise<WebhookHeaders> {
  const body = typeof payload === 'string' ? payload : new TextDecoder().decode(payload)
  const timestampMs = Date.now()
  const signingPayload = webhookSigningPayload(timestampMs, body)
  const sig = await signCanonicalPayloadHmac(signingPayload, opts.secret)
  return { [WEBHOOK_SIG_HEADER]: sig, [WEBHOOK_TS_HEADER]: String(timestampMs) }
}

// Verify Ed25519 webhook signature
export async function verifyWebhook(
  payload: string | Uint8Array,
  headers: WebhookHeaders | Record<string, string>,
  opts: WebhookVerifyOptions
): Promise<boolean> {
  const body = typeof payload === 'string' ? payload : new TextDecoder().decode(payload)
  const sig = headers[WEBHOOK_SIG_HEADER]
  const tsStr = headers[WEBHOOK_TS_HEADER]
  if (!sig || !tsStr) return false
  const ts = Number(tsStr)
  if (!Number.isFinite(ts)) return false
  const maxAge = opts.maxAgeMs ?? WEBHOOK_DEFAULT_TTL_MS
  const nowMs = Date.now()
  if (nowMs - ts > maxAge) return false
  const signingPayload = webhookSigningPayload(ts, body)
  const valid = await verifyCanonicalPayloadEd25519(signingPayload, sig, opts.publicKey)
  if (!valid) return false
  if (opts.replayCache) {
    const reserved = await opts.replayCache.consume(sig, ts + maxAge, nowMs)
    if (!reserved) return false
  }
  return true
}

// Verify HMAC webhook signature
export async function verifyWebhookHmac(
  payload: string | Uint8Array,
  headers: WebhookHeaders | Record<string, string>,
  opts: WebhookVerifyHmacOptions
): Promise<boolean> {
  const body = typeof payload === 'string' ? payload : new TextDecoder().decode(payload)
  const sig = headers[WEBHOOK_SIG_HEADER]
  const tsStr = headers[WEBHOOK_TS_HEADER]
  if (!sig || !tsStr) return false
  const ts = Number(tsStr)
  if (!Number.isFinite(ts)) return false
  const maxAge = opts.maxAgeMs ?? WEBHOOK_DEFAULT_TTL_MS
  const nowMs = Date.now()
  if (nowMs - ts > maxAge) return false
  const signingPayload = webhookSigningPayload(ts, body)
  const valid = await verifyCanonicalPayloadHmac(signingPayload, sig, opts.secret)
  if (!valid) return false
  if (opts.replayCache) {
    const reserved = await opts.replayCache.consume(sig, ts + maxAge, nowMs)
    if (!reserved) return false
  }
  return true
}

// Parse and verify in one call, throws on failure
export async function consumeWebhook<T = unknown>(
  payload: string,
  headers: Record<string, string>,
  opts: WebhookVerifyOptions
): Promise<T> {
  const valid = await verifyWebhook(payload, headers, opts)
  if (!valid) throw new Error('7h3: webhook signature verification failed')
  return JSON.parse(payload) as T
}

// Re-export key generation for convenience
export { generateEd25519KeypairBase64Url }
