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
}

export interface WebhookVerifyHmacOptions {
  secret: string
  maxAgeMs?: number
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
  if (Date.now() - ts > maxAge) return false
  const signingPayload = webhookSigningPayload(ts, body)
  return verifyCanonicalPayloadEd25519(signingPayload, sig, opts.publicKey)
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
  if (Date.now() - ts > maxAge) return false
  const signingPayload = webhookSigningPayload(ts, body)
  return verifyCanonicalPayloadHmac(signingPayload, sig, opts.secret)
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
