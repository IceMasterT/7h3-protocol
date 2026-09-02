// 7h3 Protocol - Browser/Edge SDK
// Pure Web Crypto API. Zero dependencies.
// Works in browsers, Deno, Cloudflare Workers, Bun, and Node 20+.

export const WIRE_VERSION = '7h3/0.1'
export const ENVELOPE_HEADER = 'x-7h3-envelope'
export const RESPONSE_HEADER = 'x-7h3-response'

export type IntentKind = 'PING' | 'PONG' | 'CAPS' | 'TASK' | 'RESULT' | 'ERROR'

export interface BrowserEnvelopeHeader {
  version: typeof WIRE_VERSION
  messageId: string
  timestampMs: number
  ttlMs: number
  sender: string
  recipient?: string
  nonce: string
}

export interface BrowserEnvelopeBody {
  intent: IntentKind
  content: string
  capability?: string
  correlationId?: string
}

export interface BrowserSignature {
  alg: 'ED25519'
  keyId: string
  value: string
}

export interface BrowserEnvelope {
  header: BrowserEnvelopeHeader
  body: BrowserEnvelopeBody
  signature?: BrowserSignature
}

export interface BrowserKeyPair {
  publicKey: string  // base64url SPKI, no padding
  privateKey: string // base64url PKCS8, no padding
}

// ─── Internal helpers (NOT exported) ─────────────────────────────────────────

function toBase64Url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function fromBase64Url(str: string): Uint8Array {
  const padded = str
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(str.length / 4) * 4, '=')
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function generateNonce(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return toBase64Url(bytes)
}

function canonicalBody(b: BrowserEnvelopeBody): string {
  const parts: string[] = []
  if (b.capability !== undefined) {
    parts.push(`"capability":${JSON.stringify(b.capability)}`)
  }
  parts.push(`"content":${JSON.stringify(b.content)}`)
  if (b.correlationId !== undefined) {
    parts.push(`"correlationId":${JSON.stringify(b.correlationId)}`)
  }
  parts.push(`"intent":${JSON.stringify(b.intent)}`)
  return `{${parts.join(',')}}`
}

function canonicalHeader(h: BrowserEnvelopeHeader): string {
  const parts: string[] = [
    `"messageId":${JSON.stringify(h.messageId)}`,
    `"nonce":${JSON.stringify(h.nonce)}`,
  ]
  if (h.recipient !== undefined) {
    parts.push(`"recipient":${JSON.stringify(h.recipient)}`)
  }
  parts.push(`"sender":${JSON.stringify(h.sender)}`)
  parts.push(`"timestampMs":${h.timestampMs}`)
  parts.push(`"ttlMs":${h.ttlMs}`)
  parts.push(`"version":${JSON.stringify(h.version)}`)
  return `{${parts.join(',')}}`
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function canonicalizeEnvelope(envelope: Omit<BrowserEnvelope, 'signature'>): string {
  return `{"body":${canonicalBody(envelope.body)},"header":${canonicalHeader(envelope.header)}}`
}

export async function generateKeypair(): Promise<BrowserKeyPair> {
  const pair = await crypto.subtle.generateKey(
    { name: 'Ed25519' } as AlgorithmIdentifier,
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair

  const privateKeyRaw = await crypto.subtle.exportKey('pkcs8', pair.privateKey)
  const publicKeyRaw = await crypto.subtle.exportKey('spki', pair.publicKey)

  return {
    publicKey: toBase64Url(publicKeyRaw),
    privateKey: toBase64Url(privateKeyRaw),
  }
}

export async function signEnvelope(
  envelope: Omit<BrowserEnvelope, 'signature'>,
  privateKeyPkcs8Base64Url: string,
  keyId?: string,
): Promise<BrowserEnvelope> {
  const der = fromBase64Url(privateKeyPkcs8Base64Url)
  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer,
    { name: 'Ed25519' } as AlgorithmIdentifier,
    false,
    ['sign'],
  )

  const payload = canonicalizeEnvelope(envelope)
  const sigBuffer = await crypto.subtle.sign(
    'Ed25519',
    cryptoKey,
    new TextEncoder().encode(payload),
  )

  return {
    ...envelope,
    signature: {
      alg: 'ED25519',
      keyId: keyId ?? generateNonce().slice(0, 16),
      value: toBase64Url(sigBuffer),
    },
  }
}

export async function verifyEnvelope(
  envelope: BrowserEnvelope,
  publicKeySpkiBase64Url: string,
): Promise<boolean> {
  if (!envelope.signature) return false
  if (envelope.signature.alg !== 'ED25519') return false

  const der = fromBase64Url(publicKeySpkiBase64Url)
  const cryptoKey = await crypto.subtle.importKey(
    'spki',
    der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer,
    { name: 'Ed25519' } as AlgorithmIdentifier,
    false,
    ['verify'],
  )

  const unsigned: Omit<BrowserEnvelope, 'signature'> = {
    header: envelope.header,
    body: envelope.body,
  }
  const payload = canonicalizeEnvelope(unsigned)
  const sigBytes = fromBase64Url(envelope.signature.value)

  return crypto.subtle.verify(
    'Ed25519',
    cryptoKey,
    sigBytes.buffer.slice(sigBytes.byteOffset, sigBytes.byteOffset + sigBytes.byteLength) as ArrayBuffer,
    new TextEncoder().encode(payload),
  )
}

export function createEnvelope(opts: {
  sender: string
  recipient?: string
  ttlMs?: number
  body: BrowserEnvelopeBody
}): Omit<BrowserEnvelope, 'signature'> {
  return {
    header: {
      version: WIRE_VERSION,
      messageId: generateNonce(),
      timestampMs: Date.now(),
      ttlMs: opts.ttlMs ?? 60_000,
      sender: opts.sender,
      recipient: opts.recipient,
      nonce: generateNonce(),
    },
    body: opts.body,
  }
}

export async function signRequest(
  request: Request,
  opts: {
    sender: string
    recipient?: string
    ttlMs?: number
    privateKey: string
    keyId?: string
  },
): Promise<Request> {
  const envelope = createEnvelope({
    sender: opts.sender,
    recipient: opts.recipient,
    ttlMs: opts.ttlMs,
    body: {
      intent: 'TASK',
      content: request.url,
    },
  })

  const signed = await signEnvelope(envelope, opts.privateKey, opts.keyId)

  const headers = new Headers(request.headers)
  headers.set(ENVELOPE_HEADER, JSON.stringify(signed))

  return new Request(request, { headers })
}

export async function verifyResponseHeader(
  response: Response,
  publicKey: string,
): Promise<boolean> {
  const headerValue = response.headers.get(RESPONSE_HEADER)
  if (!headerValue) return false

  let parsed: BrowserEnvelope
  try {
    parsed = JSON.parse(headerValue) as BrowserEnvelope
  } catch {
    return false
  }

  return verifyEnvelope(parsed, publicKey)
}

/**
 * Ceiling on `ttlMs`. A huge TTL keeps an envelope replayable long after any
 * replay store has forgotten its nonce.
 */
export const MAX_TTL_MS = 86_400_000 // 24 hours

/**
 * How far into the future a timestamp may sit before it is rejected.
 *
 * Without this ceiling `MAX_TTL_MS` bounds nothing: a sender can post-date
 * `timestampMs` by a year and still pass a legal 24h `ttlMs`, keeping the
 * envelope valid — and replayable — for a year.
 */
export const MAX_CLOCK_SKEW_MS = 30_000

export interface BrowserDiagnostic {
  level: 'error' | 'warning'
  message: string
}

/** A header string field, or "" when absent or not actually a string. */
function headerString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

/**
 * A finite numeric header field, or null when absent, non-numeric or non-finite.
 *
 * `typeof NaN === 'number'` is true, so a plain typeof check lets NaN and
 * ±Infinity through as if they were ordinary numbers — and every comparison
 * against NaN is false, which silently defeats the TTL ceiling, the clock-skew
 * ceiling and expiry all at once. Booleans are excluded too, so `ttlMs: true`
 * cannot be read as 1.
 */
function headerNumber(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null
  return value
}

/**
 * Validate an envelope, returning diagnostics rather than throwing.
 *
 * Deliberately byte-for-byte the same checks and messages as the TypeScript,
 * Python, Rust and Go SDKs, so a browser peer accepts exactly what they accept.
 * Pass `nowMs` to control the clock in tests.
 */
export function validateEnvelope(envelope: BrowserEnvelope, nowMs: number = Date.now()): BrowserDiagnostic[] {
  const diagnostics: BrowserDiagnostic[] = []
  const header = (envelope?.header ?? {}) as Partial<BrowserEnvelopeHeader>
  const body = (envelope?.body ?? {}) as Partial<BrowserEnvelopeBody>

  if (header.version !== WIRE_VERSION) {
    diagnostics.push({ level: 'error', message: `Unsupported protocol version '${String(header.version)}'` })
  }
  if (!headerString(header.messageId)) {
    diagnostics.push({ level: 'error', message: 'Missing messageId' })
  }
  if (!headerString(header.sender)) {
    diagnostics.push({ level: 'error', message: 'Missing sender identity' })
  }
  if (!headerString(header.nonce)) {
    diagnostics.push({
      level: 'error',
      message: 'Missing nonce — replay protection requires a unique nonce per message',
    })
  }

  const timestampMs = headerNumber(header.timestampMs)
  const ttlMs = headerNumber(header.ttlMs)

  if (timestampMs === null) {
    diagnostics.push({ level: 'error', message: 'timestampMs must be a finite number' })
  }
  if (ttlMs === null) {
    diagnostics.push({ level: 'error', message: 'ttlMs must be a finite number' })
  } else {
    if (ttlMs <= 0) {
      diagnostics.push({ level: 'error', message: 'ttlMs must be greater than zero' })
    }
    if (ttlMs > MAX_TTL_MS) {
      diagnostics.push({ level: 'error', message: `ttlMs exceeds maximum allowed ${MAX_TTL_MS} ms` })
    }
  }

  if (timestampMs !== null) {
    if (timestampMs > nowMs + MAX_CLOCK_SKEW_MS) {
      diagnostics.push({
        level: 'error',
        message: `timestampMs is more than ${MAX_CLOCK_SKEW_MS} ms in the future`,
      })
    }
    if (ttlMs !== null && timestampMs + ttlMs < nowMs) {
      diagnostics.push({ level: 'error', message: 'Message TTL expired' })
    }
  }

  if (!headerString(body.content)) {
    diagnostics.push({ level: 'warning', message: 'Empty content payload' })
  }

  return diagnostics
}

/**
 * Whether an envelope has expired.
 *
 * Fails closed on a non-finite timestamp or TTL: `NaN + NaN < now` is false, so
 * a naive arithmetic check would report such an envelope as *not* expired and
 * wave it through.
 */
export function isEnvelopeExpired(envelope: BrowserEnvelope, nowMs: number = Date.now()): boolean {
  const timestampMs = headerNumber(envelope?.header?.timestampMs)
  const ttlMs = headerNumber(envelope?.header?.ttlMs)
  if (timestampMs === null || ttlMs === null) return true
  return timestampMs + ttlMs < nowMs
}
