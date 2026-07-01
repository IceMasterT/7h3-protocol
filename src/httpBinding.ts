import {
  type ProtocolEnvelope,
  type ProtocolDiagnostic,
  verifyEnvelopeEd25519,
  verifyEnvelopeHmac,
  signEnvelopeEd25519,
  signEnvelopeHmac,
  createEnvelope,
  validateEnvelope,
} from './protocol'
import type { KeyRegistry } from './keyRegistry'
import { encodeEnvelopeCbor, decodeEnvelopeCbor, CBOR_CONTENT_TYPE as _CBOR_CONTENT_TYPE } from './envelopeCbor'

export { _CBOR_CONTENT_TYPE as CBOR_CONTENT_TYPE }

export { type KeyRegistry }

export const DEFAULT_HEADER = 'x-7h3-envelope'

export type VerifyFailReason =
  | 'missing-header'
  | 'malformed-envelope'
  | 'unknown-sender'
  | 'invalid-signature'
  | 'ttl-expired'
  | 'validation-error'

export type VerifyHttpResult =
  | { ok: true; envelope: ProtocolEnvelope }
  | { ok: false; reason: VerifyFailReason; detail?: string }

export interface HttpBindingOptions {
  keyRegistry: KeyRegistry
  headerName?: string
  strictTtl?: boolean   // default true - reject expired TTL
}

// Verify the 7h3 envelope from an incoming HTTP request's headers or body
// If content-type includes '7h3-cbor', decodes body as CBOR instead of JSON
export async function verifyHttpEnvelope(
  headers: Record<string, string | string[] | undefined>,
  opts: HttpBindingOptions,
  body?: Uint8Array
): Promise<VerifyHttpResult> {
  const headerName = opts.headerName ?? DEFAULT_HEADER
  const contentType = (Array.isArray(headers['content-type']) ? headers['content-type'][0] : headers['content-type']) ?? ''

  let envelope: ProtocolEnvelope

  // CBOR mode: content-type contains '7h3-cbor' and body is provided
  if (contentType.includes('7h3-cbor') && body instanceof Uint8Array) {
    try {
      envelope = decodeEnvelopeCbor(body)
    } catch (e: unknown) {
      return { ok: false, reason: 'malformed-envelope', detail: e instanceof Error ? e.message : 'CBOR decode failed' }
    }
  } else {
    // JSON mode: read from header
    const raw = headers[headerName]
    const rawStr = Array.isArray(raw) ? raw[0] : raw
    if (!rawStr) return { ok: false, reason: 'missing-header' }

    try {
      envelope = JSON.parse(rawStr) as ProtocolEnvelope
    } catch {
      return { ok: false, reason: 'malformed-envelope', detail: 'JSON parse failed' }
    }
  }

  if (!envelope?.signature || !envelope?.header) {
    return { ok: false, reason: 'malformed-envelope', detail: 'missing required fields' }
  }

  const strictTtl = opts.strictTtl ?? true
  if (strictTtl) {
    const diags: ProtocolDiagnostic[] = validateEnvelope(envelope)
    const errors = diags.filter(d => d.level === 'error')
    if (errors.length > 0) {
      return { ok: false, reason: 'ttl-expired', detail: errors.map(e => e.message).join('; ') }
    }
  }

  const sender = envelope.header.sender
  const alg = envelope.signature.alg

  if (alg === 'ED25519') {
    const publicKey = await opts.keyRegistry.getPublicKey(sender)
    if (!publicKey) return { ok: false, reason: 'unknown-sender', detail: sender }
    const valid = await verifyEnvelopeEd25519(envelope, publicKey)
    if (!valid) return { ok: false, reason: 'invalid-signature' }
  } else if (alg === 'HS256') {
    const secret = await opts.keyRegistry.getSharedSecret?.(envelope.signature.keyId)
    if (!secret) return { ok: false, reason: 'unknown-sender', detail: envelope.signature.keyId }
    const valid = await verifyEnvelopeHmac(envelope, secret)
    if (!valid) return { ok: false, reason: 'invalid-signature' }
  } else {
    return { ok: false, reason: 'malformed-envelope', detail: `unsupported alg: ${String((envelope.signature as any).alg)}` }
  }

  return { ok: true, envelope }
}

// Sign an outgoing HTTP request — returns headers to merge in
// When format is 'cbor', returns binary body + content-type header instead of JSON header
export async function signHttpRequest(
  envelope: Omit<ProtocolEnvelope, 'signature'>,
  privateKey: string,
  opts?: { headerName?: string; format?: 'cbor' | 'json' }
): Promise<{ headers: Record<string, string>; body?: Uint8Array }> {
  const signed = await signEnvelopeEd25519(envelope, privateKey)
  if (opts?.format === 'cbor') {
    const body = encodeEnvelopeCbor(signed)
    return {
      headers: { 'content-type': _CBOR_CONTENT_TYPE },
      body,
    }
  }
  return {
    headers: { [opts?.headerName ?? DEFAULT_HEADER]: JSON.stringify(signed) },
  }
}

// Sign with HMAC shared secret
export async function signHttpRequestHmac(
  envelope: Omit<ProtocolEnvelope, 'signature'>,
  secret: string,
  keyId: string,
  opts?: { headerName?: string }
): Promise<{ headers: Record<string, string> }> {
  const signed = await signEnvelopeHmac(envelope, secret, keyId)
  return {
    headers: { [opts?.headerName ?? DEFAULT_HEADER]: JSON.stringify(signed) },
  }
}

// Express/Fastify/Hono-compatible middleware factory (fail-closed)
export function createHttpMiddleware(opts: HttpBindingOptions) {
  return async function protocol7h3Middleware(
    req: { headers: Record<string, string | string[] | undefined> },
    res: { status: (n: number) => { json: (b: unknown) => void } },
    next: (err?: unknown) => void,
  ): Promise<void> {
    const result = await verifyHttpEnvelope(req.headers, opts)
    if (!result.ok) {
      res.status(401).json({
        error: '7h3: request verification failed',
        reason: result.reason,
        detail: result.detail,
      })
      return
    }
    ;(req as any)['7h3Envelope'] = result.envelope
    next()
  }
}

// Fetch API: sign a Request and return a new Request with the envelope header
export async function signFetchRequest(
  request: Request,
  envelope: Omit<ProtocolEnvelope, 'signature'>,
  privateKey: string,
  opts?: { headerName?: string }
): Promise<Request> {
  const { headers } = await signHttpRequest(envelope, privateKey, opts)
  const newHeaders = new Headers(request.headers)
  for (const [k, v] of Object.entries(headers)) newHeaders.set(k, v)
  return new Request(request, { headers: newHeaders })
}

// Convenience: build an envelope and sign a Fetch request in one call
export async function createSignedFetchRequest(
  request: Request,
  opts: {
    privateKey: string
    sender: string
    recipient?: string
    ttlMs?: number
    headerName?: string
  }
): Promise<Request> {
  const envelope = createEnvelope({
    sender: opts.sender,
    recipient: opts.recipient,
    ttlMs: opts.ttlMs ?? 60_000,
    intent: 'TASK',
    content: request.url,
  })
  return signFetchRequest(request, envelope, opts.privateKey, { headerName: opts.headerName })
}
