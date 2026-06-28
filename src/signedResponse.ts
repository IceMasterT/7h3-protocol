import {
  createEnvelope,
  signEnvelopeEd25519,
  verifyEnvelopeEd25519,
  type ProtocolEnvelope,
} from './protocol'

export const RESPONSE_HEADER = 'x-7h3-response'

export async function signResponse(
  body: string,
  opts: {
    privateKey: string
    sender: string
    recipient?: string
    correlationId?: string
    ttlMs?: number
  },
): Promise<{ headers: { 'x-7h3-response': string } }> {
  const envelope = createEnvelope({
    sender: opts.sender,
    recipient: opts.recipient,
    intent: 'RESULT',
    content: body,
    correlationId: opts.correlationId,
    ttlMs: opts.ttlMs ?? 60_000,
  })

  const signed = await signEnvelopeEd25519(envelope, opts.privateKey)

  return {
    headers: {
      [RESPONSE_HEADER]: JSON.stringify(signed),
    },
  }
}

export async function verifyResponse(
  body: string,
  headers: Record<string, string | string[] | undefined>,
  opts: {
    publicKey: string
    maxAgeMs?: number
  },
): Promise<{ ok: boolean; envelope?: ProtocolEnvelope; reason?: string }> {
  const raw = headers[RESPONSE_HEADER]
  const rawStr = Array.isArray(raw) ? raw[0] : raw
  if (!rawStr) {
    return { ok: false, reason: 'missing-header' }
  }

  let envelope: ProtocolEnvelope
  try {
    envelope = JSON.parse(rawStr) as ProtocolEnvelope
  } catch {
    return { ok: false, reason: 'malformed-envelope' }
  }

  // Check TTL from envelope
  const nowMs = Date.now()
  const { timestampMs, ttlMs } = envelope.header
  if (timestampMs + ttlMs < nowMs) {
    return { ok: false, reason: 'ttl-expired', envelope }
  }

  // Check maxAgeMs if provided
  if (opts.maxAgeMs !== undefined && nowMs - timestampMs > opts.maxAgeMs) {
    return { ok: false, reason: 'ttl-expired', envelope }
  }

  // Verify signature
  const valid = await verifyEnvelopeEd25519(envelope, opts.publicKey)
  if (!valid) {
    return { ok: false, reason: 'invalid-signature', envelope }
  }

  // Verify body matches envelope content
  if (envelope.body.content !== body) {
    return { ok: false, reason: 'content-mismatch', envelope }
  }

  return { ok: true, envelope }
}
