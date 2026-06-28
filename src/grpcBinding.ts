import {
  signEnvelopeEd25519, signEnvelopeHmac,
  verifyEnvelopeEd25519, verifyEnvelopeHmac,
  createEnvelope, validateEnvelope,
  type ProtocolEnvelope,
} from './protocol'
import type { KeyRegistry } from './keyRegistry'

export { type KeyRegistry }

export const GRPC_METADATA_KEY = '7h3-envelope-bin'  // -bin suffix = binary safe in gRPC

export interface GrpcSignOptions {
  privateKey: string
  sender: string
  recipient?: string
  ttlMs?: number
  metadataKey?: string
}

export interface GrpcVerifyOptions {
  keyRegistry: KeyRegistry
  metadataKey?: string
  strictTtl?: boolean
}

export type GrpcVerifyResult =
  | { ok: true; envelope: ProtocolEnvelope }
  | { ok: false; code: number; message: string }  // code = gRPC status code

// Client side: produce metadata to attach to outbound call
export async function signGrpcCall(
  opts: GrpcSignOptions
): Promise<Record<string, string>> {
  const envelope = createEnvelope({
    sender: opts.sender,
    recipient: opts.recipient,
    ttlMs: opts.ttlMs ?? 60_000,
    intent: 'TASK',
    content: 'grpc-call',
  })
  const signed = await signEnvelopeEd25519(envelope, opts.privateKey)
  return { [opts.metadataKey ?? GRPC_METADATA_KEY]: JSON.stringify(signed) }
}

// Server side: verify metadata from incoming call
export async function verifyGrpcCall(
  metadata: Record<string, string | Buffer | string[]>,
  opts: GrpcVerifyOptions
): Promise<GrpcVerifyResult> {
  const key = opts.metadataKey ?? GRPC_METADATA_KEY
  const raw = metadata[key]
  const rawStr = Array.isArray(raw) ? raw[0] : (Buffer.isBuffer(raw) ? raw.toString('utf8') : raw)
  if (!rawStr) return { ok: false, code: 16, message: '7h3: missing gRPC envelope metadata' }

  let envelope: ProtocolEnvelope
  try { envelope = JSON.parse(typeof rawStr === 'string' ? rawStr : rawStr.toString()) as ProtocolEnvelope }
  catch { return { ok: false, code: 3, message: '7h3: malformed envelope metadata' } }

  if (opts.strictTtl !== false) {
    const diags = validateEnvelope(envelope)
    if (diags.some(d => d.level === 'error')) {
      return { ok: false, code: 4, message: '7h3: envelope expired or invalid' }
    }
  }

  const sender = envelope.header?.sender
  const alg = envelope.signature?.alg
  if (!sender || !alg) return { ok: false, code: 3, message: '7h3: missing sender or alg' }

  if (alg === 'ED25519') {
    const publicKey = await opts.keyRegistry.getPublicKey(sender)
    if (!publicKey) return { ok: false, code: 16, message: `7h3: unknown sender ${sender}` }
    const valid = await verifyEnvelopeEd25519(envelope, publicKey)
    if (!valid) return { ok: false, code: 16, message: '7h3: invalid signature' }
  } else if (alg === 'HS256') {
    const secret = await opts.keyRegistry.getSharedSecret?.(envelope.signature.keyId)
    if (!secret) return { ok: false, code: 16, message: '7h3: unknown key' }
    const valid = await verifyEnvelopeHmac(envelope, secret)
    if (!valid) return { ok: false, code: 16, message: '7h3: invalid signature' }
  } else {
    return { ok: false, code: 3, message: `7h3: unsupported alg ${String(alg)}` }
  }

  return { ok: true, envelope }
}

// Factory: creates a function that wraps any async gRPC handler with verify logic
// Usage: const handler = withGrpcVerification(myHandler, verifyOpts)
export function withGrpcVerification<TCall extends { metadata: Record<string, string | Buffer | string[]> }, TResp>(
  handler: (call: TCall) => Promise<TResp>,
  opts: GrpcVerifyOptions
): (call: TCall) => Promise<TResp> {
  return async (call: TCall) => {
    const result = await verifyGrpcCall(call.metadata, opts)
    if (!result.ok) {
      const err = Object.assign(new Error(result.message), { code: result.code })
      throw err
    }
    ;(call as any)['7h3Envelope'] = result.envelope
    return handler(call)
  }
}
