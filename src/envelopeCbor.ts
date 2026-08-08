/**
 * Higher-level CBOR codec for ProtocolEnvelope.
 * Uses numeric field keys for maximum compactness.
 *
 * Envelope map structure:
 *   1 → header map
 *   2 → body map
 *   3 → signature map (omitted if no signature)
 *
 * Header map:
 *   1 → version (string)
 *   2 → messageId (string)
 *   3 → timestampMs (int)
 *   4 → ttlMs (int)
 *   5 → sender (string)
 *   6 → recipient (string, omit if absent)
 *   7 → nonce (string)
 *
 * Body map:
 *   1 → intent (string)
 *   2 → content (string)
 *   3 → capability (string, omit if absent)
 *   4 → correlationId (string, omit if absent)
 *
 * Signature map:
 *   1 → alg (string)
 *   2 → keyId (string)
 *   3 → value (string — base64url signature)
 */

import type { ProtocolEnvelope, ProtocolSignature } from './protocol'
import { encodeCbor, decodeCbor } from './cborCodec'

export const CBOR_CONTENT_TYPE = 'application/7h3-cbor'

export function encodeEnvelopeCbor(env: ProtocolEnvelope): Uint8Array {
  // Build header map
  const headerMap = new Map<number, unknown>()
  headerMap.set(1, env.header.version)
  headerMap.set(2, env.header.messageId)
  headerMap.set(3, env.header.timestampMs)
  headerMap.set(4, env.header.ttlMs)
  headerMap.set(5, env.header.sender)
  if (env.header.recipient !== undefined) {
    headerMap.set(6, env.header.recipient)
  }
  headerMap.set(7, env.header.nonce)

  // Build body map
  const bodyMap = new Map<number, unknown>()
  bodyMap.set(1, env.body.intent)
  bodyMap.set(2, env.body.content)
  if (env.body.capability !== undefined) {
    bodyMap.set(3, env.body.capability)
  }
  if (env.body.correlationId !== undefined) {
    bodyMap.set(4, env.body.correlationId)
  }

  // Build top-level map
  const topMap = new Map<number, unknown>()
  topMap.set(1, headerMap)
  topMap.set(2, bodyMap)

  const sig = env.signature
  if (sig) {
    const sigMap = new Map<number, unknown>()
    sigMap.set(1, sig.alg)
    sigMap.set(2, sig.keyId)
    sigMap.set(3, sig.value)
    topMap.set(3, sigMap)
  }

  return encodeCbor(topMap)
}

// `as` casts below are compile-time only — they have zero runtime effect, so
// a malicious/malformed CBOR body could otherwise smuggle any decoded shape
// (a map, array, or non-finite float) straight into fields the rest of the
// protocol assumes are plain strings/finite numbers. That gap is exactly how
// a NaN ttlMs/timestampMs (or a non-string content/capability/correlationId)
// can defeat TTL and replay checks downstream, or diverge from what a
// strictly-typed Python/Rust peer would accept for the same bytes. These
// helpers make decoding fail loudly instead of producing a wrong-shaped
// envelope that downstream code trusts implicitly.
function expectString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new Error(`decodeEnvelopeCbor: ${field} must be a string`)
  }
  return value
}

function expectOptionalString(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined
  return expectString(value, field)
}

function expectFiniteNumber(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`decodeEnvelopeCbor: ${field} must be a finite number`)
  }
  return value
}

export function decodeEnvelopeCbor(data: Uint8Array): ProtocolEnvelope {
  const top = decodeCbor(data)

  if (!top || typeof top !== 'object' || Array.isArray(top)) {
    throw new Error('decodeEnvelopeCbor: expected a map at top level')
  }

  const topRecord = top as Record<string, unknown>

  // Header
  const headerRaw = topRecord['1']
  if (!headerRaw || typeof headerRaw !== 'object' || Array.isArray(headerRaw)) {
    throw new Error('decodeEnvelopeCbor: missing header map (key 1)')
  }
  const hr = headerRaw as Record<string, unknown>

  // Body
  const bodyRaw = topRecord['2']
  if (!bodyRaw || typeof bodyRaw !== 'object' || Array.isArray(bodyRaw)) {
    throw new Error('decodeEnvelopeCbor: missing body map (key 2)')
  }
  const br = bodyRaw as Record<string, unknown>

  const env: ProtocolEnvelope = {
    header: {
      version: expectString(hr['1'], 'header.version') as ProtocolEnvelope['header']['version'],
      messageId: expectString(hr['2'], 'header.messageId'),
      timestampMs: expectFiniteNumber(hr['3'], 'header.timestampMs'),
      ttlMs: expectFiniteNumber(hr['4'], 'header.ttlMs'),
      sender: expectString(hr['5'], 'header.sender'),
      nonce: expectString(hr['7'], 'header.nonce'),
    },
    body: {
      intent: expectString(br['1'], 'body.intent') as ProtocolEnvelope['body']['intent'],
      content: expectString(br['2'], 'body.content'),
    },
  }

  const recipient = expectOptionalString(hr['6'], 'header.recipient')
  if (recipient !== undefined) env.header.recipient = recipient

  const capability = expectOptionalString(br['3'], 'body.capability')
  if (capability !== undefined) env.body.capability = capability

  const correlationId = expectOptionalString(br['4'], 'body.correlationId')
  if (correlationId !== undefined) env.body.correlationId = correlationId

  // Signature
  const sigRaw = topRecord['3']
  if (sigRaw !== undefined && sigRaw !== null) {
    if (typeof sigRaw !== 'object' || Array.isArray(sigRaw)) {
      throw new Error('decodeEnvelopeCbor: expected signature map at key 3')
    }
    const sr = sigRaw as Record<string, unknown>
    env.signature = {
      alg: expectString(sr['1'], 'signature.alg') as ProtocolSignature['alg'],
      keyId: expectString(sr['2'], 'signature.keyId'),
      value: expectString(sr['3'], 'signature.value'),
    }
  }

  return env
}
