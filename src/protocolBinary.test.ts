import { describe, expect, it } from 'vitest'
import { createEnvelope, signEnvelopeEd25519, signEnvelopeHmac } from './protocol'
import { DEFAULT_MAX_BINARY_ENVELOPE_BYTES, decodeEnvelopeBinary, encodeEnvelopeBinary } from './protocolBinary'

function stringFieldOffset(raw: Uint8Array, fieldIndex: number): { lengthOffset: number; valueOffset: number; length: number } {
  let offset = 4 + 1 + 1 + 8 + 4
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength)
  for (let index = 0; index <= fieldIndex; index += 1) {
    const lengthOffset = offset
    const length = view.getUint32(lengthOffset, false)
    const valueOffset = lengthOffset + 4
    if (index === fieldIndex) return { lengthOffset, valueOffset, length }
    offset = valueOffset + length
  }
  throw new Error(`missing string field ${fieldIndex}`)
}

function replaceAscii(raw: Uint8Array, fieldIndex: number, value: string): Uint8Array {
  const copy = raw.slice()
  const field = stringFieldOffset(copy, fieldIndex)
  if (value.length !== field.length) throw new Error('replacement must preserve encoded length')
  for (let index = 0; index < value.length; index += 1) {
    copy[field.valueOffset + index] = value.charCodeAt(index)
  }
  return copy
}

describe('AIP binary wire codec', () => {
  it('roundtrips HS256 signed envelope', async () => {
    const signed = await signEnvelopeHmac(
      createEnvelope({
        sender: 'agent.alpha',
        recipient: 'agent.beta',
        intent: 'TASK',
        content: 'route:binary',
        capability: 'task.plan',
        correlationId: 'corr-b1',
        messageId: 'bin-1',
        nonce: 'nb1',
        nowMs: 1000,
        ttlMs: 60_000,
      }),
      'shared-secret',
      'k1',
    )

    const raw = encodeEnvelopeBinary(signed)
    const decoded = decodeEnvelopeBinary(raw)
    expect(decoded.ok).toBe(true)
    expect(decoded.envelope).toEqual(signed)
  })

  it('roundtrips ED25519 signed envelope', async () => {
    const privateKey = 'MC4CAQAwBQYDK2VwBCIEICheZbQGuDVb6hezIlcs0QnCHGxz6IhiLkC9M0qr8OOZ'
    const signed = await signEnvelopeEd25519(
      createEnvelope({
        sender: 'agent.ed',
        recipient: 'agent.verify',
        intent: 'TASK',
        content: 'route:ed25519-binary',
        capability: 'task.sign',
        correlationId: 'corr-ed-b1',
        messageId: 'bin-ed-1',
        nonce: 'n-ed-b1',
        nowMs: 1000,
        ttlMs: 45_000,
      }),
      privateKey,
      'ed-k1',
    )

    const raw = encodeEnvelopeBinary(signed)
    const decoded = decodeEnvelopeBinary(raw)
    expect(decoded.ok).toBe(true)
    expect(decoded.envelope).toEqual(signed)
  })

  it('rejects bad magic and trailing bytes', async () => {
    const signed = await signEnvelopeHmac(
      createEnvelope({
        sender: 'agent.alpha',
        intent: 'PING',
        content: 'x',
        messageId: 'bin-2',
        nonce: 'nb2',
        nowMs: 1000,
        ttlMs: 60_000,
      }),
      'shared-secret',
      'k1',
    )

    const raw = encodeEnvelopeBinary(signed)
    const badMagic = raw.slice()
    badMagic[0] = 0
    const decodedMagic = decodeEnvelopeBinary(badMagic)
    expect(decodedMagic.ok).toBe(false)
    expect(decodedMagic.diagnostics.some((d) => d.message.includes('magic'))).toBe(true)

    const trailing = new Uint8Array(raw.byteLength + 1)
    trailing.set(raw)
    trailing[raw.byteLength] = 1
    const decodedTrailing = decodeEnvelopeBinary(trailing)
    expect(decodedTrailing.ok).toBe(false)
    expect(decodedTrailing.diagnostics.some((d) => d.message.includes('Trailing bytes'))).toBe(true)
  })

  it('rejects oversized binary frames before parsing', () => {
    const oversized = new Uint8Array(DEFAULT_MAX_BINARY_ENVELOPE_BYTES + 1)
    const decoded = decodeEnvelopeBinary(oversized)

    expect(decoded.ok).toBe(false)
    expect(decoded.diagnostics.some((d) => d.message.includes('maximum frame size'))).toBe(true)
  })

  it('rejects malformed string lengths', async () => {
    const signed = await signEnvelopeHmac(
      createEnvelope({
        sender: 'agent.alpha',
        intent: 'PING',
        content: 'x',
        messageId: 'bin-malformed-length',
        nonce: 'nb-malformed-length',
        nowMs: 1000,
        ttlMs: 60_000,
      }),
      'shared-secret',
      'k1',
    )

    const raw = encodeEnvelopeBinary(signed)
    const malformed = raw.slice()
    const version = stringFieldOffset(malformed, 0)
    new DataView(malformed.buffer, malformed.byteOffset, malformed.byteLength).setUint32(version.lengthOffset, raw.byteLength, false)

    const decoded = decodeEnvelopeBinary(malformed)
    expect(decoded.ok).toBe(false)
    expect(decoded.diagnostics.some((d) => d.message.includes('Unexpected end'))).toBe(true)
  })

  it('rejects unsupported decoded protocol fields', async () => {
    const signed = await signEnvelopeHmac(
      createEnvelope({
        sender: 'agent.alpha',
        intent: 'TASK',
        content: 'x',
        messageId: 'bin-invalid-fields',
        nonce: 'nb-invalid-fields',
        nowMs: 1000,
        ttlMs: 60_000,
      }),
      'shared-secret',
      'k1',
    )

    const raw = encodeEnvelopeBinary(signed)
    const badVersion = decodeEnvelopeBinary(replaceAscii(raw, 0, 'aip/0.2'))
    const badIntent = decodeEnvelopeBinary(replaceAscii(raw, 4, 'NOPE'))

    expect(badVersion.ok).toBe(false)
    expect(badVersion.diagnostics.some((d) => d.message.includes('Unsupported protocol version'))).toBe(true)
    expect(badIntent.ok).toBe(false)
    expect(badIntent.diagnostics.some((d) => d.message.includes('Unsupported intent'))).toBe(true)
  })
})
