import type { ProtocolEnvelope, ProtocolSignature } from './protocol'
import type { ReceiveEnvelopeResult } from './protocolTransport'

const MAGIC = [0x41, 0x49, 0x50, 0x42] as const // AIPB
const MAGIC_BYTES = Uint8Array.from(MAGIC)
const FORMAT_VERSION = 1
export const DEFAULT_MAX_BINARY_ENVELOPE_BYTES = 1024 * 1024

const FLAG_RECIPIENT = 1 << 0
const FLAG_CAPABILITY = 1 << 1
const FLAG_CORRELATION = 1 << 2
const FLAG_SIGNATURE = 1 << 3
const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()
const INTENT_KINDS = new Set(['PING', 'PONG', 'CAPS', 'TASK', 'RESULT', 'ERROR'])

export interface BinaryDecodeOptions {
  maxFrameBytes?: number
}

function utf8Encode(value: string): Uint8Array {
  return textEncoder.encode(value)
}

function utf8Decode(value: Uint8Array): string {
  return textDecoder.decode(value)
}

function signatureAlgCode(alg: ProtocolSignature['alg']): number {
  return alg === 'ED25519' ? 2 : 1
}

function signatureAlgFromCode(code: number): ProtocolSignature['alg'] | null {
  if (code === 1) return 'HS256'
  if (code === 2) return 'ED25519'
  return null
}

interface EncodedString {
  bytes: Uint8Array
}

function encodeString(value: string): EncodedString {
  return { bytes: utf8Encode(value) }
}

function encodedStringSize(encoded: EncodedString | null): number {
  return encoded ? 4 + encoded.bytes.byteLength : 0
}

class BinaryWriter {
  private readonly bytes: Uint8Array

  private readonly view: DataView

  private offset = 0

  constructor(size: number) {
    this.bytes = new Uint8Array(size)
    this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength)
  }

  writeU8(value: number): void {
    this.bytes[this.offset] = value & 0xff
    this.offset += 1
  }

  writeU32(value: number): void {
    this.view.setUint32(this.offset, value, false)
    this.offset += 4
  }

  writeU64(value: number): void {
    this.view.setBigUint64(this.offset, BigInt(value), false)
    this.offset += 8
  }

  writeBytes(value: Uint8Array): void {
    this.bytes.set(value, this.offset)
    this.offset += value.byteLength
  }

  writeString(encoded: EncodedString): void {
    this.writeU32(encoded.bytes.byteLength)
    this.writeBytes(encoded.bytes)
  }

  finish(): Uint8Array {
    return this.bytes
  }
}

class BinaryReader {
  private readonly bytes: Uint8Array

  private offset = 0

  constructor(bytes: Uint8Array) {
    this.bytes = bytes
  }

  remaining(): number {
    return this.bytes.byteLength - this.offset
  }

  readU8(): number {
    if (this.remaining() < 1) throw new Error('Unexpected end of binary envelope')
    const value = this.bytes[this.offset]
    this.offset += 1
    return value ?? 0
  }

  readU32(): number {
    if (this.remaining() < 4) throw new Error('Unexpected end of binary envelope')
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 4).getUint32(0, false)
    this.offset += 4
    return value
  }

  readU64(): number {
    if (this.remaining() < 8) throw new Error('Unexpected end of binary envelope')
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 8).getBigUint64(0, false)
    this.offset += 8
    return Number(value)
  }

  readBytes(length: number): Uint8Array {
    if (length < 0 || this.remaining() < length) throw new Error('Unexpected end of binary envelope')
    const value = this.bytes.slice(this.offset, this.offset + length)
    this.offset += length
    return value
  }

  readString(): string {
    const length = this.readU32()
    const value = this.readBytes(length)
    return utf8Decode(value)
  }
}

export function encodeEnvelopeBinary(envelope: ProtocolEnvelope): Uint8Array {
  const flags =
    (envelope.header.recipient ? FLAG_RECIPIENT : 0) |
    (envelope.body.capability ? FLAG_CAPABILITY : 0) |
    (envelope.body.correlationId ? FLAG_CORRELATION : 0) |
    (envelope.signature ? FLAG_SIGNATURE : 0)

  const version = encodeString(envelope.header.version)
  const messageId = encodeString(envelope.header.messageId)
  const sender = encodeString(envelope.header.sender)
  const nonce = encodeString(envelope.header.nonce)
  const intent = encodeString(envelope.body.intent)
  const content = encodeString(envelope.body.content)
  const recipient = envelope.header.recipient ? encodeString(envelope.header.recipient) : null
  const capability = envelope.body.capability ? encodeString(envelope.body.capability) : null
  const correlationId = envelope.body.correlationId ? encodeString(envelope.body.correlationId) : null
  const signatureKeyId = envelope.signature ? encodeString(envelope.signature.keyId) : null
  const signatureValue = envelope.signature ? encodeString(envelope.signature.value) : null

  const size =
    MAGIC_BYTES.byteLength +
    1 +
    1 +
    8 +
    4 +
    encodedStringSize(version) +
    encodedStringSize(messageId) +
    encodedStringSize(sender) +
    encodedStringSize(nonce) +
    encodedStringSize(intent) +
    encodedStringSize(content) +
    encodedStringSize(recipient) +
    encodedStringSize(capability) +
    encodedStringSize(correlationId) +
    (envelope.signature ? 1 : 0) +
    encodedStringSize(signatureKeyId) +
    encodedStringSize(signatureValue)

  const writer = new BinaryWriter(size)
  writer.writeBytes(MAGIC_BYTES)
  writer.writeU8(FORMAT_VERSION)
  writer.writeU8(flags)
  writer.writeU64(envelope.header.timestampMs)
  writer.writeU32(envelope.header.ttlMs)

  writer.writeString(version)
  writer.writeString(messageId)
  writer.writeString(sender)
  writer.writeString(nonce)
  writer.writeString(intent)
  writer.writeString(content)

  if (recipient) writer.writeString(recipient)
  if (capability) writer.writeString(capability)
  if (correlationId) writer.writeString(correlationId)

  if (envelope.signature && signatureKeyId && signatureValue) {
    writer.writeU8(signatureAlgCode(envelope.signature.alg))
    writer.writeString(signatureKeyId)
    writer.writeString(signatureValue)
  }

  return writer.finish()
}

export function decodeEnvelopeBinary(payload: Uint8Array, options: BinaryDecodeOptions = {}): ReceiveEnvelopeResult {
  try {
    const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_BINARY_ENVELOPE_BYTES
    if (payload.byteLength > maxFrameBytes) {
      return {
        ok: false,
        diagnostics: [{ level: 'error', message: `Binary envelope exceeds maximum frame size '${maxFrameBytes}'` }],
        envelope: null,
      }
    }

    const reader = new BinaryReader(payload)
    const magic = [reader.readU8(), reader.readU8(), reader.readU8(), reader.readU8()]
    if (magic.some((value, idx) => value !== MAGIC[idx])) {
      return {
        ok: false,
        diagnostics: [{ level: 'error', message: 'Invalid binary envelope magic' }],
        envelope: null,
      }
    }

    const version = reader.readU8()
    if (version !== FORMAT_VERSION) {
      return {
        ok: false,
        diagnostics: [{ level: 'error', message: `Unsupported binary envelope version '${version}'` }],
        envelope: null,
      }
    }

    const flags = reader.readU8()
    const timestampMs = reader.readU64()
    const ttlMs = reader.readU32()

    const envelope: ProtocolEnvelope = {
      header: {
        version: reader.readString() as 'aip/0.1',
        messageId: reader.readString(),
        timestampMs,
        ttlMs,
        sender: reader.readString(),
        nonce: reader.readString(),
      },
      body: {
        intent: reader.readString() as ProtocolEnvelope['body']['intent'],
        content: reader.readString(),
      },
    }

    if (envelope.header.version !== 'aip/0.1') {
      return {
        ok: false,
        diagnostics: [{ level: 'error', message: `Unsupported protocol version '${envelope.header.version}'` }],
        envelope: null,
      }
    }

    if (!INTENT_KINDS.has(envelope.body.intent)) {
      return {
        ok: false,
        diagnostics: [{ level: 'error', message: `Unsupported intent '${envelope.body.intent}'` }],
        envelope: null,
      }
    }

    if (flags & FLAG_RECIPIENT) envelope.header.recipient = reader.readString()
    if (flags & FLAG_CAPABILITY) envelope.body.capability = reader.readString()
    if (flags & FLAG_CORRELATION) envelope.body.correlationId = reader.readString()

    if (flags & FLAG_SIGNATURE) {
      const algCode = reader.readU8()
      const alg = signatureAlgFromCode(algCode)
      if (!alg) {
        return {
          ok: false,
          diagnostics: [{ level: 'error', message: `Unsupported binary signature algorithm '${algCode}'` }],
          envelope: null,
        }
      }
      envelope.signature = {
        alg,
        keyId: reader.readString(),
        value: reader.readString(),
      }
    }

    if (reader.remaining() !== 0) {
      return {
        ok: false,
        diagnostics: [{ level: 'error', message: 'Trailing bytes found in binary envelope' }],
        envelope: null,
      }
    }

    return {
      ok: true,
      diagnostics: [],
      envelope,
    }
  } catch (error: unknown) {
    return {
      ok: false,
      diagnostics: [{ level: 'error', message: error instanceof Error ? error.message : 'Invalid binary envelope' }],
      envelope: null,
    }
  }
}
