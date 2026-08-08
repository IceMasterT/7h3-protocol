/**
 * Minimal deterministic CBOR encoder/decoder — zero external dependencies.
 * Follows RFC 8949 §4.2 deterministic encoding:
 *   - Shortest-length integers
 *   - Map keys sorted by lexicographic byte order of encoded key
 */

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

// CBOR major types
const MT_UINT    = 0 // major type 0: unsigned int
const MT_NINT    = 1 // major type 1: negative int
const MT_BSTR    = 2 // major type 2: byte string
const MT_TSTR    = 3 // major type 3: text string
const MT_ARRAY   = 4 // major type 4: array
const MT_MAP     = 5 // major type 5: map
const MT_SIMPLE  = 7 // major type 7: simple/float

const SIMPLE_FALSE  = 0xf4
const SIMPLE_TRUE   = 0xf5
const SIMPLE_NULL   = 0xf6

// Additional info thresholds
const AI_1BYTE  = 24
const AI_2BYTE  = 25
const AI_4BYTE  = 26
const AI_8BYTE  = 27

// float64 additional info
const AI_FLOAT64 = 27

export class CborEncoder {
  private chunks: Uint8Array[] = []

  encode(value: unknown): Uint8Array {
    this.chunks = []
    this._encode(value)
    return this._concat()
  }

  private _encode(value: unknown): void {
    if (value === null || value === undefined) {
      this.chunks.push(new Uint8Array([SIMPLE_NULL]))
      return
    }
    if (typeof value === 'boolean') {
      this.chunks.push(new Uint8Array([value ? SIMPLE_TRUE : SIMPLE_FALSE]))
      return
    }
    if (typeof value === 'number') {
      this._encodeNumber(value)
      return
    }
    if (typeof value === 'string') {
      this._encodeString(value)
      return
    }
    if (value instanceof Uint8Array) {
      this._encodeByteString(value)
      return
    }
    if (Array.isArray(value)) {
      this._encodeArray(value)
      return
    }
    if (value instanceof Map) {
      // Keys can be numbers or strings
      const entries = [...value.entries()] as Array<[unknown, unknown]>
      this._encodeMapFromAnyEntries(entries)
      return
    }
    if (typeof value === 'object') {
      // Plain object: treat keys as strings
      const entries = Object.entries(value as Record<string, unknown>)
      this._encodeMapFromEntries(entries)
      return
    }
    throw new Error(`CborEncoder: unsupported type: ${typeof value}`)
  }

  private _encodeNumber(value: number): void {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      // float64
      this.chunks.push(this._float64Header())
      const buf = new ArrayBuffer(8)
      new DataView(buf).setFloat64(0, value, false)
      this.chunks.push(new Uint8Array(buf))
      return
    }
    if (value >= 0) {
      this._encodeHead(MT_UINT, value)
    } else {
      // negative: -1 - n encoded as n
      this._encodeHead(MT_NINT, -1 - value)
    }
  }

  private _float64Header(): Uint8Array {
    return new Uint8Array([(MT_SIMPLE << 5) | AI_FLOAT64])
  }

  private _encodeString(value: string): void {
    const bytes = textEncoder.encode(value)
    this._encodeHead(MT_TSTR, bytes.length)
    this.chunks.push(bytes)
  }

  private _encodeByteString(value: Uint8Array): void {
    this._encodeHead(MT_BSTR, value.length)
    this.chunks.push(value)
  }

  private _encodeArray(value: unknown[]): void {
    this._encodeHead(MT_ARRAY, value.length)
    for (const item of value) {
      this._encode(item)
    }
  }

  private _encodeMapFromAnyEntries(entries: Array<[unknown, unknown]>): void {
    // Encode each key to bytes, then sort by lexicographic byte order of encoded key
    const encoded: Array<{ keyEncoded: Uint8Array; key: unknown; value: unknown }> = entries.map(([k, v]) => {
      let keyEncoded: Uint8Array
      if (typeof k === 'number' && Number.isInteger(k)) {
        keyEncoded = this._encodeHeadBytes(MT_UINT, k)
      } else {
        const keyBytes = textEncoder.encode(String(k))
        const keyLenEncoded = this._encodeHeadBytes(MT_TSTR, keyBytes.length)
        keyEncoded = this._concatPair(keyLenEncoded, keyBytes)
      }
      return { keyEncoded, key: k, value: v }
    })

    encoded.sort((a, b) => this._compareBytes(a.keyEncoded, b.keyEncoded))

    this._encodeHead(MT_MAP, encoded.length)
    for (const { key, value } of encoded) {
      // Write key
      if (typeof key === 'number' && Number.isInteger(key)) {
        this._encodeHead(MT_UINT, key as number)
      } else {
        const keyBytes = textEncoder.encode(String(key))
        this._encodeHead(MT_TSTR, keyBytes.length)
        this.chunks.push(keyBytes)
      }
      // Write value
      this._encode(value)
    }
  }

  private _encodeMapFromEntries(entries: Array<[string, unknown]>): void {
    // Deterministic: sort keys by UTF-8 byte order of encoded key
    const encoded: Array<{ keyBytes: Uint8Array; keyEncoded: Uint8Array; value: unknown }> = entries.map(([k, v]) => {
      const keyBytes = textEncoder.encode(k)
      const keyLenEncoded = this._encodeHeadBytes(MT_TSTR, keyBytes.length)
      const keyEncoded = this._concatPair(keyLenEncoded, keyBytes)
      return { keyBytes, keyEncoded, value: v }
    })

    encoded.sort((a, b) => this._compareBytes(a.keyEncoded, b.keyEncoded))

    this._encodeHead(MT_MAP, encoded.length)
    for (const { keyBytes, value } of encoded) {
      // Write key
      this._encodeHead(MT_TSTR, keyBytes.length)
      this.chunks.push(keyBytes)
      // Write value
      this._encode(value)
    }
  }

  private _compareBytes(a: Uint8Array, b: Uint8Array): number {
    const len = Math.min(a.length, b.length)
    for (let i = 0; i < len; i++) {
      const diff = (a[i] ?? 0) - (b[i] ?? 0)
      if (diff !== 0) return diff
    }
    return a.length - b.length
  }

  private _concatPair(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length + b.length)
    result.set(a, 0)
    result.set(b, a.length)
    return result
  }

  private _encodeHead(majorType: number, value: number): void {
    this.chunks.push(this._encodeHeadBytes(majorType, value))
  }

  private _encodeHeadBytes(majorType: number, value: number): Uint8Array {
    const mt = majorType << 5
    if (value <= 23) {
      return new Uint8Array([mt | value])
    }
    if (value <= 0xff) {
      return new Uint8Array([mt | AI_1BYTE, value])
    }
    if (value <= 0xffff) {
      const buf = new ArrayBuffer(3)
      const dv = new DataView(buf)
      dv.setUint8(0, mt | AI_2BYTE)
      dv.setUint16(1, value, false)
      return new Uint8Array(buf)
    }
    if (value <= 0xffffffff) {
      const buf = new ArrayBuffer(5)
      const dv = new DataView(buf)
      dv.setUint8(0, mt | AI_4BYTE)
      dv.setUint32(1, value, false)
      return new Uint8Array(buf)
    }
    // 8-byte (for large numbers)
    const buf = new ArrayBuffer(9)
    const dv = new DataView(buf)
    dv.setUint8(0, mt | AI_8BYTE)
    dv.setBigUint64(1, BigInt(value), false)
    return new Uint8Array(buf)
  }

  private _concat(): Uint8Array {
    const total = this.chunks.reduce((sum, c) => sum + c.length, 0)
    const result = new Uint8Array(total)
    let offset = 0
    for (const chunk of this.chunks) {
      result.set(chunk, offset)
      offset += chunk.length
    }
    return result
  }
}

export class CborDecoder {
  private data!: Uint8Array
  private offset = 0

  decode(data: Uint8Array): unknown {
    this.data = data
    this.offset = 0
    const result = this._decode()
    return result
  }

  private _decode(): unknown {
    const initialByte = this._readByte()
    const majorType = (initialByte >> 5) & 0x7
    const additionalInfo = initialByte & 0x1f

    switch (majorType) {
      case MT_UINT:
        return this._decodeUint(additionalInfo)
      case MT_NINT:
        return -1 - this._decodeUint(additionalInfo)
      case MT_BSTR: {
        const len = this._decodeUint(additionalInfo)
        return this._readBytes(len)
      }
      case MT_TSTR: {
        const len = this._decodeUint(additionalInfo)
        const bytes = this._readBytes(len)
        return textDecoder.decode(bytes)
      }
      case MT_ARRAY: {
        const count = this._decodeUint(additionalInfo)
        const result: unknown[] = []
        for (let i = 0; i < count; i++) {
          result.push(this._decode())
        }
        return result
      }
      case MT_MAP: {
        const count = this._decodeUint(additionalInfo)
        // Object.create(null), not {}: a plain object literal's "__proto__"
        // key is a prototype-reassignment accessor, not a normal property —
        // `result["__proto__"] = value` would swap result's prototype
        // instead of storing a "__proto__" own property (unlike JSON.parse,
        // which is spec-guaranteed to treat "__proto__" as an ordinary key).
        // A null-prototype object has no such accessor, so every decoded key
        // — including "__proto__" — becomes a plain own data property.
        const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>
        for (let i = 0; i < count; i++) {
          const key = this._decode()
          const value = this._decode()
          result[String(key)] = value
        }
        return result
      }
      case MT_SIMPLE: {
        if (additionalInfo === 20) return false  // 0xf4
        if (additionalInfo === 21) return true   // 0xf5
        if (additionalInfo === 22) return null   // 0xf6
        if (additionalInfo === AI_FLOAT64) {
          const bytes = this._readBytes(8)
          return new DataView(bytes.buffer, bytes.byteOffset, 8).getFloat64(0, false)
        }
        throw new Error(`CborDecoder: unsupported simple value ${additionalInfo}`)
      }
      default:
        throw new Error(`CborDecoder: unsupported major type ${majorType}`)
    }
  }

  private _decodeUint(additionalInfo: number): number {
    if (additionalInfo <= 23) return additionalInfo
    if (additionalInfo === AI_1BYTE) return this._readByte()
    if (additionalInfo === AI_2BYTE) {
      const bytes = this._readBytes(2)
      return new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0, false)
    }
    if (additionalInfo === AI_4BYTE) {
      const bytes = this._readBytes(4)
      return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false)
    }
    if (additionalInfo === AI_8BYTE) {
      const bytes = this._readBytes(8)
      return Number(new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, false))
    }
    throw new Error(`CborDecoder: unsupported additional info ${additionalInfo}`)
  }

  private _readByte(): number {
    if (this.offset >= this.data.length) {
      throw new Error('CborDecoder: unexpected end of data')
    }
    return this.data[this.offset++] ?? 0
  }

  private _readBytes(count: number): Uint8Array {
    if (this.offset + count > this.data.length) {
      throw new Error('CborDecoder: unexpected end of data')
    }
    const result = this.data.slice(this.offset, this.offset + count)
    this.offset += count
    return result
  }
}

export function encodeCbor(value: unknown): Uint8Array {
  return new CborEncoder().encode(value)
}

export function decodeCbor(data: Uint8Array): unknown {
  return new CborDecoder().decode(data)
}
