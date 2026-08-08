import { describe, it, expect } from 'vitest'
import { encodeCbor, decodeCbor, CborEncoder } from './cborCodec'
import { encodeEnvelopeCbor, decodeEnvelopeCbor } from './envelopeCbor'
import type { ProtocolEnvelope } from './protocol'

// Helper: compare Uint8Arrays
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

describe('CborCodec - round-trip', () => {
  it('null round-trips', () => {
    const encoded = encodeCbor(null)
    expect(decodeCbor(encoded)).toBe(null)
  })

  it('boolean false round-trips', () => {
    const encoded = encodeCbor(false)
    expect(decodeCbor(encoded)).toBe(false)
  })

  it('boolean true round-trips', () => {
    const encoded = encodeCbor(true)
    expect(decodeCbor(encoded)).toBe(true)
  })

  it('integer 0 round-trips', () => {
    const encoded = encodeCbor(0)
    expect(decodeCbor(encoded)).toBe(0)
  })

  it('integer 42 round-trips', () => {
    const encoded = encodeCbor(42)
    expect(decodeCbor(encoded)).toBe(42)
  })

  it('negative integer round-trips', () => {
    const encoded = encodeCbor(-100)
    expect(decodeCbor(encoded)).toBe(-100)
  })

  it('float round-trips', () => {
    const encoded = encodeCbor(3.14)
    const decoded = decodeCbor(encoded)
    expect(typeof decoded).toBe('number')
    expect(decoded as number).toBeCloseTo(3.14, 10)
  })

  it('string round-trips', () => {
    const encoded = encodeCbor('hello world')
    expect(decodeCbor(encoded)).toBe('hello world')
  })

  it('empty string round-trips', () => {
    const encoded = encodeCbor('')
    expect(decodeCbor(encoded)).toBe('')
  })

  it('array round-trips', () => {
    const arr = [1, 'two', true, null, 3.14]
    const encoded = encodeCbor(arr)
    const decoded = decodeCbor(encoded)
    expect(decoded).toEqual(arr)
  })

  it('nested object round-trips', () => {
    const obj = { a: 1, b: 'hello', c: [1, 2, 3], d: { e: true } }
    const encoded = encodeCbor(obj)
    const decoded = decodeCbor(encoded)
    expect(decoded).toEqual(obj)
  })

  it('Uint8Array round-trips', () => {
    const bytes = new Uint8Array([0x01, 0x02, 0x03, 0xff])
    const encoded = encodeCbor(bytes)
    const decoded = decodeCbor(encoded)
    expect(decoded).toBeInstanceOf(Uint8Array)
    expect(bytesEqual(decoded as Uint8Array, bytes)).toBe(true)
  })
})

describe('CborCodec - deterministic encoding', () => {
  it('encoding same object twice gives identical bytes', () => {
    const obj = { z: 3, a: 1, m: 2, nested: { x: 'hello' } }
    const enc1 = encodeCbor(obj)
    const enc2 = encodeCbor(obj)
    expect(bytesEqual(enc1, enc2)).toBe(true)
  })

  it('encoding independently with two encoder instances gives identical bytes', () => {
    const obj = { foo: 'bar', baz: 42 }
    const enc1 = new CborEncoder().encode(obj)
    const enc2 = new CborEncoder().encode(obj)
    expect(bytesEqual(enc1, enc2)).toBe(true)
  })
})

describe('CborCodec - key ordering', () => {
  it('map keys {z, a, m} are encoded in a < m < z byte order', () => {
    const obj = { z: 3, a: 1, m: 2 }
    const encoded = encodeCbor(obj)
    const decoded = decodeCbor(encoded) as Record<string, unknown>
    // Verify all keys present and correct values
    expect(decoded['a']).toBe(1)
    expect(decoded['m']).toBe(2)
    expect(decoded['z']).toBe(3)

    // Verify byte order: find the offset of each key char in encoded bytes
    // Key 'a' (0x61) must appear before 'm' (0x6d) which must appear before 'z' (0x7a)
    const textA = 0x61 // 'a'
    const textM = 0x6d // 'm'
    const textZ = 0x7a // 'z'

    let posA = -1, posM = -1, posZ = -1
    for (let i = 0; i < encoded.length; i++) {
      if (encoded[i] === textA && posA === -1) posA = i
      if (encoded[i] === textM && posM === -1) posM = i
      if (encoded[i] === textZ && posZ === -1) posZ = i
    }
    expect(posA).toBeGreaterThanOrEqual(0)
    expect(posM).toBeGreaterThan(posA)
    expect(posZ).toBeGreaterThan(posM)
  })
})

describe('CborCodec - integer encoding sizes', () => {
  it('0 encodes to 1 byte', () => {
    const encoded = encodeCbor(0)
    expect(encoded.length).toBe(1)
    expect(encoded[0]).toBe(0x00)
  })

  it('23 encodes to 1 byte', () => {
    const encoded = encodeCbor(23)
    expect(encoded.length).toBe(1)
    expect(encoded[0]).toBe(0x17) // 0<<5 | 23
  })

  it('24 encodes to 2 bytes', () => {
    const encoded = encodeCbor(24)
    expect(encoded.length).toBe(2)
    expect(encoded[0]).toBe(0x18) // 0<<5 | 24 (1-byte additional)
    expect(encoded[1]).toBe(24)
  })

  it('255 encodes to 2 bytes', () => {
    const encoded = encodeCbor(255)
    expect(encoded.length).toBe(2)
    expect(encoded[0]).toBe(0x18)
    expect(encoded[1]).toBe(255)
  })

  it('256 encodes to 3 bytes', () => {
    const encoded = encodeCbor(256)
    expect(encoded.length).toBe(3)
    expect(encoded[0]).toBe(0x19) // 0<<5 | 25 (2-byte additional)
    expect(encoded[1]).toBe(0x01)
    expect(encoded[2]).toBe(0x00)
  })
})

describe('envelopeCbor - round-trip', () => {
  const baseEnvelope: ProtocolEnvelope = {
    header: {
      version: '7h3/0.1',
      messageId: 'msg-1234567890-abc12345',
      timestampMs: 1700000000000,
      ttlMs: 60000,
      sender: 'agent:alice@example.com',
      nonce: 'abcdefghij',
    },
    body: {
      intent: 'TASK',
      content: 'Hello, agent!',
    },
  }

  it('round-trip preserves all required fields', () => {
    const encoded = encodeEnvelopeCbor(baseEnvelope)
    const decoded = decodeEnvelopeCbor(encoded)

    expect(decoded.header.version).toBe(baseEnvelope.header.version)
    expect(decoded.header.messageId).toBe(baseEnvelope.header.messageId)
    expect(decoded.header.timestampMs).toBe(baseEnvelope.header.timestampMs)
    expect(decoded.header.ttlMs).toBe(baseEnvelope.header.ttlMs)
    expect(decoded.header.sender).toBe(baseEnvelope.header.sender)
    expect(decoded.header.nonce).toBe(baseEnvelope.header.nonce)
    expect(decoded.body.intent).toBe(baseEnvelope.body.intent)
    expect(decoded.body.content).toBe(baseEnvelope.body.content)
  })

  it('round-trip preserves optional fields: recipient, capability, correlationId', () => {
    const full: ProtocolEnvelope = {
      ...baseEnvelope,
      header: { ...baseEnvelope.header, recipient: 'agent:bob@example.com' },
      body: { ...baseEnvelope.body, capability: 'file.read', correlationId: 'corr-xyz' },
      signature: {
        alg: 'HS256',
        keyId: 'my-key-id',
        value: 'base64urlencodedvalue',
      },
    }

    const encoded = encodeEnvelopeCbor(full)
    const decoded = decodeEnvelopeCbor(encoded)

    expect(decoded.header.recipient).toBe('agent:bob@example.com')
    expect(decoded.body.capability).toBe('file.read')
    expect(decoded.body.correlationId).toBe('corr-xyz')
    expect(decoded.signature?.alg).toBe('HS256')
    expect(decoded.signature?.keyId).toBe('my-key-id')
    expect(decoded.signature?.value).toBe('base64urlencodedvalue')
  })

  it('CBOR envelope is smaller than JSON equivalent (size comparison)', () => {
    const full: ProtocolEnvelope = {
      ...baseEnvelope,
      header: { ...baseEnvelope.header, recipient: 'agent:bob@example.com' },
      body: { ...baseEnvelope.body, capability: 'file.read', correlationId: 'corr-xyz' },
      signature: {
        alg: 'HS256',
        keyId: 'my-key-id',
        value: 'base64urlencodedvalue',
      },
    }

    const cborBytes = encodeEnvelopeCbor(full)
    const jsonBytes = new TextEncoder().encode(JSON.stringify(full))

    console.log(`CBOR size: ${cborBytes.length} bytes, JSON size: ${jsonBytes.length} bytes, ratio: ${(cborBytes.length / jsonBytes.length).toFixed(2)}`)
    expect(cborBytes.length).toBeLessThan(jsonBytes.length)
  })

  it('optional fields absent in input are absent in output', () => {
    // No recipient, capability, correlationId, signature
    const minimal: ProtocolEnvelope = {
      header: {
        version: '7h3/0.1',
        messageId: 'msg-min',
        timestampMs: 1700000000000,
        ttlMs: 30000,
        sender: 'agent:sender',
        nonce: 'nonce123',
      },
      body: {
        intent: 'PING',
        content: 'ping',
      },
    }

    const encoded = encodeEnvelopeCbor(minimal)
    const decoded = decodeEnvelopeCbor(encoded)

    expect(decoded.header.recipient).toBeUndefined()
    expect(decoded.body.capability).toBeUndefined()
    expect(decoded.body.correlationId).toBeUndefined()
    expect(decoded.signature).toBeUndefined()
  })
})

describe('CborCodec - map decoding does not enable prototype pollution', () => {
  it('a "__proto__" key decodes as a plain own property, not a prototype swap', () => {
    const map = new Map<string, unknown>()
    map.set('__proto__', { polluted: true })
    map.set('safe', 'value')

    const decoded = decodeCbor(encodeCbor(map)) as Record<string, unknown>

    expect(Object.getPrototypeOf(decoded)).toBe(null)
    expect(Object.prototype.hasOwnProperty.call(decoded, '__proto__')).toBe(true)
    expect(decoded['__proto__']).toEqual({ polluted: true })
    expect(decoded.safe).toBe('value')
    // Confirm the global Object.prototype was never actually touched.
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
  })
})

describe('envelopeCbor - rejects wrong-typed and non-finite fields', () => {
  // Field keys per the module doc comment: header 3=timestampMs, 4=ttlMs;
  // body 1=intent, 2=content.
  function encodeRawEnvelope(headerOverrides: Record<number, unknown>, bodyOverrides: Record<number, unknown> = {}): Uint8Array {
    const header = new Map<number, unknown>([
      [1, '7h3/0.1'],
      [2, 'msg-1'],
      [3, 1700000000000],
      [4, 60000],
      [5, 'agent:sender'],
      [7, 'nonce123'],
    ])
    for (const [k, v] of Object.entries(headerOverrides)) header.set(Number(k), v)

    const body = new Map<number, unknown>([
      [1, 'TASK'],
      [2, 'hello'],
    ])
    for (const [k, v] of Object.entries(bodyOverrides)) body.set(Number(k), v)

    const top = new Map<number, unknown>([
      [1, header],
      [2, body],
    ])
    return encodeCbor(top)
  }

  it('rejects a non-finite ttlMs (NaN/Infinity float smuggled via CBOR)', () => {
    for (const bad of [NaN, Infinity, -Infinity]) {
      const bytes = encodeRawEnvelope({ 4: bad })
      expect(() => decodeEnvelopeCbor(bytes)).toThrow(/ttlMs must be a finite number/)
    }
  })

  it('rejects a non-finite timestampMs', () => {
    const bytes = encodeRawEnvelope({ 3: NaN })
    expect(() => decodeEnvelopeCbor(bytes)).toThrow(/timestampMs must be a finite number/)
  })

  it('rejects a non-string content field (e.g. a nested map instead of a string)', () => {
    const bytes = encodeRawEnvelope({}, { 2: new Map([['injected', true]]) })
    expect(() => decodeEnvelopeCbor(bytes)).toThrow(/content must be a string/)
  })

  it('rejects a non-string sender field', () => {
    const bytes = encodeRawEnvelope({ 5: 12345 })
    expect(() => decodeEnvelopeCbor(bytes)).toThrow(/sender must be a string/)
  })
})
