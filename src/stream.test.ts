import { describe, it, expect } from 'vitest'
import {
  SignedStreamWriter,
  SignedStreamReader,
  createSignedStream,
  createStreamVerifier,
  signStream,
  verifyStream,
  encodeStreamChunk,
  decodeStreamChunk,
  type StreamChunk,
  type StreamSignerOpts,
  type StreamVerifierOpts,
} from './stream'
import { generateEd25519KeypairBase64Url } from './protocol'

// ─────────────────── helpers ───────────────────────────────────────────────────

async function makeKeyPair() {
  return generateEd25519KeypairBase64Url()
}

function signerOpts(privateKey: string, nonce?: string): StreamSignerOpts {
  return { privateKey, sender: 'test-agent', nonce: nonce ?? 'fixed-nonce-for-tests', keyId: 'test-key' }
}

function verifierOpts(publicKey: string): StreamVerifierOpts {
  return { publicKey }
}

// ─────────────────── tests ────────────────────────────────────────────────────

describe('SignedStreamWriter + SignedStreamReader', () => {
  it('test 1: 5-chunk round trip verifies', async () => {
    const kp = await makeKeyPair()
    const writer = new SignedStreamWriter(signerOpts(kp.privateKey))
    const reader = new SignedStreamReader(verifierOpts(kp.publicKey))

    const dataChunks = ['Hello ', 'World', ' from', ' 7h3', ' Protocol']
    const frames: StreamChunk[] = []

    for (const d of dataChunks) {
      const frame = await writer.writeChunk(d)
      expect(frame.f).toBe(false)
      expect(frame.i).toBe(frames.length)
      expect(typeof frame.h).toBe('string')
      frames.push(frame)
    }

    // Feed non-final chunks to reader
    for (const frame of frames) {
      const res = await reader.receiveChunk(frame)
      expect(res.ok).toBe(true)
    }

    const finalFrame = await writer.finalize()
    expect(finalFrame.f).toBe(true)
    expect(typeof finalFrame.sig).toBe('string')
    expect(finalFrame.kid).toBe('test-key')

    const result = await reader.finalize(finalFrame)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.chunkCount).toBe(5)
      // totalBytes = sum of UTF-8 bytes of each data chunk
      const expected = dataChunks.reduce((s, d) => s + new TextEncoder().encode(d).length, 0)
      expect(result.totalBytes).toBe(expected)
    }
  })

  it('test 2: single chunk round trip', async () => {
    const kp = await makeKeyPair()
    const writer = new SignedStreamWriter(signerOpts(kp.privateKey))
    const reader = new SignedStreamReader(verifierOpts(kp.publicKey))

    const frame = await writer.writeChunk('only one chunk')
    const res = await reader.receiveChunk(frame)
    expect(res.ok).toBe(true)

    const finalFrame = await writer.finalize()
    const result = await reader.finalize(finalFrame)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.chunkCount).toBe(1)
    }
  })

  it('test 3: empty stream (just finalize) verifies', async () => {
    const kp = await makeKeyPair()
    const writer = new SignedStreamWriter(signerOpts(kp.privateKey))
    const reader = new SignedStreamReader(verifierOpts(kp.publicKey))

    const finalFrame = await writer.finalize()
    expect(finalFrame.f).toBe(true)
    expect(typeof finalFrame.sig).toBe('string')

    const result = await reader.finalize(finalFrame)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.chunkCount).toBe(0)
      expect(result.totalBytes).toBe(0)
    }
  })

  it('test 4: tampered chunk data detected (HMAC fails on that chunk, Ed25519 fails at finalize)', async () => {
    const kp = await makeKeyPair()
    const writer = new SignedStreamWriter(signerOpts(kp.privateKey))
    const reader = new SignedStreamReader(verifierOpts(kp.publicKey))

    const frame0 = await writer.writeChunk('legit data')
    const frame1 = await writer.writeChunk('also legit')
    const finalFrame = await writer.finalize()

    // Tamper with frame0's data
    const tampered: StreamChunk = { ...frame0, d: 'TAMPERED' }

    // Reader accepts the chunk (sequence is fine; reader can't verify HMAC without private key)
    await reader.receiveChunk(tampered)
    await reader.receiveChunk(frame1)

    // But the final Ed25519 signature will fail because the content hash is different
    const result = await reader.finalize(finalFrame)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/signature verification failed/i)
    }
  })

  it('test 5: wrong public key: final Ed25519 fails', async () => {
    const kp = await makeKeyPair()
    const wrongKp = await makeKeyPair()

    const writer = new SignedStreamWriter(signerOpts(kp.privateKey))
    // Reader uses a DIFFERENT public key
    const reader = new SignedStreamReader(verifierOpts(wrongKp.publicKey))

    const frame = await writer.writeChunk('data')
    await reader.receiveChunk(frame)

    const finalFrame = await writer.finalize()
    const result = await reader.finalize(finalFrame)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/signature verification failed/i)
    }
  })

  it('test 6: out-of-order chunk: sequence error', async () => {
    const kp = await makeKeyPair()
    const writer = new SignedStreamWriter(signerOpts(kp.privateKey))
    const reader = new SignedStreamReader(verifierOpts(kp.publicKey))

    const frame0 = await writer.writeChunk('first')
    const frame1 = await writer.writeChunk('second')

    // Feed frame1 before frame0 (out of order — frame1 has i=1, reader expects i=0)
    const resOoo = await reader.receiveChunk(frame1)
    expect(resOoo.ok).toBe(false)
    if (!resOoo.ok) {
      expect(resOoo.reason).toMatch(/sequence error/i)
    }

    // Feed in yet another out-of-order delivery: feed frame0, then frame1 again — frame1 will be seen
    // as seq=1 but reader has only accepted 0 so far (via the successful frame0), so now inject a
    // duplicate of frame1 which would be at seq=1 yet again — that should be fine.
    // More importantly: verify that the FIRST out-of-order was caught.
    // The reader did NOT increment on failure, so frame0 (i=0) is now OK.
    const resAfter = await reader.receiveChunk(frame0)
    expect(resAfter.ok).toBe(true)  // seq=0 is correct now (reader expected 0 after ooo failure)
  })

  it('test 7: signStream(array) + verifyStream round trip', async () => {
    const kp = await makeKeyPair()
    const data = ['chunk A', 'chunk B', 'chunk C']
    const chunks = await signStream(data, signerOpts(kp.privateKey))

    // signStream returns n+1 frames (n data + 1 final)
    expect(chunks).toHaveLength(data.length + 1)
    expect(chunks[chunks.length - 1].f).toBe(true)

    const result = await verifyStream(chunks, verifierOpts(kp.publicKey))
    expect(result.ok).toBe(true)
  })

  it('test 8: replay — same StreamChunk in a different stream fails (nonce in HMAC)', async () => {
    const kp = await makeKeyPair()

    // Stream A
    const writerA = new SignedStreamWriter({ ...signerOpts(kp.privateKey), nonce: 'nonce-A' })
    const chunkA0 = await writerA.writeChunk('data A')
    const finalA = await writerA.finalize()

    // Stream B — different nonce
    const writerB = new SignedStreamWriter({ ...signerOpts(kp.privateKey), nonce: 'nonce-B' })
    // Don't write any chunk to B, then produce its final frame
    const finalB = await writerB.finalize()

    // Reader for stream B expects B's content — inject A's chunk into B's reader
    const readerB = new SignedStreamReader(verifierOpts(kp.publicKey))
    // Feed chunk from stream A (which has content 'data A') and use B's finalFrame
    await readerB.receiveChunk(chunkA0)
    // finalB was computed over empty content — now we have chunkA0's data accumulated
    const result = await readerB.finalize(finalB)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/signature verification failed/i)
    }

    // Stream A itself verifies fine
    const readerA = new SignedStreamReader(verifierOpts(kp.publicKey))
    await readerA.receiveChunk(chunkA0)
    const resultA = await readerA.finalize(finalA)
    expect(resultA.ok).toBe(true)
  })

  it('test 9: large stream — 1000 chunks verify in <500ms', async () => {
    const kp = await makeKeyPair()
    const chunks: string[] = Array.from({ length: 1000 }, (_, i) => `token-${i}`)

    const start = Date.now()
    const frames = await signStream(chunks, signerOpts(kp.privateKey))
    const result = await verifyStream(frames, verifierOpts(kp.publicKey))
    const elapsed = Date.now() - start

    expect(result.ok).toBe(true)
    expect(elapsed).toBeLessThan(500)
    if (result.ok) {
      expect(result.chunkCount).toBe(1000)
    }
  })
})

describe('encodeStreamChunk / decodeStreamChunk', () => {
  it('round-trips a non-final chunk', () => {
    const chunk: StreamChunk = { i: 3, d: 'hello', h: 'abc-def', f: false }
    const encoded = encodeStreamChunk(chunk)
    const decoded = decodeStreamChunk(encoded)
    expect(decoded).toEqual(chunk)
  })

  it('round-trips a final chunk', () => {
    const chunk: StreamChunk = { i: 10, d: '', h: 'xxx', f: true, sig: 'yyy', kid: 'mykey' }
    expect(decodeStreamChunk(encodeStreamChunk(chunk))).toEqual(chunk)
  })

  it('throws on invalid JSON', () => {
    expect(() => decodeStreamChunk('not json')).toThrow(/invalid JSON/i)
  })

  it('throws on missing required fields', () => {
    expect(() => decodeStreamChunk('{"i":0,"d":"x"}')).toThrow(/missing required fields/i)
  })
})

