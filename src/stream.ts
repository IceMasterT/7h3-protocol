// 7h3 Protocol — Streaming message signing (Feature 4)
//
// Wire format per chunk:
//   { i, d, h, f }                    — non-final frame
//   { i, d, h, f:true, sig, kid }     — final frame
//
// Security model:
//   Writer derives an HMAC-SHA256 key via HKDF(privateKeyBytes, salt=nonce, info='7h3-stream/1')
//   and produces per-chunk HMACs.  Only the writer can verify these (private key material).
//
//   Reader verification is anchored on the Ed25519 final signature which covers
//   SHA-256( ordered concat of "i:d" per chunk ) — so any mid-stream tamper, reorder,
//   or cross-stream splice is caught at finalize time.

// ────────────────────────────────── types ─────────────────────────────────────

export interface StreamChunk {
  i: number       // sequence index (0-based)
  d: string       // data (string)
  h: string       // per-chunk HMAC-SHA256 (base64url) — writer-side only
  f: boolean      // true = final frame
  sig?: string    // Ed25519 sig over content hash (only on final frame)
  kid?: string    // keyId (only on final frame)
}

export interface StreamSignerOpts {
  privateKey: string    // Ed25519 PKCS8 base64url
  sender: string
  nonce?: string        // auto-generated when omitted
  keyId?: string
}

export interface StreamVerifierOpts {
  publicKey: string     // Ed25519 SPKI base64url
  maxChunks?: number    // default 10000
}

export type StreamVerifyResult =
  | { ok: true; totalBytes: number; chunkCount: number }
  | { ok: false; reason: string; chunkIndex?: number }

// ─────────────────────────── constants ────────────────────────────────────────

export const STREAM_HEADER = 'x-7h3-stream'

// ─────────────────────────── internal helpers ─────────────────────────────────

const textEncoder = new TextEncoder()

function requireCryptoSubtle(): SubtleCrypto {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API is not available in this runtime')
  }
  return crypto.subtle
}

function toBase64Url(bytes: Uint8Array): string {
  const bufferLike = (globalThis as any).Buffer
  const base64 = bufferLike
    ? bufferLike.from(bytes).toString('base64')
    : btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=')
  const bufferLike = (globalThis as any).Buffer
  if (bufferLike) return new Uint8Array(bufferLike.from(padded, 'base64'))
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

function generateNonce(): string {
  const arr = new Uint8Array(16)
  crypto.getRandomValues(arr)
  return toBase64Url(arr)
}

// ─────────────────── HMAC key derivation (HKDF from private key) ──────────────
//
// IKM = raw PKCS8 DER bytes of the Ed25519 private key
// salt = nonce (UTF-8)
// info = '7h3-stream/1' (UTF-8)
// output = 32-byte HMAC-SHA256 key
//
// The derived key is cached per (privateKey, nonce) pair so 1000 chunks only
// pay one HKDF derivation.

const derivedHmacKeyCache = new Map<string, Promise<CryptoKey>>()
const HMAC_KEY_CACHE_LIMIT = 128

function getDerivedHmacKey(privateKeyBase64Url: string, nonce: string): Promise<CryptoKey> {
  const cacheKey = `${privateKeyBase64Url}:${nonce}`
  const cached = derivedHmacKeyCache.get(cacheKey)
  if (cached) return cached

  if (derivedHmacKeyCache.size >= HMAC_KEY_CACHE_LIMIT) derivedHmacKeyCache.clear()

  const subtle = requireCryptoSubtle()
  const pkcs8Bytes = fromBase64Url(privateKeyBase64Url)

  const promise = (async () => {
    // Import the raw PKCS8 bytes as HKDF input keying material
    const hkdfKey = await subtle.importKey(
      'raw',
      toArrayBuffer(pkcs8Bytes),
      'HKDF',
      false,
      ['deriveBits'],
    )
    // Derive 256 bits
    const bits = await subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: textEncoder.encode(nonce),
        info: textEncoder.encode('7h3-stream/1'),
      },
      hkdfKey,
      256,
    )
    // Wrap as HMAC-SHA256 signing key
    return subtle.importKey(
      'raw',
      bits,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
  })()

  promise.catch(() => derivedHmacKeyCache.delete(cacheKey))
  derivedHmacKeyCache.set(cacheKey, promise)
  return promise
}

// ─────────────────── Ed25519 private key cache ────────────────────────────────

const ed25519PrivCache = new Map<string, Promise<CryptoKey>>()
const ED25519_PRIV_CACHE_LIMIT = 64

function getCachedEd25519PrivateKey(privateKeyBase64Url: string): Promise<CryptoKey> {
  const cached = ed25519PrivCache.get(privateKeyBase64Url)
  if (cached) return cached
  if (ed25519PrivCache.size >= ED25519_PRIV_CACHE_LIMIT) ed25519PrivCache.clear()
  const subtle = requireCryptoSubtle()
  const promise = subtle
    .importKey('pkcs8', toArrayBuffer(fromBase64Url(privateKeyBase64Url)), { name: 'Ed25519' }, false, ['sign'])
    .catch((err: unknown) => { ed25519PrivCache.delete(privateKeyBase64Url); throw err })
  ed25519PrivCache.set(privateKeyBase64Url, promise)
  return promise
}

const ed25519PubCache = new Map<string, Promise<CryptoKey>>()
const ED25519_PUB_CACHE_LIMIT = 64

function getCachedEd25519PublicKey(publicKeyBase64Url: string): Promise<CryptoKey> {
  const cached = ed25519PubCache.get(publicKeyBase64Url)
  if (cached) return cached
  if (ed25519PubCache.size >= ED25519_PUB_CACHE_LIMIT) ed25519PubCache.clear()
  const subtle = requireCryptoSubtle()
  const promise = subtle
    .importKey('spki', toArrayBuffer(fromBase64Url(publicKeyBase64Url)), { name: 'Ed25519' }, false, ['verify'])
    .catch((err: unknown) => { ed25519PubCache.delete(publicKeyBase64Url); throw err })
  ed25519PubCache.set(publicKeyBase64Url, promise)
  return promise
}

// ─────────────────── content-hash helpers ─────────────────────────────────────
//
// Content hash = SHA-256 over UTF-8 join of "i:d" per chunk, in order.
// For the empty stream the message is the empty string "".
// The join separator is "\n" to keep chunks from blending across boundaries.

function buildContentMessage(chunks: Array<{ i: number; d: string }>): Uint8Array {
  const parts = chunks.map(c => `${c.i}:${c.d}`)
  return textEncoder.encode(parts.join('\n'))
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const subtle = requireCryptoSubtle()
  const digest = await subtle.digest('SHA-256', toArrayBuffer(data))
  return new Uint8Array(digest)
}

// ─────────────────── SignedStreamWriter ───────────────────────────────────────

export class SignedStreamWriter {
  private readonly opts: Required<StreamSignerOpts>
  private seq = 0
  private readonly accum: Array<{ i: number; d: string }> = []
  // Lazily-derived HMAC key (cached after first use)
  private hmacKeyPromise: Promise<CryptoKey> | null = null

  constructor(opts: StreamSignerOpts) {
    this.opts = {
      nonce: opts.nonce ?? generateNonce(),
      keyId: opts.keyId ?? 'stream-key',
      ...opts,
    }
  }

  get nonce(): string { return this.opts.nonce }

  private getHmacKey(): Promise<CryptoKey> {
    if (!this.hmacKeyPromise) {
      this.hmacKeyPromise = getDerivedHmacKey(this.opts.privateKey, this.opts.nonce)
    }
    return this.hmacKeyPromise
  }

  private async computeChunkHmac(index: number, data: string): Promise<string> {
    const subtle = requireCryptoSubtle()
    const key = await this.getHmacKey()
    // payload = nonce ":" index ":" data
    const payload = `${this.opts.nonce}:${index}:${data}`
    const sig = await subtle.sign('HMAC', key, textEncoder.encode(payload))
    return toBase64Url(new Uint8Array(sig))
  }

  async writeChunk(data: string): Promise<StreamChunk> {
    const index = this.seq++
    const h = await this.computeChunkHmac(index, data)
    this.accum.push({ i: index, d: data })
    return { i: index, d: data, h, f: false }
  }

  async finalize(): Promise<StreamChunk> {
    const subtle = requireCryptoSubtle()
    const privKey = await getCachedEd25519PrivateKey(this.opts.privateKey)

    // Sign over SHA-256 of ordered chunk content
    const contentMsg = buildContentMessage(this.accum)
    const digest = await sha256(contentMsg)
    // Ed25519 signs the digest bytes directly (WebCrypto Ed25519 takes raw message)
    const sigBytes = await subtle.sign('Ed25519', privKey, toArrayBuffer(digest))
    const sig = toBase64Url(new Uint8Array(sigBytes))

    // Final frame HMAC is over the content hash (hex) so it binds the full stream
    const index = this.seq
    const finalData = ''
    const h = await this.computeChunkHmac(index, toBase64Url(digest))

    return { i: index, d: finalData, h, f: true, sig, kid: this.opts.keyId }
  }
}

// ─────────────────── SignedStreamReader ───────────────────────────────────────

export class SignedStreamReader {
  private readonly opts: StreamVerifierOpts
  private expectedSeq = 0
  private readonly accum: Array<{ i: number; d: string }> = []
  private totalBytes = 0
  private done = false

  constructor(opts: StreamVerifierOpts) {
    this.opts = opts
  }

  async receiveChunk(chunk: StreamChunk): Promise<{ ok: boolean; reason?: string }> {
    if (this.done) return { ok: false, reason: 'stream already finalized' }

    const maxChunks = this.opts.maxChunks ?? 10_000
    if (this.accum.length >= maxChunks) {
      return { ok: false, reason: `exceeded maxChunks (${maxChunks})` }
    }

    // Sequence check — no gaps, no reorder
    if (chunk.i !== this.expectedSeq) {
      return { ok: false, reason: `sequence error: expected ${this.expectedSeq}, got ${chunk.i}` }
    }
    this.expectedSeq++

    // Accumulate data
    this.accum.push({ i: chunk.i, d: chunk.d })
    this.totalBytes += textEncoder.encode(chunk.d).length

    // Per-chunk HMAC is writer-side only (requires private key); we skip it here.
    // The Ed25519 final signature covers all chunks and is the reader's guarantee.

    return { ok: true }
  }

  async finalize(finalChunk: StreamChunk): Promise<StreamVerifyResult> {
    if (this.done) return { ok: false, reason: 'stream already finalized' }
    this.done = true

    if (!finalChunk.sig) {
      return { ok: false, reason: 'missing signature on final chunk' }
    }

    const subtle = requireCryptoSubtle()
    let pubKey: CryptoKey
    try {
      pubKey = await getCachedEd25519PublicKey(this.opts.publicKey)
    } catch {
      return { ok: false, reason: 'invalid public key' }
    }

    // Recompute the content hash (same as writer)
    const contentMsg = buildContentMessage(this.accum)
    const digest = await sha256(contentMsg)

    const sigBytes = fromBase64Url(finalChunk.sig)
    const valid = await subtle.verify('Ed25519', pubKey, toArrayBuffer(sigBytes), toArrayBuffer(digest))

    if (!valid) {
      return { ok: false, reason: 'signature verification failed' }
    }

    return { ok: true, totalBytes: this.totalBytes, chunkCount: this.accum.length }
  }
}

// ─────────────────── factory helpers ──────────────────────────────────────────

export function createSignedStream(opts: StreamSignerOpts): SignedStreamWriter {
  return new SignedStreamWriter(opts)
}

export function createStreamVerifier(opts: StreamVerifierOpts): SignedStreamReader {
  return new SignedStreamReader(opts)
}

// ─────────────────── convenience functions ────────────────────────────────────

export async function signStream(
  chunks: AsyncIterable<string> | string[],
  opts: StreamSignerOpts,
): Promise<StreamChunk[]> {
  const writer = new SignedStreamWriter(opts)
  const result: StreamChunk[] = []
  if (Array.isArray(chunks)) {
    for (const data of chunks) {
      result.push(await writer.writeChunk(data))
    }
  } else {
    for await (const data of chunks) {
      result.push(await writer.writeChunk(data))
    }
  }
  result.push(await writer.finalize())
  return result
}

export async function verifyStream(
  chunks: StreamChunk[],
  opts: StreamVerifierOpts,
): Promise<StreamVerifyResult> {
  const reader = new SignedStreamReader(opts)
  // All frames except the last
  const nonFinal = chunks.slice(0, -1)
  const finalFrame = chunks[chunks.length - 1]

  if (chunks.length === 0) {
    return { ok: false, reason: 'empty chunk array — missing final frame' }
  }

  for (const chunk of nonFinal) {
    const res = await reader.receiveChunk(chunk)
    if (!res.ok) return { ok: false, reason: res.reason!, chunkIndex: chunk.i }
  }

  if (!finalFrame.f) {
    // The last chunk in the array is not marked final — still try to read it as non-final
    // so sequence errors are reported, but finalize will fail due to missing sig
    const res = await reader.receiveChunk(finalFrame)
    if (!res.ok) return { ok: false, reason: res.reason!, chunkIndex: finalFrame.i }
    return { ok: false, reason: 'missing final frame' }
  }

  return reader.finalize(finalFrame)
}

// ─────────────────── encode / decode helpers ──────────────────────────────────

export function encodeStreamChunk(chunk: StreamChunk): string {
  return JSON.stringify(chunk)
}

export function decodeStreamChunk(raw: string): StreamChunk {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('decodeStreamChunk: invalid JSON')
  }
  const obj = parsed as Record<string, unknown>
  if (
    typeof obj.i !== 'number' ||
    typeof obj.d !== 'string' ||
    typeof obj.h !== 'string' ||
    typeof obj.f !== 'boolean'
  ) {
    throw new Error('decodeStreamChunk: missing required fields (i, d, h, f)')
  }
  const chunk: StreamChunk = { i: obj.i, d: obj.d, h: obj.h, f: obj.f }
  if (obj.sig !== undefined) {
    if (typeof obj.sig !== 'string') throw new Error('decodeStreamChunk: sig must be string')
    chunk.sig = obj.sig
  }
  if (obj.kid !== undefined) {
    if (typeof obj.kid !== 'string') throw new Error('decodeStreamChunk: kid must be string')
    chunk.kid = obj.kid
  }
  return chunk
}
