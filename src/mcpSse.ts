/**
 * Signed Server-Sent Events for MCP's streamable HTTP transport.
 *
 * MCP servers stream JSON-RPC messages (progress, notifications, results) to the
 * client as SSE. Unlike the request/response tunnel in `mcpWrapper`, a stream is a
 * long-lived sequence, so signing each message is not enough: an attacker on the
 * path could still drop events, reorder them, replay old ones, splice in events
 * from another stream, or cut the stream short and let the client think it
 * finished. This module closes those gaps.
 *
 * Each event carries one signed 7h3 envelope whose signed content is
 * `{ stream, seq, message }`:
 *
 *   - **authenticity** — every event is signed by the peer; an injected or altered
 *     event fails verification;
 *   - **order and completeness** — `seq` must be exactly 0, 1, 2, …; a gap, repeat
 *     or reorder is rejected;
 *   - **stream binding** — the stream id is signed, so events cannot be spliced in
 *     from another stream, and the envelope is addressed to this client;
 *   - **replay** — the usual nonce/TTL replay cache applies to every event;
 *   - **termination** — the stream ends with a signed `end` event carrying the
 *     message count. A stream that stops without it is reported as truncated.
 *
 * The SSE framing itself (`id:`, `event:`, comments) is NOT signed and is never
 * trusted; only the signed `data` matters.
 *
 * Not supported: resuming with `Last-Event-ID`. A resumed stream cannot prove it
 * has no gap, so a reconnect must open a new stream (new stream id) and re-request.
 */

import { createEnvelope, type ProtocolEnvelope } from './protocol'
import { InMemoryReplayCache } from './protocolReplay'
import { encodeEnvelope, receiveEnvelope, type ReceiveEnvelopeOptions } from './protocolTransport'

export type McpMessage = { jsonrpc: '2.0'; [key: string]: unknown }

export const SSE_CONTENT_TYPE = 'text/event-stream'

/** Headers for a signed SSE response. `x-accel-buffering: no` stops nginx from batching events. */
export function signedSseHeaders(): Record<string, string> {
  return { 'content-type': SSE_CONTENT_TYPE, 'cache-control': 'no-cache, no-transform', 'x-accel-buffering': 'no' }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

export interface SignedSseWriterOptions {
  /** This peer's id: the envelope sender. */
  selfAgentId: string
  /** The receiving peer's id: the envelope recipient. */
  peerAgentId: string
  sign: (envelope: Omit<ProtocolEnvelope, 'signature'>) => Promise<ProtocolEnvelope>
  /** Unique per stream. Generated when omitted. */
  streamId?: string
  /** Per-event envelope lifetime in ms (default 60 s). Each event is signed when it is written. */
  ttlMs?: number
  /** Ties the stream to the request that opened it (recommended: the request envelope's messageId). */
  correlationId?: string
}

function randomStreamId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export class SignedSseWriter {
  readonly streamId: string
  private seq = 0
  private ended = false

  constructor(private readonly options: SignedSseWriterOptions) {
    this.streamId = options.streamId ?? randomStreamId()
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(this.streamId)) throw new Error('SignedSseWriter: streamId must be 1-128 of [A-Za-z0-9._:-]')
  }

  private async event(kind: 'message' | 'end', payload: Record<string, unknown>): Promise<string> {
    const seq = this.seq++
    const envelope = createEnvelope({
      sender: this.options.selfAgentId,
      recipient: this.options.peerAgentId,
      intent: 'RESULT',
      content: JSON.stringify({ stream: this.streamId, seq, ...payload }),
      correlationId: this.options.correlationId,
      ttlMs: this.options.ttlMs ?? 60_000,
    })
    const wire = encodeEnvelope(await this.options.sign(envelope), 'json')
    // JSON.stringify output contains no raw newlines, so one `data:` line is always enough.
    return `id: ${seq}\nevent: ${kind}\ndata: ${wire}\n\n`
  }

  /** Encode one JSON-RPC message as an SSE event. */
  async message(message: McpMessage): Promise<string> {
    if (this.ended) throw new Error('SignedSseWriter: stream already ended')
    return this.event('message', { message })
  }

  /** The signed terminator. Without it the reader reports the stream as truncated. */
  async end(): Promise<string> {
    if (this.ended) throw new Error('SignedSseWriter: stream already ended')
    const count = this.seq
    const text = await this.event('end', { end: true, count })
    this.ended = true
    return text
  }

  /** A keep-alive comment. Carries no data and is ignored by the reader. */
  static keepAlive(): string {
    return ': keep-alive\n\n'
  }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

export type SseFailure =
  | 'verification-failed'
  | 'wrong-sender'
  | 'wrong-recipient'
  | 'malformed-event'
  | 'stream-mismatch'
  | 'sequence-error'
  | 'event-after-end'
  | 'count-mismatch'
  | 'stream-truncated'
  | 'event-too-large'
  | 'too-many-events'

export class SseVerificationError extends Error {
  constructor(
    public readonly code: SseFailure,
    detail?: string,
  ) {
    super(detail === undefined ? code : `${code}: ${detail}`)
    this.name = 'SseVerificationError'
  }
}

export interface SignedSseReaderOptions {
  /** This peer's id; events must be addressed to it. */
  selfAgentId: string
  /** The only peer whose events are accepted. */
  peerAgentId: string
  /** Signature material resolvers, clock skew, etc. `requireSignature` and `replayCache` cannot be weakened. */
  receive?: ReceiveEnvelopeOptions
  /** Require this stream id (e.g. the one announced in the response that opened the stream). */
  expectStreamId?: string
  /** Require this envelope correlationId (the request that opened the stream). */
  expectCorrelationId?: string
  /** Largest single event, in characters (default 1 MiB). */
  maxEventBytes?: number
  /** Most events accepted before the stream is refused (default 100,000). */
  maxEvents?: number
}

export interface VerifiedSseMessage {
  seq: number
  message: McpMessage
}

interface RawSseEvent {
  data: string
  type: string
}

/**
 * Incremental verifier. Feed it text as it arrives; it returns the messages whose
 * events completed and verified in that chunk, and throws {@link SseVerificationError}
 * on the first violation. After a throw the reader is unusable: a stream that has
 * misbehaved once is not trusted for the rest of its life.
 */
export class SignedSseReader {
  private buffer = ''
  private started = false
  private lastWasCr = false
  private current: { data: string[]; type: string; size: number } = { data: [], type: '', size: 0 }
  private expectedSeq = 0
  private streamId: string | undefined
  private ended = false
  private failed: SseVerificationError | undefined
  private events = 0
  private readonly receiveOptions: ReceiveEnvelopeOptions
  private readonly maxEventBytes: number
  private readonly maxEvents: number

  constructor(private readonly options: SignedSseReaderOptions) {
    this.receiveOptions = {
      ...options.receive,
      requireSignature: true,
      replayCache: options.receive?.replayCache ?? new InMemoryReplayCache(),
    }
    this.streamId = options.expectStreamId
    this.maxEventBytes = options.maxEventBytes ?? 1024 * 1024
    this.maxEvents = options.maxEvents ?? 100_000
  }

  get done(): boolean {
    return this.ended
  }

  private fail(code: SseFailure, detail?: string): never {
    this.failed = new SseVerificationError(code, detail)
    throw this.failed
  }

  /** Feed a chunk of the response body. */
  async feed(chunk: string): Promise<VerifiedSseMessage[]> {
    if (this.failed) throw this.failed
    if (!this.started) {
      this.started = true
      if (chunk.charCodeAt(0) === 0xfeff) chunk = chunk.slice(1)
    }
    if (this.lastWasCr && chunk.startsWith('\n')) chunk = chunk.slice(1) // CRLF split across chunks
    this.lastWasCr = chunk.endsWith('\r')
    this.buffer += chunk

    const out: VerifiedSseMessage[] = []
    // Split into lines on \r\n, \n or \r (WHATWG SSE parsing). A trailing partial line stays buffered.
    for (;;) {
      const m = /\r\n|\n|\r/.exec(this.buffer)
      if (!m) break
      const line = this.buffer.slice(0, m.index)
      this.buffer = this.buffer.slice(m.index + m[0].length)
      const event = this.line(line)
      if (event) {
        const verified = await this.handle(event)
        if (verified) out.push(verified)
      }
    }
    if (this.buffer.length > this.maxEventBytes) this.fail('event-too-large')
    return out
  }

  private line(line: string): RawSseEvent | null {
    if (line === '') {
      const cur = this.current
      this.current = { data: [], type: '', size: 0 }
      if (cur.data.length === 0) return null
      return { data: cur.data.join('\n'), type: cur.type || 'message' }
    }
    if (line.startsWith(':')) return null // comment / keep-alive
    const colon = line.indexOf(':')
    const field = colon === -1 ? line : line.slice(0, colon)
    let value = colon === -1 ? '' : line.slice(colon + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    if (field === 'data') {
      this.current.size += value.length + 1
      if (this.current.size > this.maxEventBytes) this.fail('event-too-large')
      this.current.data.push(value)
    } else if (field === 'event') {
      this.current.type = value
    }
    // `id`, `retry` and unknown fields are unsigned framing: ignored on purpose.
    return null
  }

  private async handle(event: RawSseEvent): Promise<VerifiedSseMessage | null> {
    if (this.ended) this.fail('event-after-end')
    if (++this.events > this.maxEvents) this.fail('too-many-events')

    const received = await receiveEnvelope(event.data, this.receiveOptions)
    if (!received.ok || !received.envelope) {
      this.fail('verification-failed', received.diagnostics.find((d) => d.level === 'error')?.message)
    }
    const env = received.envelope
    if (env.header.sender !== this.options.peerAgentId) this.fail('wrong-sender', env.header.sender)
    if (env.header.recipient !== this.options.selfAgentId) this.fail('wrong-recipient', env.header.recipient)
    if (this.options.expectCorrelationId !== undefined && env.body.correlationId !== this.options.expectCorrelationId) {
      this.fail('stream-mismatch', 'correlationId')
    }

    let payload: { stream?: unknown; seq?: unknown; message?: unknown; end?: unknown; count?: unknown }
    try {
      payload = JSON.parse(env.body.content) as typeof payload
    } catch {
      this.fail('malformed-event')
    }
    if (typeof payload !== 'object' || payload === null || typeof payload.stream !== 'string' || typeof payload.seq !== 'number') {
      this.fail('malformed-event')
    }
    if (this.streamId === undefined) this.streamId = payload.stream
    else if (payload.stream !== this.streamId) this.fail('stream-mismatch', 'stream id')
    if (payload.seq !== this.expectedSeq) this.fail('sequence-error', `expected ${this.expectedSeq}, got ${String(payload.seq)}`)
    this.expectedSeq++

    if (payload.end === true) {
      if (payload.count !== payload.seq) this.fail('count-mismatch', `end says ${String(payload.count)}, saw ${payload.seq}`)
      this.ended = true
      return null
    }
    const msg = payload.message
    if (typeof msg !== 'object' || msg === null || Array.isArray(msg) || (msg as { jsonrpc?: unknown }).jsonrpc !== '2.0') {
      this.fail('malformed-event', 'message is not JSON-RPC 2.0')
    }
    return { seq: payload.seq, message: msg as McpMessage }
  }

  /**
   * Call when the transport closes. Throws if the stream did not finish with its
   * signed end event: silence is not proof of completion.
   */
  finish(): void {
    if (this.failed) throw this.failed
    if (!this.ended) throw new SseVerificationError('stream-truncated')
  }
}

/** Verify a whole body delivered as an async iterable or web stream. Yields messages; throws on any violation, including truncation. */
export async function* readSignedSse(
  source: AsyncIterable<string | Uint8Array> | ReadableStream<Uint8Array | string>,
  options: SignedSseReaderOptions,
): AsyncGenerator<VerifiedSseMessage> {
  const reader = new SignedSseReader(options)
  const decoder = new TextDecoder('utf-8', { fatal: true })
  const iterable: AsyncIterable<string | Uint8Array> =
    Symbol.asyncIterator in source
      ? (source as AsyncIterable<string | Uint8Array>)
      : (async function* () {
          const r = (source as ReadableStream<Uint8Array | string>).getReader()
          try {
            for (;;) {
              const { done, value } = await r.read()
              if (done) return
              yield value
            }
          } finally {
            r.releaseLock()
          }
        })()
  for await (const chunk of iterable) {
    let text: string
    try {
      text = typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true })
    } catch {
      throw new SseVerificationError('malformed-event', 'invalid UTF-8')
    }
    for (const m of await reader.feed(text)) yield m
  }
  reader.finish()
}
