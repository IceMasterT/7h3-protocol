import {
  signEnvelopeEd25519, verifyEnvelopeEd25519,
  createEnvelope, validateEnvelope,
  generateEd25519KeypairBase64Url, type ProtocolEnvelope
} from './protocol'
import type { KeyRegistry } from './keyRegistry'
import type { ReplayCache } from './protocolReplay'
import {
  SignedStreamWriter,
  verifyStream,
  decodeStreamChunk,
  encodeStreamChunk,
  type StreamSignerOpts,
  type StreamVerifierOpts,
  type StreamVerifyResult,
  type StreamChunk,
} from './stream'

export { type KeyRegistry, generateEd25519KeypairBase64Url }
export type { StreamSignerOpts, StreamVerifierOpts, StreamVerifyResult, StreamChunk }

// Minimal WebSocket interface (works with browser WebSocket, ws library, etc.)
export type WsMessageHandler = (e: { data: string | Buffer }) => void
export type WsCloseHandler = () => void

export interface WebSocketLike {
  send(data: string): void
  addEventListener(event: 'message', handler: WsMessageHandler): void
  addEventListener(event: 'close', handler: WsCloseHandler): void
  removeEventListener(event: 'message' | 'close', handler: WsMessageHandler | WsCloseHandler): void
  readyState?: number
}

export interface WsBindingOptions {
  privateKey: string
  sender: string
  recipient?: string
  keyRegistry: KeyRegistry   // to look up peer public keys by sender ID
  ttlMs?: number             // per-frame TTL, default 30_000
  onVerifyFail?: (err: Error, rawData: string) => void
  /**
   * Optional — signature+TTL alone don't stop a captured frame from being
   * replayed verbatim any number of times within its TTL window. Pass an
   * InMemoryReplayCache (or a distributed one) to dedupe incoming frames by
   * sender/messageId/nonce, same as the HTTP gateway does.
   */
  replayCache?: ReplayCache
}

export interface ProtectedWebSocket {
  // Send a payload — automatically signs it
  send(payload: unknown): Promise<void>
  // Register handler for verified incoming messages
  onMessage(handler: (payload: unknown, envelope: ProtocolEnvelope) => void): void
  // Register handler for verify failures (optional)
  onVerifyFail(handler: (err: Error, rawData: string) => void): void
  // Sequence number of last sent message
  readonly seq: number
}

export function wrapWebSocket(ws: WebSocketLike, opts: WsBindingOptions): ProtectedWebSocket {
  let seq = 0
  const messageHandlers: Array<(payload: unknown, envelope: ProtocolEnvelope) => void> = []
  const failHandlers: Array<(err: Error, rawData: string) => void> = []

  function fireVerifyFail(err: Error, raw: string) {
    opts.onVerifyFail?.(err, raw)
    for (const h of failHandlers) h(err, raw)
  }

  // Listen for incoming frames
  const messageListener = async (e: { data: string | Buffer }) => {
    const raw = typeof e.data === 'string' ? e.data : e.data.toString('utf8')
    let envelope: ProtocolEnvelope
    try { envelope = JSON.parse(raw) as ProtocolEnvelope }
    catch { fireVerifyFail(new Error('malformed frame'), raw); return }

    const sender = envelope?.header?.sender
    if (!sender) { fireVerifyFail(new Error('missing sender'), raw); return }

    const publicKey = await opts.keyRegistry.getPublicKey(sender)
    if (!publicKey) { fireVerifyFail(new Error(`unknown sender: ${sender}`), raw); return }

    const valid = await verifyEnvelopeEd25519(envelope, publicKey).catch(() => false)
    if (!valid) { fireVerifyFail(new Error('invalid signature'), raw); return }

    const diags = validateEnvelope(envelope)
    if (diags.some(d => d.level === 'error')) {
      fireVerifyFail(new Error(`envelope invalid: ${diags.map(d => d.message).join('; ')}`), raw)
      return
    }

    if (opts.replayCache) {
      const replayResult = await opts.replayCache.consume(envelope)
      if (!replayResult.ok) {
        fireVerifyFail(new Error(replayResult.reason ?? 'replay detected'), raw)
        return
      }
    }

    let payload: unknown = envelope.body.content
    try { payload = JSON.parse(envelope.body.content) } catch { /* keep as string */ }
    for (const h of messageHandlers) h(payload, envelope)
  }

  ws.addEventListener('message', messageListener)
  ws.addEventListener('close', () => {
    ws.removeEventListener('message', messageListener)
  })

  return {
    get seq() { return seq },
    async send(payload: unknown): Promise<void> {
      const content = typeof payload === 'string' ? payload : JSON.stringify(payload)
      // embed sequence number in correlationId to help downstream ordering
      const envelope = createEnvelope({
        sender: opts.sender,
        recipient: opts.recipient,
        ttlMs: opts.ttlMs ?? 30_000,
        intent: 'TASK',
        content,
        correlationId: String(++seq),
      })
      const signed = await signEnvelopeEd25519(envelope, opts.privateKey)
      ws.send(JSON.stringify(signed))
    },
    onMessage(handler) { messageHandlers.push(handler) },
    onVerifyFail(handler) { failHandlers.push(handler) },
  }
}

// ─────────────────── Stream signing over WebSocket ────────────────────────────

/**
 * createSignedWebSocketStream
 *
 * Attaches a SignedStreamWriter to a WebSocket:
 *   - Each incoming WebSocket message is signed as a stream chunk and sent back.
 *   - On connection close, the final signed frame is sent.
 *
 * Returns the underlying SignedStreamWriter so callers can also call writeChunk
 * directly (e.g. when driving the stream from application code rather than
 * forwarding received messages).
 */
export function createSignedWebSocketStream(
  ws: WebSocketLike,
  opts: StreamSignerOpts,
): SignedStreamWriter {
  const writer = new SignedStreamWriter(opts)

  const messageListener = async (e: { data: string | Buffer }) => {
    const data = typeof e.data === 'string' ? e.data : e.data.toString('utf8')
    const chunk = await writer.writeChunk(data)
    ws.send(encodeStreamChunk(chunk))
  }

  const closeListener = async () => {
    ws.removeEventListener('message', messageListener)
    ws.removeEventListener('close', closeListener)
    const finalChunk = await writer.finalize()
    ws.send(encodeStreamChunk(finalChunk))
  }

  ws.addEventListener('message', messageListener)
  ws.addEventListener('close', closeListener)

  return writer
}

/**
 * receiveSignedWebSocketStream
 *
 * Listens for StreamChunk JSON frames on a WebSocket, accumulates them, and
 * when the final frame (f=true) arrives calls verifyStream over the complete
 * set of collected chunks.
 *
 * Resolves with StreamVerifyResult when the final frame is received.
 * Rejects if a frame cannot be decoded.
 */
export function receiveSignedWebSocketStream(
  ws: WebSocketLike,
  opts: StreamVerifierOpts,
): Promise<StreamVerifyResult> {
  return new Promise<StreamVerifyResult>((resolve, reject) => {
    const collected: StreamChunk[] = []

    const messageListener = async (e: { data: string | Buffer }) => {
      const raw = typeof e.data === 'string' ? e.data : e.data.toString('utf8')
      let chunk: StreamChunk
      try {
        chunk = decodeStreamChunk(raw)
      } catch (err) {
        cleanup()
        reject(err)
        return
      }
      collected.push(chunk)
      if (chunk.f) {
        cleanup()
        const result = await verifyStream(collected, opts)
        resolve(result)
      }
    }

    const closeListener = () => {
      // Connection closed before receiving final frame
      cleanup()
      resolve({ ok: false, reason: 'connection closed before final frame' })
    }

    function cleanup() {
      ws.removeEventListener('message', messageListener)
      ws.removeEventListener('close', closeListener)
    }

    ws.addEventListener('message', messageListener)
    ws.addEventListener('close', closeListener)
  })
}
