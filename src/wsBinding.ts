import {
  signEnvelopeEd25519, verifyEnvelopeEd25519,
  createEnvelope, validateEnvelope,
  generateEd25519KeypairBase64Url, type ProtocolEnvelope
} from './protocol'
import type { KeyRegistry } from './keyRegistry'

export { type KeyRegistry, generateEd25519KeypairBase64Url }

// Minimal WebSocket interface (works with browser WebSocket, ws library, etc.)
export interface WebSocketLike {
  send(data: string): void
  addEventListener(event: 'message', handler: (e: { data: string | Buffer }) => void): void
  addEventListener(event: 'close', handler: () => void): void
  removeEventListener(event: string, handler: (...args: unknown[]) => void): void
  readyState?: number
}

export interface WsBindingOptions {
  privateKey: string
  sender: string
  recipient?: string
  keyRegistry: KeyRegistry   // to look up peer public keys by sender ID
  ttlMs?: number             // per-frame TTL, default 30_000
  onVerifyFail?: (err: Error, rawData: string) => void
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
    catch (err) { fireVerifyFail(new Error('malformed frame'), raw); return }

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

    let payload: unknown = envelope.body.content
    try { payload = JSON.parse(envelope.body.content) } catch { /* keep as string */ }
    for (const h of messageHandlers) h(payload, envelope)
  }

  ws.addEventListener('message', messageListener as any)
  ws.addEventListener('close', () => {
    ws.removeEventListener('message', messageListener as any)
  })

  return {
    get seq() { return seq },
    async send(payload: unknown): Promise<void> {
      const content = typeof payload === 'string' ? payload : JSON.stringify(payload)
      const envelope = createEnvelope({
        sender: opts.sender,
        recipient: opts.recipient,
        ttlMs: opts.ttlMs ?? 30_000,
        intent: 'TASK',
        content,
      })
      // embed sequence number in correlationId to help downstream ordering
      ;(envelope.body as any).correlationId = String(++seq)
      const signed = await signEnvelopeEd25519(envelope, opts.privateKey)
      ws.send(JSON.stringify(signed))
    },
    onMessage(handler) { messageHandlers.push(handler) },
    onVerifyFail(handler) { failHandlers.push(handler) },
  }
}
