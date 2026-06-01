import { createEnvelope, type ProtocolEnvelope } from './protocol'
import { InMemoryReplayCache } from './protocolReplay'
import {
  encodeEnvelope,
  receiveEnvelope,
  type ReceiveEnvelopeOptions,
  type WireEnvelope,
  type WireFormat,
} from './protocolTransport'

/**
 * MCP hardening middleware.
 *
 * MCP messages are plain JSON-RPC 2.0 and, as shipped, carry no signature or
 * replay protection. These wrappers put an AIP envelope around each message on
 * the wire — signing, TTL-bounding, and replay-checking every request and
 * response — while the underlying MCP handler still receives plain JSON-RPC.
 * "Zero app changes": your handler signature does not change.
 *
 * The wrappers enforce four bindings beyond signature verification:
 *   - recipient binding: the server only runs the handler when the envelope is
 *     addressed to it (`recipient === selfAgentId`) — defeats cross-server relay.
 *   - sender binding: the client only accepts responses from its expected peer
 *     (`sender === peerAgentId`) — defeats response spoofing.
 *   - correlation binding: the client only accepts a response whose
 *     `correlationId` matches the request it sent — defeats response substitution.
 *   - replay protection on by default (an `InMemoryReplayCache` if none supplied).
 *
 * Verification reuses the transport pipeline (`receiveEnvelope`), so it composes
 * directly with a Redis-backed replay cache (`createRedisReplayStore`) and
 * fleet-wide revocation (`withRevocationCheck`) via the `receive` options.
 */

export type JsonRpcId = string | number | null

export interface JsonRpcRequest {
  jsonrpc: '2.0'
  id: JsonRpcId
  method: string
  params?: unknown
}

export interface JsonRpcResponse {
  jsonrpc: '2.0'
  id: JsonRpcId
  result?: unknown
  error?: { code: number; message: string; data?: unknown }
}

export type McpJsonRpcHandler = (request: JsonRpcRequest) => JsonRpcResponse | Promise<JsonRpcResponse>

export interface McpSecurityOptions {
  /** This peer's agent id, used as the envelope `sender` and enforced as the inbound `recipient`. */
  selfAgentId: string
  /** The peer's agent id: set as the envelope `recipient` (client) and enforced as the response `sender`. */
  peerAgentId?: string
  /** Signs an unsigned envelope, e.g. `(e) => signEnvelopeHmac(e, secret, keyId)`. */
  sign: (envelope: Omit<ProtocolEnvelope, 'signature'>) => Promise<ProtocolEnvelope>
  /** Inbound verification options: signature material resolver, replay cache, clock skew, etc. */
  receive?: ReceiveEnvelopeOptions
  /** Wire format for the envelope on the wire. Default `compact`. */
  wireFormat?: WireFormat
  /** Envelope TTL in ms. Default 60_000. */
  ttlMs?: number
}

export interface EncodedRequest {
  raw: WireEnvelope
  /** The envelope `messageId` generated for this request; bind the response's `correlationId` to it. */
  messageId: string
}

export interface DecodeResponseOptions {
  /** When set, require the response `correlationId` to equal this value (the request's messageId). */
  expectCorrelationId?: string
}

function jsonRpcError(id: JsonRpcId, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: '2.0', id, error: { code, message } }
}

/** Verification options with signature required and a replay cache guaranteed (secure defaults). */
function hardenedReceive(options: McpSecurityOptions, replayCache: ReceiveEnvelopeOptions['replayCache']): ReceiveEnvelopeOptions {
  return { requireSignature: true, ...options.receive, replayCache }
}

/**
 * Wraps an existing MCP JSON-RPC handler so every inbound message is verified
 * (signature + replay + TTL + recipient binding) before the handler runs, and
 * every response is signed. Returns a function over the AIP wire envelope.
 */
export function wrapMcpServer(handler: McpJsonRpcHandler, options: McpSecurityOptions): (raw: WireEnvelope) => Promise<WireEnvelope> {
  const wireFormat = options.wireFormat ?? 'compact'
  const ttlMs = options.ttlMs ?? 60_000
  // Replay protection is on by default; supply a Redis-backed cache via options.receive for scale.
  const replayCache = options.receive?.replayCache ?? new InMemoryReplayCache()
  const receiveOptions = hardenedReceive(options, replayCache)

  async function signAndEncode(envelope: Omit<ProtocolEnvelope, 'signature'>): Promise<WireEnvelope> {
    return encodeEnvelope(await options.sign(envelope), wireFormat)
  }

  function reply(recipient: string | undefined, intent: 'RESULT' | 'ERROR', response: JsonRpcResponse, correlationId?: string) {
    return signAndEncode(
      createEnvelope({ sender: options.selfAgentId, recipient, intent, content: JSON.stringify(response), correlationId, ttlMs }),
    )
  }

  return async (raw: WireEnvelope): Promise<WireEnvelope> => {
    const received = await receiveEnvelope(raw, receiveOptions)
    const senderHint = received.envelope?.header.sender
    const correlationId = received.envelope?.header.messageId

    if (!received.ok || !received.envelope) {
      const reason = received.diagnostics.find((d) => d.level === 'error')?.message ?? 'AIP verification failed'
      return reply(senderHint, 'ERROR', jsonRpcError(null, -32600, reason), correlationId)
    }

    // Recipient binding: refuse to act on an envelope not addressed to this agent.
    if (received.envelope.header.recipient !== options.selfAgentId) {
      return reply(senderHint, 'ERROR', jsonRpcError(null, -32600, 'Recipient mismatch: envelope not addressed to this agent'), correlationId)
    }

    let request: JsonRpcRequest
    try {
      request = JSON.parse(received.envelope.body.content) as JsonRpcRequest
    } catch {
      return reply(senderHint, 'ERROR', jsonRpcError(null, -32700, 'Parse error: envelope body is not JSON-RPC'), correlationId)
    }

    let response: JsonRpcResponse
    try {
      response = await handler(request)
    } catch (error) {
      response = jsonRpcError(request.id ?? null, -32603, error instanceof Error ? error.message : 'Internal error')
    }
    return reply(received.envelope.header.sender, 'RESULT', response, correlationId)
  }
}

export interface McpClientCodec {
  encodeRequest(request: JsonRpcRequest): Promise<EncodedRequest>
  decodeResponse(raw: WireEnvelope, options?: DecodeResponseOptions): Promise<JsonRpcResponse>
}

/** Signs outbound requests and verifies inbound responses (with sender + correlation binding). */
export function createMcpClientCodec(options: McpSecurityOptions): McpClientCodec {
  const wireFormat = options.wireFormat ?? 'compact'
  const ttlMs = options.ttlMs ?? 60_000
  const replayCache = options.receive?.replayCache ?? new InMemoryReplayCache()
  const receiveOptions = hardenedReceive(options, replayCache)

  return {
    async encodeRequest(request: JsonRpcRequest): Promise<EncodedRequest> {
      const envelope = createEnvelope({
        sender: options.selfAgentId,
        recipient: options.peerAgentId,
        intent: 'TASK',
        content: JSON.stringify(request),
        ttlMs,
      })
      return { raw: encodeEnvelope(await options.sign(envelope), wireFormat), messageId: envelope.header.messageId }
    },

    async decodeResponse(raw: WireEnvelope, decodeOptions: DecodeResponseOptions = {}): Promise<JsonRpcResponse> {
      const received = await receiveEnvelope(raw, receiveOptions)
      if (!received.ok || !received.envelope) {
        const reason = received.diagnostics.find((d) => d.level === 'error')?.message ?? 'unknown'
        throw new Error(`AIP response verification failed: ${reason}`)
      }

      // Sender binding: the response must come from the expected peer.
      if (!options.peerAgentId) {
        throw new Error('createMcpClientCodec requires peerAgentId to bind the response sender')
      }
      if (received.envelope.header.sender !== options.peerAgentId) {
        throw new Error(`AIP response sender '${received.envelope.header.sender}' is not the expected peer '${options.peerAgentId}'`)
      }

      // Correlation binding: the response must answer the request we sent.
      if (decodeOptions.expectCorrelationId !== undefined && received.envelope.body.correlationId !== decodeOptions.expectCorrelationId) {
        throw new Error(
          `AIP response correlationId '${received.envelope.body.correlationId ?? ''}' does not match request '${decodeOptions.expectCorrelationId}'`,
        )
      }

      return JSON.parse(received.envelope.body.content) as JsonRpcResponse
    },
  }
}

/**
 * Wraps a transport send function (`stdio`, HTTP, ...) so callers issue and
 * receive plain JSON-RPC while AIP signing, verification, and request/response
 * correlation happen on the wire.
 */
export function wrapMcpClient(
  send: (raw: WireEnvelope) => Promise<WireEnvelope>,
  options: McpSecurityOptions,
): (request: JsonRpcRequest) => Promise<JsonRpcResponse> {
  const codec = createMcpClientCodec(options)
  return async (request: JsonRpcRequest): Promise<JsonRpcResponse> => {
    const { raw, messageId } = await codec.encodeRequest(request)
    return codec.decodeResponse(await send(raw), { expectCorrelationId: messageId })
  }
}
