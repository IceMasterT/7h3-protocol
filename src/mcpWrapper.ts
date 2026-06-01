import { createEnvelope, type ProtocolEnvelope } from './protocol'
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
 * Verification reuses the full transport pipeline (`receiveEnvelope`), so it
 * composes directly with a Redis-backed replay cache (`createRedisReplayStore`)
 * and fleet-wide revocation (`withRevocationCheck`) via the `receive` options.
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
  /** This peer's agent id, used as the envelope `sender`. */
  selfAgentId: string
  /** The peer's agent id, used as the envelope `recipient` (client side). */
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

function jsonRpcError(id: JsonRpcId, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: '2.0', id, error: { code, message } }
}

/**
 * Wraps an existing MCP JSON-RPC handler so every inbound message is verified
 * (signature + replay + TTL) before the handler runs, and every response is
 * signed. Returns a function over the AIP wire envelope.
 */
export function wrapMcpServer(handler: McpJsonRpcHandler, options: McpSecurityOptions): (raw: WireEnvelope) => Promise<WireEnvelope> {
  const wireFormat = options.wireFormat ?? 'compact'
  const ttlMs = options.ttlMs ?? 60_000

  async function signAndEncode(envelope: Omit<ProtocolEnvelope, 'signature'>): Promise<WireEnvelope> {
    return encodeEnvelope(await options.sign(envelope), wireFormat)
  }

  function reply(recipient: string | undefined, intent: 'RESULT' | 'ERROR', response: JsonRpcResponse, correlationId?: string) {
    return signAndEncode(
      createEnvelope({ sender: options.selfAgentId, recipient, intent, content: JSON.stringify(response), correlationId, ttlMs }),
    )
  }

  return async (raw: WireEnvelope): Promise<WireEnvelope> => {
    const received = await receiveEnvelope(raw, { requireSignature: true, ...options.receive })
    const senderHint = received.envelope?.header.sender

    if (!received.ok || !received.envelope) {
      const reason = received.diagnostics.find((d) => d.level === 'error')?.message ?? 'AIP verification failed'
      return reply(senderHint, 'ERROR', jsonRpcError(null, -32600, reason))
    }

    let request: JsonRpcRequest
    try {
      request = JSON.parse(received.envelope.body.content) as JsonRpcRequest
    } catch {
      return reply(senderHint, 'ERROR', jsonRpcError(null, -32700, 'Parse error: envelope body is not JSON-RPC'), received.envelope.header.messageId)
    }

    let response: JsonRpcResponse
    try {
      response = await handler(request)
    } catch (error) {
      response = jsonRpcError(request.id ?? null, -32603, error instanceof Error ? error.message : 'Internal error')
    }
    return reply(received.envelope.header.sender, 'RESULT', response, received.envelope.header.messageId)
  }
}

export interface McpClientCodec {
  encodeRequest(request: JsonRpcRequest): Promise<WireEnvelope>
  decodeResponse(raw: WireEnvelope): Promise<JsonRpcResponse>
}

/** Signs outbound requests and verifies inbound responses. */
export function createMcpClientCodec(options: McpSecurityOptions): McpClientCodec {
  const wireFormat = options.wireFormat ?? 'compact'
  const ttlMs = options.ttlMs ?? 60_000

  return {
    async encodeRequest(request: JsonRpcRequest): Promise<WireEnvelope> {
      const envelope = createEnvelope({
        sender: options.selfAgentId,
        recipient: options.peerAgentId,
        intent: 'TASK',
        content: JSON.stringify(request),
        ttlMs,
      })
      return encodeEnvelope(await options.sign(envelope), wireFormat)
    },

    async decodeResponse(raw: WireEnvelope): Promise<JsonRpcResponse> {
      const received = await receiveEnvelope(raw, { requireSignature: true, ...options.receive })
      if (!received.ok || !received.envelope) {
        const reason = received.diagnostics.find((d) => d.level === 'error')?.message ?? 'unknown'
        throw new Error(`AIP response verification failed: ${reason}`)
      }
      return JSON.parse(received.envelope.body.content) as JsonRpcResponse
    },
  }
}

/**
 * Wraps a transport send function (`stdio`, HTTP, ...) so callers issue and
 * receive plain JSON-RPC while AIP signing/verification happens on the wire.
 */
export function wrapMcpClient(
  send: (raw: WireEnvelope) => Promise<WireEnvelope>,
  options: McpSecurityOptions,
): (request: JsonRpcRequest) => Promise<JsonRpcResponse> {
  const codec = createMcpClientCodec(options)
  return async (request: JsonRpcRequest): Promise<JsonRpcResponse> => codec.decodeResponse(await send(await codec.encodeRequest(request)))
}
