import { type AipAgentAdapter } from './agentAdapter'
import { type ProtocolEnvelope } from './protocol'
import { type WireEnvelope } from './protocolTransport'

export interface LangChainMessageLike {
  content: string
  name?: string
  additionalKwargs?: Record<string, unknown>
}

export interface LlamaIndexMessageLike {
  role: 'user' | 'assistant' | 'system'
  content: string
  additionalKwargs?: Record<string, unknown>
}

export interface JsonRpcError {
  code: number
  message: string
  data?: unknown
}

export interface JsonRpcRequestLike {
  jsonrpc: '2.0'
  id: string | number
  method: string
  params?: unknown
}

export interface JsonRpcResponseLike {
  jsonrpc: '2.0'
  id: string | number
  result?: unknown
  error?: JsonRpcError
}

export interface JsonRpcBridgeOptions {
  recipient?: string
  allowedMethods?: readonly string[]
  methodToCapability?: (method: string) => string
  authorizeMethod?: (request: JsonRpcRequestLike, context: JsonRpcPolicyContext) => boolean | Promise<boolean>
  rateLimitKey?: (request: JsonRpcRequestLike, context: JsonRpcPolicyContext) => string
  rateLimiter?: {
    consume: (key: string, request: JsonRpcRequestLike, context: JsonRpcPolicyContext) => boolean | Promise<boolean>
  }
  onPolicyEvent?: (event: JsonRpcPolicyEvent) => void | Promise<void>
}

export interface JsonRpcPolicyContext {
  intent: 'TASK'
  recipient?: string
  capability: string
  correlationId: string
  createdAtMs: number
}

export interface JsonRpcPolicyEvent {
  stage: 'allowlist' | 'authorize' | 'rateLimit'
  decision: 'allow' | 'deny'
  method: string
  context: JsonRpcPolicyContext
  reason?: string
}

export interface JsonRpcResponseOptions {
  defaultErrorCode?: number
}

export async function createRawTaskFromLangChain(
  adapter: AipAgentAdapter,
  message: LangChainMessageLike,
  options: { recipient?: string; capability?: string; correlationId?: string } = {},
): Promise<WireEnvelope> {
  return adapter.createRawIntent({
    recipient: options.recipient,
    intent: 'TASK',
    content: message.content,
    capability: options.capability,
    correlationId: options.correlationId,
  })
}

export function toLangChainMessage(envelope: ProtocolEnvelope): LangChainMessageLike {
  return {
    content: envelope.body.content,
    name: envelope.body.intent,
    additionalKwargs: {
      capability: envelope.body.capability,
      correlationId: envelope.body.correlationId,
      sender: envelope.header.sender,
      recipient: envelope.header.recipient,
      messageId: envelope.header.messageId,
      timestampMs: envelope.header.timestampMs,
    },
  }
}

export async function createRawTaskFromLlamaIndex(
  adapter: AipAgentAdapter,
  message: LlamaIndexMessageLike,
  options: { recipient?: string; capability?: string; correlationId?: string } = {},
): Promise<WireEnvelope> {
  return adapter.createRawIntent({
    recipient: options.recipient,
    intent: 'TASK',
    content: message.content,
    capability: options.capability,
    correlationId: options.correlationId,
  })
}

export function toLlamaIndexMessage(envelope: ProtocolEnvelope): LlamaIndexMessageLike {
  const role: LlamaIndexMessageLike['role'] = envelope.body.intent === 'TASK' ? 'user' : 'assistant'
  return {
    role,
    content: envelope.body.content,
    additionalKwargs: {
      intent: envelope.body.intent,
      capability: envelope.body.capability,
      correlationId: envelope.body.correlationId,
      sender: envelope.header.sender,
      recipient: envelope.header.recipient,
    },
  }
}

function createMcpCapability(method: string): string {
  return `mcp.${method}`
}

export async function createRawTaskFromJsonRpc(
  adapter: AipAgentAdapter,
  request: JsonRpcRequestLike,
  options: JsonRpcBridgeOptions = {},
): Promise<WireEnvelope> {
  async function emitPolicyEvent(event: JsonRpcPolicyEvent): Promise<void> {
    if (options.onPolicyEvent) await options.onPolicyEvent(event)
  }

  if (options.allowedMethods && !options.allowedMethods.includes(request.method)) {
    const capability = options.methodToCapability
      ? options.methodToCapability(request.method)
      : createMcpCapability(request.method)
    const blockedContext: JsonRpcPolicyContext = {
      intent: 'TASK',
      recipient: options.recipient,
      capability,
      correlationId: String(request.id),
      createdAtMs: Date.now(),
    }
    await emitPolicyEvent({
      stage: 'allowlist',
      decision: 'deny',
      method: request.method,
      context: blockedContext,
      reason: 'method_not_allowed',
    })
    throw new Error(`JSON-RPC method '${request.method}' is not allowed`)
  }

  const capability = options.methodToCapability
    ? options.methodToCapability(request.method)
    : createMcpCapability(request.method)
  const context: JsonRpcPolicyContext = {
    intent: 'TASK',
    recipient: options.recipient,
    capability,
    correlationId: String(request.id),
    createdAtMs: Date.now(),
  }

  await emitPolicyEvent({
    stage: 'allowlist',
    decision: 'allow',
    method: request.method,
    context,
  })

  if (options.authorizeMethod) {
    const authorized = await options.authorizeMethod(request, context)
    if (!authorized) {
      await emitPolicyEvent({
        stage: 'authorize',
        decision: 'deny',
        method: request.method,
        context,
        reason: 'not_authorized',
      })
      throw new Error(`JSON-RPC method '${request.method}' is not authorized`)
    }
    await emitPolicyEvent({
      stage: 'authorize',
      decision: 'allow',
      method: request.method,
      context,
    })
  }

  if (options.rateLimiter) {
    const key = options.rateLimitKey ? options.rateLimitKey(request, context) : request.method
    const allowed = await options.rateLimiter.consume(key, request, context)
    if (!allowed) {
      await emitPolicyEvent({
        stage: 'rateLimit',
        decision: 'deny',
        method: request.method,
        context,
        reason: 'rate_limited',
      })
      throw new Error(`JSON-RPC method '${request.method}' is rate-limited`)
    }
    await emitPolicyEvent({
      stage: 'rateLimit',
      decision: 'allow',
      method: request.method,
      context,
    })
  }

  return adapter.createRawIntent({
    recipient: options.recipient,
    intent: 'TASK',
    capability,
    correlationId: String(request.id),
    content: JSON.stringify({ method: request.method, params: request.params ?? null }),
  })
}

export function toJsonRpcResponse(
  envelope: ProtocolEnvelope,
  id: string | number,
  options: JsonRpcResponseOptions = {},
): JsonRpcResponseLike {
  if (envelope.body.intent === 'ERROR') {
    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: options.defaultErrorCode ?? -32000,
        message: envelope.body.content,
        data: {
          capability: envelope.body.capability,
          correlationId: envelope.body.correlationId,
        },
      },
    }
  }

  let result: unknown
  try {
    result = JSON.parse(envelope.body.content)
  } catch {
    result = envelope.body.content
  }

  return {
    jsonrpc: '2.0',
    id,
    result,
  }
}
