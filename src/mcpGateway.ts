import { createAipAgentAdapter } from './agentAdapter'
import { bootstrapRuntimePolicyEnforcer, type BootstrapRuntimePolicyEnforcerOptions } from './policyEnforcer'
import {
  createRawTaskFromJsonRpc,
  type JsonRpcPolicyEvent,
  toJsonRpcResponse,
  type JsonRpcBridgeOptions,
  type JsonRpcRequestLike,
} from './frameworkAdapters'
import { type WireEnvelope } from './protocolTransport'

export interface AipMcpGatewayOptions {
  sharedSecret: string
  gatewayAgentId?: string
  workerAgentId?: string
  allowedMethods?: readonly string[]
  workerCapabilityPrefix?: string
  methodToCapability?: JsonRpcBridgeOptions['methodToCapability']
  authorizeMethod?: JsonRpcBridgeOptions['authorizeMethod']
  rateLimitKey?: JsonRpcBridgeOptions['rateLimitKey']
  rateLimiter?: JsonRpcBridgeOptions['rateLimiter']
  onAuditEvent?: (event: AipMcpGatewayAuditEvent) => void | Promise<void>
  gatewayWireFormat?: 'json' | 'compact' | 'binary'
  workerWireFormat?: 'json' | 'compact' | 'binary'
  runtimePolicy?: {
    enabled?: boolean
    options?: BootstrapRuntimePolicyEnforcerOptions
    concurrencyHint?: number
    latencySensitive?: boolean
    compatibilityFirst?: boolean
  }
}

export interface AipMcpGatewayRuntime {
  handleLine: (line: string) => Promise<string | null>
}

export interface AipMcpGatewayAuditEvent {
  phase: 'request_received' | 'policy' | 'verification_failed' | 'request_success' | 'request_error'
  id?: string | number | null
  method?: string
  code?: number
  message?: string
  policy?: JsonRpcPolicyEvent
  timestampMs: number
}

const DEFAULT_ALLOWED_METHODS = ['tools/call', 'resources/read', 'prompts/get']

function jsonString(value: unknown): string {
  return JSON.stringify(value)
}

function createErrorResponse(id: string | number | null, code: number, message: string): string {
  return jsonString({
    jsonrpc: '2.0',
    id,
    error: { code, message },
  })
}

function parseRequest(raw: string): JsonRpcRequestLike | null {
  const parsed = JSON.parse(raw) as Partial<JsonRpcRequestLike>
  if (parsed.jsonrpc !== '2.0') return null
  if (typeof parsed.method !== 'string' || parsed.method.length === 0) return null
  if (typeof parsed.id !== 'string' && typeof parsed.id !== 'number') return null

  return {
    jsonrpc: '2.0',
    id: parsed.id,
    method: parsed.method,
    params: parsed.params,
  }
}

function mapBridgeErrorCode(message: string): number {
  if (message.includes('not allowed')) return -32601
  if (message.includes('not authorized')) return -32001
  if (message.includes('rate-limited')) return -32002
  return -32603
}

export function createAipMcpGatewayRuntime(options: AipMcpGatewayOptions): AipMcpGatewayRuntime {
  const gatewayAgentId = options.gatewayAgentId ?? 'agent.gateway'
  const workerAgentId = options.workerAgentId ?? 'agent.worker'
  const allowedMethods = options.allowedMethods ?? DEFAULT_ALLOWED_METHODS
  const workerCapabilityPrefix = options.workerCapabilityPrefix ?? 'mcp.'
  const gatewayWireFormat = options.gatewayWireFormat ?? 'compact'
  const workerWireFormat = options.workerWireFormat ?? 'compact'

  async function emitAuditEvent(event: Omit<AipMcpGatewayAuditEvent, 'timestampMs'>): Promise<void> {
    if (options.onAuditEvent) {
      await options.onAuditEvent({
        ...event,
        timestampMs: Date.now(),
      })
    }
  }

  const gateway = createAipAgentAdapter({
    agentId: gatewayAgentId,
    outboundSecret: options.sharedSecret,
    sharedSecrets: { [workerAgentId]: options.sharedSecret },
    wireFormat: gatewayWireFormat,
  })

  const worker = createAipAgentAdapter({
    agentId: workerAgentId,
    outboundSecret: options.sharedSecret,
    sharedSecrets: { [gatewayAgentId]: options.sharedSecret },
    wireFormat: workerWireFormat,
    onTask: async (envelope) => ({
      intent: 'RESULT',
      content: jsonString({
        ok: true,
        capability: envelope.body.capability,
        content: envelope.body.content,
      }),
      capability: envelope.body.capability?.startsWith(workerCapabilityPrefix)
        ? envelope.body.capability
        : `${workerCapabilityPrefix}${envelope.body.capability ?? 'unknown'}`,
    }),
  })

  return {
    async handleLine(line: string): Promise<string | null> {
      const raw = line.trim()
      if (!raw) return null

      let id: string | number | null = null
      try {
        const request = parseRequest(raw)
        if (!request) {
          await emitAuditEvent({
            phase: 'request_error',
            code: -32600,
            message: 'Invalid Request',
          })
          return createErrorResponse(null, -32600, 'Invalid Request')
        }
        id = request.id
        await emitAuditEvent({
          phase: 'request_received',
          id: request.id,
          method: request.method,
        })

        const bridgeOptions: JsonRpcBridgeOptions = {
          recipient: workerAgentId,
          allowedMethods,
          methodToCapability: options.methodToCapability,
          authorizeMethod: options.authorizeMethod,
          rateLimitKey: options.rateLimitKey,
          rateLimiter: options.rateLimiter,
          onPolicyEvent: async (event) => {
            await emitAuditEvent({
              phase: 'policy',
              id: request.id,
              method: request.method,
              policy: event,
            })
          },
        }

        const outbound = await createRawTaskFromJsonRpc(gateway, request, bridgeOptions)
        let rawResponse: WireEnvelope | null = null
        await worker.handleRaw(outbound, async (responseRaw) => {
          rawResponse = responseRaw
        })
        if (!rawResponse) {
          await emitAuditEvent({
            phase: 'verification_failed',
            id: request.id,
            method: request.method,
            code: -32603,
            message: 'AIP worker did not produce a response',
          })
          return createErrorResponse(id, -32603, 'AIP worker did not produce a response')
        }

        const verified = await gateway.receiveRaw(rawResponse)
        if (!verified.ok || !verified.received) {
          await emitAuditEvent({
            phase: 'verification_failed',
            id: request.id,
            method: request.method,
            code: -32603,
            message: 'AIP verification failed',
          })
          return createErrorResponse(id, -32603, 'AIP verification failed')
        }

        await emitAuditEvent({
          phase: 'request_success',
          id: request.id,
          method: request.method,
        })

        return jsonString(toJsonRpcResponse(verified.received, request.id))
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : 'Internal error'
        const code = mapBridgeErrorCode(message)
        await emitAuditEvent({
          phase: 'request_error',
          id,
          code,
          message,
        })
        return createErrorResponse(id, code, message)
      }
    },
  }
}

export async function createAipMcpGatewayRuntimeWithPolicy(options: AipMcpGatewayOptions): Promise<AipMcpGatewayRuntime> {
  if (!options.runtimePolicy?.enabled) {
    return createAipMcpGatewayRuntime(options)
  }

  const { enforcer } = await bootstrapRuntimePolicyEnforcer(options.runtimePolicy.options)
  enforcer.assertInvariant({
    signatureVerification: true,
    canonicalization: true,
    replayDefense: true,
    ttlClockSkewEnforcement: true,
  })

  const mode = enforcer.selectMode({
    concurrency: options.runtimePolicy.concurrencyHint ?? 1,
    latencySensitive: options.runtimePolicy.latencySensitive,
    compatibilityFirst: options.runtimePolicy.compatibilityFirst,
  })

  const wireFormat = mode.includes('binary') ? 'binary' : 'compact'
  return createAipMcpGatewayRuntime({
    ...options,
    gatewayWireFormat: wireFormat,
    workerWireFormat: wireFormat,
    gatewayAgentId: options.gatewayAgentId,
    workerAgentId: options.workerAgentId,
    onAuditEvent: async (event) => {
      if (options.onAuditEvent) {
        await options.onAuditEvent({
          ...event,
          message: event.message ?? `policy-mode=${mode};wire-format=${wireFormat}`,
        })
      }
    },
  })
}
