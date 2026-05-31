import { describe, expect, it } from 'vitest'
import { createAipAgentAdapter } from './agentAdapter'
import type { WireEnvelope } from './protocolTransport'
import {
  createRawTaskFromJsonRpc,
  createRawTaskFromLangChain,
  createRawTaskFromLlamaIndex,
  toJsonRpcResponse,
  toLangChainMessage,
  toLlamaIndexMessage,
  type JsonRpcRequestLike,
} from './frameworkAdapters'

describe('framework adapters', () => {
  const secret = 'framework-adapter-secret'

  it('maps LangChain-style message into signed TASK flow', async () => {
    const orchestrator = createAipAgentAdapter({
      agentId: 'agent.orchestrator',
      outboundSecret: secret,
      sharedSecrets: { 'agent.worker': secret },
      wireFormat: 'compact',
    })

    const worker = createAipAgentAdapter({
      agentId: 'agent.worker',
      outboundSecret: secret,
      sharedSecrets: { 'agent.orchestrator': secret },
      wireFormat: 'compact',
      onTask: async (envelope) => ({
        intent: 'RESULT',
        content: `done:${envelope.body.content}`,
        capability: envelope.body.capability,
      }),
    })

    const raw = await createRawTaskFromLangChain(
      orchestrator,
      { content: 'plan travel graph', name: 'human' },
      { recipient: 'agent.worker', capability: 'task.plan' },
    )

    let rawResponse: WireEnvelope = ''
    await worker.handleRaw(raw, async (responseRaw) => {
      rawResponse = responseRaw
    })

    const verified = await orchestrator.receiveRaw(rawResponse)
    expect(verified.ok).toBe(true)
    expect(verified.received).not.toBeNull()
    const langchainMsg = toLangChainMessage(verified.received!)
    expect(langchainMsg.content).toContain('done:plan travel graph')
    expect(langchainMsg.additionalKwargs?.capability).toBe('task.plan')
  })

  it('maps LlamaIndex-style message into signed TASK flow', async () => {
    const orchestrator = createAipAgentAdapter({
      agentId: 'agent.orchestrator',
      outboundSecret: secret,
      sharedSecrets: { 'agent.worker': secret },
      wireFormat: 'compact',
    })

    const worker = createAipAgentAdapter({
      agentId: 'agent.worker',
      outboundSecret: secret,
      sharedSecrets: { 'agent.orchestrator': secret },
      wireFormat: 'compact',
      onTask: async (envelope) => ({
        intent: 'RESULT',
        content: envelope.body.content.toUpperCase(),
        capability: envelope.body.capability,
      }),
    })

    const raw = await createRawTaskFromLlamaIndex(
      orchestrator,
      { role: 'user', content: 'summarize logs' },
      { recipient: 'agent.worker', capability: 'task.summarize' },
    )

    let rawResponse: WireEnvelope = ''
    await worker.handleRaw(raw, async (responseRaw) => {
      rawResponse = responseRaw
    })

    const verified = await orchestrator.receiveRaw(rawResponse)
    expect(verified.ok).toBe(true)
    expect(verified.received).not.toBeNull()
    const llamaMsg = toLlamaIndexMessage(verified.received!)
    expect(llamaMsg.role).toBe('assistant')
    expect(llamaMsg.content).toBe('SUMMARIZE LOGS')
    expect(llamaMsg.additionalKwargs?.capability).toBe('task.summarize')
  })

  it('maps JSON-RPC request/response through TASK and RESULT envelopes', async () => {
    const orchestrator = createAipAgentAdapter({
      agentId: 'agent.gateway',
      outboundSecret: secret,
      sharedSecrets: { 'agent.mcp-worker': secret },
      wireFormat: 'compact',
    })

    const worker = createAipAgentAdapter({
      agentId: 'agent.mcp-worker',
      outboundSecret: secret,
      sharedSecrets: { 'agent.gateway': secret },
      wireFormat: 'compact',
      onTask: async (envelope) => ({
        intent: 'RESULT',
        content: JSON.stringify({ ok: true, receivedCapability: envelope.body.capability }),
        capability: envelope.body.capability,
      }),
    })

    const req: JsonRpcRequestLike = {
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'planner', input: 'optimize route' },
    }

    const raw = await createRawTaskFromJsonRpc(orchestrator, req, { recipient: 'agent.mcp-worker' })

    let rawResponse: WireEnvelope = ''
    await worker.handleRaw(raw, async (responseRaw) => {
      rawResponse = responseRaw
    })

    const verified = await orchestrator.receiveRaw(rawResponse)
    expect(verified.ok).toBe(true)
    expect(verified.received).not.toBeNull()

    const mcpResponse = toJsonRpcResponse(verified.received!, req.id)
    expect(mcpResponse.jsonrpc).toBe('2.0')
    expect(mcpResponse.id).toBe(7)
    expect(mcpResponse.error).toBeUndefined()
    expect(mcpResponse.result).toEqual({ ok: true, receivedCapability: 'mcp.tools/call' })
  })

  it('rejects disallowed JSON-RPC methods before sending', async () => {
    const orchestrator = createAipAgentAdapter({
      agentId: 'agent.gateway',
      outboundSecret: secret,
      sharedSecrets: { 'agent.mcp-worker': secret },
      wireFormat: 'compact',
    })

    const req: JsonRpcRequestLike = {
      jsonrpc: '2.0',
      id: 'abc',
      method: 'tools/secret-call',
      params: {},
    }

    await expect(
      createRawTaskFromJsonRpc(orchestrator, req, {
        recipient: 'agent.mcp-worker',
        allowedMethods: ['tools/call', 'resources/read'],
      }),
    ).rejects.toThrow("JSON-RPC method 'tools/secret-call' is not allowed")
  })

  it('rejects unauthorized JSON-RPC methods before sending', async () => {
    const orchestrator = createAipAgentAdapter({
      agentId: 'agent.gateway',
      outboundSecret: secret,
      sharedSecrets: { 'agent.mcp-worker': secret },
      wireFormat: 'compact',
    })

    const req: JsonRpcRequestLike = {
      jsonrpc: '2.0',
      id: 'auth-1',
      method: 'tools/call',
      params: { name: 'planner' },
    }

    await expect(
      createRawTaskFromJsonRpc(orchestrator, req, {
        recipient: 'agent.mcp-worker',
        authorizeMethod: async () => false,
      }),
    ).rejects.toThrow("JSON-RPC method 'tools/call' is not authorized")
  })

  it('rejects rate-limited JSON-RPC methods before sending', async () => {
    const orchestrator = createAipAgentAdapter({
      agentId: 'agent.gateway',
      outboundSecret: secret,
      sharedSecrets: { 'agent.mcp-worker': secret },
      wireFormat: 'compact',
    })

    const req: JsonRpcRequestLike = {
      jsonrpc: '2.0',
      id: 'rate-1',
      method: 'tools/call',
      params: { name: 'planner' },
    }

    await expect(
      createRawTaskFromJsonRpc(orchestrator, req, {
        recipient: 'agent.mcp-worker',
        rateLimiter: {
          consume: async () => false,
        },
      }),
    ).rejects.toThrow("JSON-RPC method 'tools/call' is rate-limited")
  })

  it('passes capability context into policy hooks', async () => {
    const orchestrator = createAipAgentAdapter({
      agentId: 'agent.gateway',
      outboundSecret: secret,
      sharedSecrets: { 'agent.mcp-worker': secret },
      wireFormat: 'compact',
    })

    const req: JsonRpcRequestLike = {
      jsonrpc: '2.0',
      id: 'ctx-1',
      method: 'tools/call',
      params: { name: 'planner' },
    }

    let authCapability = ''
    let rateKey = ''
    const raw = await createRawTaskFromJsonRpc(orchestrator, req, {
      recipient: 'agent.mcp-worker',
      methodToCapability: (method) => `custom.${method}`,
      authorizeMethod: async (_request, context) => {
        authCapability = context.capability
        return true
      },
      rateLimitKey: (_request, context) => `${context.capability}:${context.correlationId}`,
      rateLimiter: {
        consume: async (key) => {
          rateKey = key
          return true
        },
      },
    })

    expect(raw.length).toBeGreaterThan(0)
    expect(authCapability).toBe('custom.tools/call')
    expect(rateKey).toBe('custom.tools/call:ctx-1')
  })

  it('emits policy events for allow and deny decisions', async () => {
    const orchestrator = createAipAgentAdapter({
      agentId: 'agent.gateway',
      outboundSecret: secret,
      sharedSecrets: { 'agent.mcp-worker': secret },
      wireFormat: 'compact',
    })

    const req: JsonRpcRequestLike = {
      jsonrpc: '2.0',
      id: 'evt-1',
      method: 'tools/call',
      params: {},
    }

    const events: string[] = []
    await createRawTaskFromJsonRpc(orchestrator, req, {
      recipient: 'agent.mcp-worker',
      allowedMethods: ['tools/call'],
      authorizeMethod: async () => true,
      onPolicyEvent: async (event) => {
        events.push(`${event.stage}:${event.decision}`)
      },
    })

    expect(events).toContain('allowlist:allow')
    expect(events).toContain('authorize:allow')

    await expect(
      createRawTaskFromJsonRpc(orchestrator, { ...req, id: 'evt-2', method: 'resources/read' }, {
        recipient: 'agent.mcp-worker',
        allowedMethods: ['tools/call'],
        onPolicyEvent: async (event) => {
          events.push(`${event.stage}:${event.decision}`)
        },
      }),
    ).rejects.toThrow("JSON-RPC method 'resources/read' is not allowed")

    expect(events).toContain('allowlist:deny')
  })
})
