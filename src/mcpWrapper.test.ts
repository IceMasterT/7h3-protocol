import { describe, expect, it, vi } from 'vitest'
import { signEnvelopeHmac } from './protocol'
import { InMemoryReplayCache } from './protocolReplay'
import type { WireEnvelope } from './protocolTransport'
import {
  createMcpClientCodec,
  wrapMcpClient,
  wrapMcpServer,
  type JsonRpcRequest,
  type McpSecurityOptions,
} from './mcpWrapper'

const SECRET = 'mcp-shared-secret'

function serverOptions(extra: Partial<McpSecurityOptions> = {}): McpSecurityOptions {
  return {
    selfAgentId: 'agent.server',
    sign: (envelope) => signEnvelopeHmac(envelope, SECRET, 'server-k1'),
    receive: { secretResolver: async () => SECRET },
    wireFormat: 'json',
    ...extra,
  }
}

function clientOptions(extra: Partial<McpSecurityOptions> = {}): McpSecurityOptions {
  return {
    selfAgentId: 'agent.client',
    peerAgentId: 'agent.server',
    sign: (envelope) => signEnvelopeHmac(envelope, SECRET, 'client-k1'),
    receive: { secretResolver: async () => SECRET },
    wireFormat: 'json',
    ...extra,
  }
}

const echo: (req: JsonRpcRequest) => Promise<{ jsonrpc: '2.0'; id: JsonRpcRequest['id']; result: unknown }> = async (req) => ({
  jsonrpc: '2.0',
  id: req.id,
  result: { echo: req.params },
})

describe('wrapMcpServer + wrapMcpClient round-trip', () => {
  it('delivers a signed request, runs the handler, and returns a verified result', async () => {
    const server = wrapMcpServer(echo, serverOptions())
    const call = wrapMcpClient((raw) => server(raw), clientOptions())

    const response = await call({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'planner' } })

    expect(response).toEqual({ jsonrpc: '2.0', id: 7, result: { echo: { name: 'planner' } } })
  })

  it('hands the underlying handler PLAIN json-rpc (no envelope, no signature)', async () => {
    const handler = vi.fn(echo)
    const server = wrapMcpServer(handler, serverOptions())
    const call = wrapMcpClient((raw) => server(raw), clientOptions())

    await call({ jsonrpc: '2.0', id: 1, method: 'resources/read', params: { uri: 'file://x' } })

    expect(handler).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledWith({ jsonrpc: '2.0', id: 1, method: 'resources/read', params: { uri: 'file://x' } })
  })
})

describe('tamper detection', () => {
  function tamperContent(raw: WireEnvelope): WireEnvelope {
    const env = JSON.parse(raw as string)
    env.body.content = `${env.body.content} TAMPERED`
    return JSON.stringify(env)
  }

  it('a request tampered after signing is rejected by the server (handler never runs)', async () => {
    const handler = vi.fn(echo)
    const server = wrapMcpServer(handler, serverOptions())
    const codec = createMcpClientCodec(clientOptions())

    const raw = await codec.encodeRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'x' } })
    const response = await codec.decodeResponse(await server(tamperContent(raw)))

    expect(handler).not.toHaveBeenCalled()
    expect(response.error).toBeDefined()
    expect(response.result).toBeUndefined()
  })
})

describe('replay detection', () => {
  it('rejects the second delivery of an identical signed request', async () => {
    const replayCache = new InMemoryReplayCache()
    const handler = vi.fn(echo)
    const server = wrapMcpServer(handler, serverOptions({ receive: { secretResolver: async () => SECRET, replayCache } }))
    const codec = createMcpClientCodec(clientOptions())

    const raw = await codec.encodeRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} })
    const first = await codec.decodeResponse(await server(raw))
    const second = await codec.decodeResponse(await server(raw))

    expect(first.result).toBeDefined()
    expect(second.error).toBeDefined()
    expect(handler).toHaveBeenCalledOnce()
  })
})

describe('response authenticity', () => {
  it('client rejects a response whose signature does not verify', async () => {
    const server = wrapMcpServer(echo, serverOptions())
    const codec = createMcpClientCodec(clientOptions({ receive: { secretResolver: async () => 'WRONG-SECRET' } }))

    const raw = await codec.encodeRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} })
    const responseRaw = await server(raw)

    await expect(codec.decodeResponse(responseRaw)).rejects.toThrow(/verif/i)
  })
})
