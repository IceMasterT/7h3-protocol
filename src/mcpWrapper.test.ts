import { describe, expect, it, vi } from 'vitest'
import { createEnvelope, signEnvelopeHmac } from './protocol'
import { InMemoryReplayCache } from './protocolReplay'
import { encodeEnvelope, type WireEnvelope } from './protocolTransport'
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

    const { raw } = await codec.encodeRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'x' } })
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

    const { raw } = await codec.encodeRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} })
    const first = await codec.decodeResponse(await server(raw))
    const second = await codec.decodeResponse(await server(raw))

    expect(first.result).toBeDefined()
    expect(second.error).toBeDefined()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('defaults to replay protection even when no cache is configured', async () => {
    const handler = vi.fn(echo)
    const server = wrapMcpServer(handler, serverOptions()) // no replayCache provided
    const codec = createMcpClientCodec(clientOptions())

    const { raw } = await codec.encodeRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} })
    await codec.decodeResponse(await server(raw))
    const replayed = await codec.decodeResponse(await server(raw))

    expect(replayed.error).toBeDefined()
    expect(handler).toHaveBeenCalledOnce()
  })
})

describe('response authenticity', () => {
  it('client rejects a response whose signature does not verify', async () => {
    const server = wrapMcpServer(echo, serverOptions())
    const codec = createMcpClientCodec(clientOptions({ receive: { secretResolver: async () => 'WRONG-SECRET' } }))

    const { raw } = await codec.encodeRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} })
    const responseRaw = await server(raw)

    await expect(codec.decodeResponse(responseRaw)).rejects.toThrow(/verif/i)
  })
})

describe('recipient binding (cross-server relay defense)', () => {
  it('server rejects an envelope addressed to a different recipient', async () => {
    const handler = vi.fn(echo)
    const server = wrapMcpServer(handler, serverOptions({ selfAgentId: 'agent.server' }))
    // a validly-signed request addressed to 'agent.other', relayed to this server
    const misaddressed = await signEnvelopeHmac(
      createEnvelope({
        sender: 'agent.client',
        recipient: 'agent.other',
        intent: 'TASK',
        content: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} }),
      }),
      SECRET,
      'client-k1',
    )
    const responseRaw = await server(encodeEnvelope(misaddressed, 'json'))

    // decode the error with a codec that matches the real server identity
    const codec = createMcpClientCodec(clientOptions({ peerAgentId: 'agent.server' }))
    const response = await codec.decodeResponse(responseRaw)

    expect(handler).not.toHaveBeenCalled()
    expect(response.error).toBeDefined()
  })
})

describe('sender binding (response spoofing defense)', () => {
  it('client rejects a validly-signed response whose sender is not the expected peer', async () => {
    const codec = createMcpClientCodec(clientOptions({ peerAgentId: 'agent.server' }))
    // a response signed with the shared secret but by a DIFFERENT agent id
    const spoofed = await signEnvelopeHmac(
      createEnvelope({ sender: 'agent.evil', recipient: 'agent.client', intent: 'RESULT', content: JSON.stringify({ jsonrpc: '2.0', id: 1, result: 'pwned' }) }),
      SECRET,
      'evil-k1',
    )
    const spoofedRaw = encodeEnvelope(spoofed, 'json')

    await expect(codec.decodeResponse(spoofedRaw)).rejects.toThrow(/sender|peer/i)
  })
})

describe('correlation binding (response substitution defense)', () => {
  it('client rejects a response whose correlationId does not match the request', async () => {
    const server = wrapMcpServer(echo, serverOptions())
    const codec = createMcpClientCodec(clientOptions())

    const { raw } = await codec.encodeRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} })
    const responseRaw = await server(raw)

    // decode while asserting it answers a DIFFERENT request id
    await expect(codec.decodeResponse(responseRaw, { expectCorrelationId: 'some-other-message-id' })).rejects.toThrow(/correlation/i)
  })
})
