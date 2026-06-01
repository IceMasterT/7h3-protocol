import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { PassThrough } from 'node:stream'
import { afterEach, describe, expect, it } from 'vitest'
import { signEnvelopeHmac } from './protocol'
import {
  createMcpClientCodec,
  wrapMcpClient,
  wrapMcpServer,
  type JsonRpcRequest,
  type McpSecurityOptions,
} from './mcpWrapper'
import { createHttpMcpClient, createHttpMcpHandler, createStdioMcpClient, serveMcpOverStdio } from './mcpTransports'

const SECRET = 'mcp-shared-secret'

const serverOptions: McpSecurityOptions = {
  selfAgentId: 'agent.server',
  sign: (envelope) => signEnvelopeHmac(envelope, SECRET, 'server-k1'),
  receive: { secretResolver: async () => SECRET },
  wireFormat: 'json',
}

const clientOptions: McpSecurityOptions = {
  selfAgentId: 'agent.client',
  peerAgentId: 'agent.server',
  sign: (envelope) => signEnvelopeHmac(envelope, SECRET, 'client-k1'),
  receive: { secretResolver: async () => SECRET },
  wireFormat: 'json',
}

const echo = async (req: JsonRpcRequest) => ({ jsonrpc: '2.0' as const, id: req.id, result: { echo: req.params } })

describe('stdio transport adapter', () => {
  const cleanups: Array<() => void> = []
  afterEach(() => {
    for (const c of cleanups.splice(0)) c()
  })

  it('round-trips signed MCP messages over newline-delimited streams', async () => {
    const clientToServer = new PassThrough()
    const serverToClient = new PassThrough()

    const server = serveMcpOverStdio(wrapMcpServer(echo, serverOptions), { input: clientToServer, output: serverToClient })
    const client = createStdioMcpClient({ input: serverToClient, output: clientToServer })
    cleanups.push(() => server.close(), () => client.close())

    const call = wrapMcpClient(client.send, clientOptions)

    const first = await call({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'planner' } })
    const second = await call({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'deploy' } })

    expect(first).toEqual({ jsonrpc: '2.0', id: 1, result: { echo: { name: 'planner' } } })
    expect(second).toEqual({ jsonrpc: '2.0', id: 2, result: { echo: { name: 'deploy' } } })
  })
})

describe('http transport adapter', () => {
  let server: http.Server | undefined
  afterEach(async () => {
    if (server) await new Promise<void>((resolve) => server!.close(() => resolve()))
    server = undefined
  })

  it('round-trips signed MCP messages over a real HTTP server', async () => {
    server = http.createServer(createHttpMcpHandler(wrapMcpServer(echo, serverOptions)))
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve))
    const { port } = server.address() as AddressInfo

    const client = createHttpMcpClient({ url: `http://127.0.0.1:${port}` })
    const call = wrapMcpClient(client.send, clientOptions)

    const response = await call({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'planner' } })

    expect(response).toEqual({ jsonrpc: '2.0', id: 1, result: { echo: { name: 'planner' } } })
  })

  it('rejects an unsigned/invalid request over HTTP and returns a signed JSON-RPC error', async () => {
    server = http.createServer(createHttpMcpHandler(wrapMcpServer(echo, serverOptions)))
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve))
    const { port } = server.address() as AddressInfo

    const client = createHttpMcpClient({ url: `http://127.0.0.1:${port}` })
    const codec = createMcpClientCodec(clientOptions)

    // a body that is not a valid signed envelope
    const responseRaw = await client.send('{"not":"an envelope"}')
    const response = await codec.decodeResponse(responseRaw)

    expect(response.error).toBeDefined()
  })
})
