import { describe, expect, it } from 'vitest'
import { createAipMcpGatewayRuntime } from './mcpGateway'

describe('AIP MCP gateway runtime', () => {
  it('returns JSON-RPC result for allowed method', async () => {
    const runtime = createAipMcpGatewayRuntime({ sharedSecret: 'gateway-test-secret' })

    const line = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'planner' },
    })

    const responseLine = await runtime.handleLine(line)
    expect(responseLine).not.toBeNull()
    const response = JSON.parse(responseLine ?? '{}') as {
      jsonrpc: string
      id: number
      result?: { ok: boolean; capability: string }
      error?: { code: number; message: string }
    }

    expect(response.jsonrpc).toBe('2.0')
    expect(response.id).toBe(1)
    expect(response.error).toBeUndefined()
    expect(response.result?.ok).toBe(true)
    expect(response.result?.capability).toBe('mcp.tools/call')
  })

  it('returns invalid request for malformed JSON-RPC line', async () => {
    const runtime = createAipMcpGatewayRuntime({ sharedSecret: 'gateway-test-secret' })
    const responseLine = await runtime.handleLine('{"bad": true}')
    const response = JSON.parse(responseLine ?? '{}') as { error?: { code: number; message: string } }

    expect(response.error?.code).toBe(-32600)
    expect(response.error?.message).toBe('Invalid Request')
  })

  it('returns method not found for disallowed method', async () => {
    const runtime = createAipMcpGatewayRuntime({
      sharedSecret: 'gateway-test-secret',
      allowedMethods: ['tools/call'],
    })

    const line = JSON.stringify({
      jsonrpc: '2.0',
      id: 'x',
      method: 'resources/read',
      params: {},
    })

    const responseLine = await runtime.handleLine(line)
    const response = JSON.parse(responseLine ?? '{}') as { error?: { code: number; message: string } }

    expect(response.error?.code).toBe(-32601)
    expect(response.error?.message).toContain("is not allowed")
  })

  it('returns authorization error when policy hook blocks request', async () => {
    const runtime = createAipMcpGatewayRuntime({
      sharedSecret: 'gateway-test-secret',
      authorizeMethod: async () => false,
    })

    const line = JSON.stringify({
      jsonrpc: '2.0',
      id: 'auth-2',
      method: 'tools/call',
      params: {},
    })

    const responseLine = await runtime.handleLine(line)
    const response = JSON.parse(responseLine ?? '{}') as { error?: { code: number; message: string } }

    expect(response.error?.code).toBe(-32001)
    expect(response.error?.message).toContain('not authorized')
  })

  it('returns rate-limit error when limiter blocks request', async () => {
    const runtime = createAipMcpGatewayRuntime({
      sharedSecret: 'gateway-test-secret',
      rateLimiter: {
        consume: async () => false,
      },
    })

    const line = JSON.stringify({
      jsonrpc: '2.0',
      id: 'rl-3',
      method: 'tools/call',
      params: {},
    })

    const responseLine = await runtime.handleLine(line)
    const response = JSON.parse(responseLine ?? '{}') as { error?: { code: number; message: string } }

    expect(response.error?.code).toBe(-32002)
    expect(response.error?.message).toContain('rate-limited')
  })

  it('ignores empty lines', async () => {
    const runtime = createAipMcpGatewayRuntime({ sharedSecret: 'gateway-test-secret' })
    await expect(runtime.handleLine('   ')).resolves.toBeNull()
  })

  it('emits audit events for policy and request phases', async () => {
    const phases: string[] = []
    const runtime = createAipMcpGatewayRuntime({
      sharedSecret: 'gateway-test-secret',
      onAuditEvent: async (event) => {
        phases.push(event.phase)
      },
    })

    const line = JSON.stringify({
      jsonrpc: '2.0',
      id: 'audit-1',
      method: 'tools/call',
      params: { name: 'planner' },
    })

    const responseLine = await runtime.handleLine(line)
    expect(responseLine).not.toBeNull()
    expect(phases).toContain('request_received')
    expect(phases).toContain('policy')
    expect(phases).toContain('request_success')
  })
})
