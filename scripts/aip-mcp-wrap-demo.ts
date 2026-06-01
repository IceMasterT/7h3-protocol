/**
 * Demo: harden an existing MCP server with AIP in a few lines.
 *
 * The "real" MCP server below is an ordinary JSON-RPC handler — it is NOT aware
 * of AIP. We wrap it with `wrapMcpServer`, drive it through `createMcpClientCodec`,
 * and show that a clean call succeeds while a tampered or replayed message is
 * rejected before the handler ever runs.
 *
 *   npx tsx scripts/aip-mcp-wrap-demo.ts
 */
import { signEnvelopeHmac } from '../src/protocol'
import { InMemoryReplayCache } from '../src/protocolReplay'
import type { WireEnvelope } from '../src/protocolTransport'
import { createMcpClientCodec, wrapMcpServer, type JsonRpcRequest } from '../src/mcpWrapper'

const SECRET = 'demo-shared-secret'

// ── An existing MCP server. Plain JSON-RPC. No AIP awareness. ────────────────
async function realMcpServer(request: JsonRpcRequest) {
  if (request.method === 'tools/call') {
    const params = (request.params ?? {}) as { name?: string }
    return { jsonrpc: '2.0' as const, id: request.id, result: { tool: params.name, output: `ran ${params.name}` } }
  }
  return { jsonrpc: '2.0' as const, id: request.id, error: { code: -32601, message: 'Method not found' } }
}

async function main(): Promise<void> {
  const replayCache = new InMemoryReplayCache()

  // ── Wrap the server: every message is verified + signed on the wire. ───────
  const securedServer = wrapMcpServer(realMcpServer, {
    selfAgentId: 'agent.mcp-server',
    sign: (envelope) => signEnvelopeHmac(envelope, SECRET, 'server-k1'),
    receive: { secretResolver: async () => SECRET, replayCache },
    wireFormat: 'json',
  })

  const codec = createMcpClientCodec({
    selfAgentId: 'agent.mcp-client',
    peerAgentId: 'agent.mcp-server',
    sign: (envelope) => signEnvelopeHmac(envelope, SECRET, 'client-k1'),
    receive: { secretResolver: async () => SECRET },
    wireFormat: 'json',
  })

  // 1) Clean call ────────────────────────────────────────────────────────────
  const clean = await codec.encodeRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'planner' } })
  const cleanResult = await codec.decodeResponse(await securedServer(clean.raw), { expectCorrelationId: clean.messageId })
  console.log('[1] clean call        ->', JSON.stringify(cleanResult))

  // 2) Tampered call ───────────────────────────────────────────────────────── (attacker edits the signed body in flight)
  const victim = await codec.encodeRequest({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'planner' } })
  const tampered = ((): WireEnvelope => {
    const env = JSON.parse(victim.raw as string)
    env.body.content = env.body.content.replace('planner', 'rm -rf /') // swap the tool
    return JSON.stringify(env)
  })()
  const tamperedResult = await codec.decodeResponse(await securedServer(tampered))
  console.log('[2] tampered call     ->', JSON.stringify(tamperedResult), '(rejected: signature no longer matches)')

  // 3) Replayed call ──────────────────────────────────────────────────────── (attacker re-sends a previously valid message)
  const once = await codec.encodeRequest({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'deploy' } })
  const firstResult = await codec.decodeResponse(await securedServer(once.raw))
  const replayResult = await codec.decodeResponse(await securedServer(once.raw))
  console.log('[3] first delivery    ->', JSON.stringify(firstResult))
  console.log('[3] replayed delivery ->', JSON.stringify(replayResult), '(rejected: messageId/nonce already consumed)')
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error))
  process.exitCode = 1
})
