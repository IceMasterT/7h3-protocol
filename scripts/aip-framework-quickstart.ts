import {
  createAipAgentAdapter,
  createRawTaskFromJsonRpc,
  createRawTaskFromLangChain,
  createRawTaskFromLlamaIndex,
  toJsonRpcResponse,
  toLangChainMessage,
  toLlamaIndexMessage,
  type JsonRpcRequestLike,
} from '../src'

function printSection(title: string): void {
  console.log(`\n=== ${title} ===`)
}

async function run(): Promise<void> {
  const sharedSecret = 'framework-quickstart-secret'

  const orchestrator = createAipAgentAdapter({
    agentId: 'agent.orchestrator',
    outboundSecret: sharedSecret,
    sharedSecrets: { 'agent.worker': sharedSecret },
    wireFormat: 'compact',
  })

  const worker = createAipAgentAdapter({
    agentId: 'agent.worker',
    outboundSecret: sharedSecret,
    sharedSecrets: { 'agent.orchestrator': sharedSecret },
    wireFormat: 'compact',
    onTask: async (envelope) => {
      if (envelope.body.capability?.startsWith('mcp.')) {
        return {
          intent: 'RESULT',
          content: JSON.stringify({ ok: true, capability: envelope.body.capability }),
          capability: envelope.body.capability,
        }
      }

      return {
        intent: 'RESULT',
        content: `processed:${envelope.body.content}`,
        capability: envelope.body.capability,
      }
    },
  })

  printSection('LangChain bridge')
  const lcRaw = await createRawTaskFromLangChain(
    orchestrator,
    { content: 'plan city route', name: 'human' },
    { recipient: 'agent.worker', capability: 'task.plan' },
  )

  let lcRawResponse = ''
  await worker.handleRaw(lcRaw, async (rawResponse) => {
    lcRawResponse = rawResponse
  })

  const lcVerified = await orchestrator.receiveRaw(lcRawResponse)
  if (!lcVerified.ok || !lcVerified.received) {
    throw new Error('LangChain bridge verification failed')
  }
  console.log(toLangChainMessage(lcVerified.received))

  printSection('LlamaIndex bridge')
  const liRaw = await createRawTaskFromLlamaIndex(
    orchestrator,
    { role: 'user', content: 'summarize this transcript' },
    { recipient: 'agent.worker', capability: 'task.summarize' },
  )

  let liRawResponse = ''
  await worker.handleRaw(liRaw, async (rawResponse) => {
    liRawResponse = rawResponse
  })

  const liVerified = await orchestrator.receiveRaw(liRawResponse)
  if (!liVerified.ok || !liVerified.received) {
    throw new Error('LlamaIndex bridge verification failed')
  }
  console.log(toLlamaIndexMessage(liVerified.received))

  printSection('JSON-RPC / MCP-like bridge')
  const request: JsonRpcRequestLike = {
    jsonrpc: '2.0',
    id: 42,
    method: 'tools/call',
    params: { name: 'planner', input: 'optimize graph' },
  }

  const mcpRaw = await createRawTaskFromJsonRpc(orchestrator, request, { recipient: 'agent.worker' })

  let mcpRawResponse = ''
  await worker.handleRaw(mcpRaw, async (rawResponse) => {
    mcpRawResponse = rawResponse
  })

  const mcpVerified = await orchestrator.receiveRaw(mcpRawResponse)
  if (!mcpVerified.ok || !mcpVerified.received) {
    throw new Error('JSON-RPC bridge verification failed')
  }
  console.log(toJsonRpcResponse(mcpVerified.received, request.id))
}

run().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
