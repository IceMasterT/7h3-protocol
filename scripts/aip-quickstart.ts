import { AgentSession } from '../src/protocolAgent'
import { encodeEnvelope } from '../src/protocolTransport'

function printExchange(label: string, raw: string): void {
  console.log(`\n[${label}]`)
  console.log(raw)
}

async function run(): Promise<void> {
  const sharedSecret = 'quickstart-shared-secret'

  const coordinator = new AgentSession({
    agentId: 'agent.coordinator',
    outboundSecret: sharedSecret,
    sharedSecrets: { 'agent.worker': sharedSecret },
    capabilities: ['task.plan', 'caps'],
  })

  const worker = new AgentSession({
    agentId: 'agent.worker',
    outboundSecret: sharedSecret,
    sharedSecrets: { 'agent.coordinator': sharedSecret },
    capabilities: ['task.plan', 'task.execute'],
    onTask: async (envelope) => ({
      intent: 'RESULT',
      content: `processed:${envelope.body.content}`,
      capability: envelope.body.capability,
    }),
  })

  const ping = await coordinator.createSignedIntent({ recipient: 'agent.worker', intent: 'PING', content: 'ping' })
  printExchange('coordinator -> worker PING (compact)', encodeEnvelope(ping, 'compact'))
  const pingReply = await worker.receiveAndRespond(ping)
  if (!pingReply.response) throw new Error('Missing PING response')
  printExchange('worker -> coordinator PONG (compact)', encodeEnvelope(pingReply.response, 'compact'))

  const caps = await coordinator.createSignedIntent({ recipient: 'agent.worker', intent: 'CAPS', content: 'caps?' })
  const capsReply = await worker.receiveAndRespond(caps)
  if (!capsReply.response) throw new Error('Missing CAPS response')
  console.log(`\n[worker CAPS payload] ${capsReply.response.body.content}`)

  const task = await coordinator.createSignedIntent({
    recipient: 'agent.worker',
    intent: 'TASK',
    content: 'build route graph',
    capability: 'task.plan',
  })
  const taskReply = await worker.receiveAndRespond(task)
  if (!taskReply.response) throw new Error('Missing TASK response')
  console.log(`\n[worker TASK result] ${taskReply.response.body.content}`)

  const verifiedAtCoordinator = await coordinator.receiveAndRespond(taskReply.response)
  console.log(`\n[coordinator verification] ok=${verifiedAtCoordinator.ok}`)
}

run().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
