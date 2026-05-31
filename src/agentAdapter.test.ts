import { describe, expect, it } from 'vitest'
import { createAipAgentAdapter } from './agentAdapter'
import type { WireEnvelope } from './protocolTransport'

describe('AIP agent adapter', () => {
  it('supports raw task request/response flow', async () => {
    const secret = 'adapter-shared-secret'

    const coordinator = createAipAgentAdapter({
      agentId: 'agent.coordinator',
      outboundSecret: secret,
      sharedSecrets: { 'agent.worker': secret },
      wireFormat: 'compact',
    })

    const worker = createAipAgentAdapter({
      agentId: 'agent.worker',
      outboundSecret: secret,
      sharedSecrets: { 'agent.coordinator': secret },
      wireFormat: 'compact',
      onTask: async (envelope) => ({
        intent: 'RESULT',
        content: `handled:${envelope.body.content}`,
        capability: envelope.body.capability,
      }),
    })

    const taskRaw = await coordinator.createRawIntent({
      recipient: 'agent.worker',
      intent: 'TASK',
      content: 'optimize route',
      capability: 'task.plan',
    })

    let responseRaw: WireEnvelope = ''
    const handled = await worker.handleRaw(taskRaw, async (rawResponse) => {
      responseRaw = rawResponse
    })

    expect(handled.ok).toBe(true)
    expect(responseRaw.length).toBeGreaterThan(0)

    const verification = await coordinator.receiveRaw(responseRaw)
    expect(verification.ok).toBe(true)
    expect(verification.received?.body.intent).toBe('RESULT')
    expect(verification.received?.body.content).toContain('handled:optimize route')
  })
})
