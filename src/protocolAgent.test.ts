import { describe, expect, it } from 'vitest'
import { AgentSession } from './protocolAgent'
import { negotiateAipCapabilities, parseAipCapabilities } from './protocolCapabilities'
import { encodeEnvelope, receiveEnvelope } from './protocolTransport'

describe('AgentSession protocol loop', () => {
  const alpha = new AgentSession({
    agentId: 'agent.alpha',
    outboundSecret: 'alpha-secret',
    sharedSecrets: {
      'agent.beta': 'beta-secret',
    },
  })

  const beta = new AgentSession({
    agentId: 'agent.beta',
    outboundSecret: 'beta-secret',
    capabilities: ['math.mul2', 'task.plan'],
    sharedSecrets: {
      'agent.alpha': 'alpha-secret',
    },
    onTask: async (envelope) => ({
      intent: 'RESULT',
      content: `task accepted:${envelope.body.content}`,
      capability: envelope.body.capability,
    }),
  })

  it('responds to PING with signed PONG', async () => {
    const ping = await alpha.createSignedIntent({
      recipient: 'agent.beta',
      intent: 'PING',
      content: 'hello',
      messageId: 'p-1',
      nonce: 'n-1',
      nowMs: 1000,
    })

    const receivedByBeta = await beta.receiveAndRespond(encodeEnvelope(ping), 1000)
    expect(receivedByBeta.ok).toBe(true)
    expect(receivedByBeta.response?.body.intent).toBe('PONG')

    const receivedByAlpha = await receiveEnvelope(receivedByBeta.response!, {
      nowMs: 1001,
      secretResolver: async () => 'beta-secret',
      requireSignature: true,
    })
    expect(receivedByAlpha.ok).toBe(true)
    expect(receivedByAlpha.envelope?.body.correlationId).toBe('p-1')
  })

  it('responds to CAPS with capability payload', async () => {
    const capsReq = await alpha.createSignedIntent({
      recipient: 'agent.beta',
      intent: 'CAPS',
      content: 'what can you do?',
      messageId: 'c-1',
      nonce: 'n-2',
      nowMs: 1100,
    })

    const receivedByBeta = await beta.receiveAndRespond(capsReq, 1100)
    expect(receivedByBeta.ok).toBe(true)
    expect(receivedByBeta.response?.body.intent).toBe('RESULT')

    const parsed = JSON.parse(receivedByBeta.response?.body.content ?? '{}') as {
      agent?: string
      capabilities?: string[]
      wireFormats?: string[]
      batchMax?: number
    }
    expect(parsed.agent).toBe('agent.beta')
    expect(parsed.capabilities).toContain('math.mul2')
    expect(parsed.wireFormats).toContain('compact')
    expect(parsed.batchMax).toBe(1)
  })

  it('negotiates shared wire capabilities from CAPS payloads', () => {
    const local = parseAipCapabilities('{"agent":"local","capabilities":[],"wireFormats":["binary","compact"],"batchMax":16,"ackModes":["fast","receipt"]}')
    const remote = parseAipCapabilities('{"agent":"remote","capabilities":[],"wireFormats":["compact","json"],"batchMax":8,"ackModes":["receipt"]}')
    expect(local).not.toBeNull()
    expect(remote).not.toBeNull()

    const negotiated = negotiateAipCapabilities(local!, remote!)
    expect(negotiated).toEqual({ wireFormat: 'compact', batchMax: 8, ackMode: 'receipt' })
  })

  it('handles TASK with custom task handler', async () => {
    const task = await alpha.createSignedIntent({
      recipient: 'agent.beta',
      intent: 'TASK',
      content: 'plan route',
      capability: 'task.plan',
      messageId: 't-1',
      nonce: 'n-3',
      nowMs: 1200,
    })

    const receivedByBeta = await beta.receiveAndRespond(task, 1200)
    expect(receivedByBeta.ok).toBe(true)
    expect(receivedByBeta.response?.body.intent).toBe('RESULT')
    expect(receivedByBeta.response?.body.content).toContain('task accepted:plan route')
    expect(receivedByBeta.response?.body.correlationId).toBe('t-1')
  })
})
