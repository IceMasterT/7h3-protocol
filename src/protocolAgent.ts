import { createEnvelope, signEnvelopeHmac, type IntentKind, type ProtocolDiagnostic, type ProtocolEnvelope } from './protocol'
import { createAipCapabilities, encodeAipCapabilities, type AckMode } from './protocolCapabilities'
import { InMemoryReplayCache } from './protocolReplay'
import { receiveEnvelope, type WireEnvelope, type WireFormat } from './protocolTransport'

export interface TaskHandlerResult {
  intent?: 'RESULT' | 'ERROR'
  content: string
  capability?: string
}

export interface AgentSessionConfig {
  agentId: string
  outboundSecret: string
  keyId?: string
  capabilities?: string[]
  supportedWireFormats?: WireFormat[]
  maxBatchSize?: number
  ackModes?: AckMode[]
  requireSignature?: boolean
  replayCache?: InMemoryReplayCache
  sharedSecrets?: Record<string, string>
  resolveInboundSecret?: (keyId: string, sender: string) => string | undefined | Promise<string | undefined>
  onTask?: (envelope: ProtocolEnvelope) => TaskHandlerResult | Promise<TaskHandlerResult>
}

export interface AgentReceiveResult {
  ok: boolean
  diagnostics: ProtocolDiagnostic[]
  received: ProtocolEnvelope | null
  response: ProtocolEnvelope | null
}

export class AgentSession {
  private readonly agentId: string
  private readonly outboundSecret: string
  private readonly keyId: string
  private readonly capabilities: string[]
  private readonly supportedWireFormats: WireFormat[]
  private readonly maxBatchSize: number
  private readonly ackModes: AckMode[]
  private readonly requireSignature: boolean
  private readonly replayCache: InMemoryReplayCache
  private readonly sharedSecrets: Record<string, string>
  private readonly resolveInboundSecret?: (keyId: string, sender: string) => string | undefined | Promise<string | undefined>
  private readonly onTask?: (envelope: ProtocolEnvelope) => TaskHandlerResult | Promise<TaskHandlerResult>

  constructor(config: AgentSessionConfig) {
    this.agentId = config.agentId
    this.outboundSecret = config.outboundSecret
    this.keyId = config.keyId ?? `${config.agentId}-k1`
    this.capabilities = config.capabilities ?? []
    this.supportedWireFormats = config.supportedWireFormats ?? ['compact', 'json']
    this.maxBatchSize = config.maxBatchSize ?? 1
    this.ackModes = config.ackModes ?? ['receipt']
    this.requireSignature = config.requireSignature ?? true
    this.replayCache = config.replayCache ?? new InMemoryReplayCache()
    this.sharedSecrets = config.sharedSecrets ?? {}
    this.resolveInboundSecret = config.resolveInboundSecret
    this.onTask = config.onTask
  }

  private async inboundSecretResolver(keyId: string, sender: string): Promise<string | undefined> {
    if (this.resolveInboundSecret) {
      return this.resolveInboundSecret(keyId, sender)
    }
    return this.sharedSecrets[sender]
  }

  async createSignedIntent(input: {
    recipient?: string
    intent: IntentKind
    content: string
    capability?: string
    correlationId?: string
    ttlMs?: number
    messageId?: string
    nonce?: string
    nowMs?: number
  }): Promise<ProtocolEnvelope> {
    const unsigned = createEnvelope({
      sender: this.agentId,
      recipient: input.recipient,
      intent: input.intent,
      content: input.content,
      capability: input.capability,
      correlationId: input.correlationId,
      ttlMs: input.ttlMs,
      messageId: input.messageId,
      nonce: input.nonce,
      nowMs: input.nowMs,
    })
    return signEnvelopeHmac(unsigned, this.outboundSecret, this.keyId)
  }

  async receiveAndRespond(input: WireEnvelope | ProtocolEnvelope, nowMs = Date.now()): Promise<AgentReceiveResult> {
    const received = await receiveEnvelope(input, {
      nowMs,
      requireSignature: this.requireSignature,
      replayCache: this.replayCache,
      secretResolver: (keyId, sender) => this.inboundSecretResolver(keyId, sender),
    })

    if (!received.ok || !received.envelope) {
      return {
        ok: false,
        diagnostics: received.diagnostics,
        received: received.envelope,
        response: null,
      }
    }

    const envelope = received.envelope
    const response = await this.buildAutoResponse(envelope, nowMs)
    return {
      ok: true,
      diagnostics: received.diagnostics,
      received: envelope,
      response,
    }
  }

  private async buildAutoResponse(envelope: ProtocolEnvelope, nowMs: number): Promise<ProtocolEnvelope | null> {
    if (envelope.body.intent === 'PING') {
      return this.createSignedIntent({
        recipient: envelope.header.sender,
        intent: 'PONG',
        content: 'pong',
        correlationId: envelope.header.messageId,
        nowMs,
      })
    }

    if (envelope.body.intent === 'CAPS') {
      return this.createSignedIntent({
        recipient: envelope.header.sender,
        intent: 'RESULT',
        content: encodeAipCapabilities(
          createAipCapabilities({
            agent: this.agentId,
            capabilities: this.capabilities,
            wireFormats: this.supportedWireFormats,
            batchMax: this.maxBatchSize,
            ackModes: this.ackModes,
          }),
        ),
        capability: 'caps',
        correlationId: envelope.header.messageId,
        nowMs,
      })
    }

    if (envelope.body.intent === 'TASK') {
      const taskResult = this.onTask
        ? await this.onTask(envelope)
        : { intent: 'RESULT' as const, content: 'ACK', capability: envelope.body.capability }
      return this.createSignedIntent({
        recipient: envelope.header.sender,
        intent: taskResult.intent ?? 'RESULT',
        content: taskResult.content,
        capability: taskResult.capability,
        correlationId: envelope.header.messageId,
        nowMs,
      })
    }

    return null
  }
}
