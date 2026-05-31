import { type AgentReceiveResult, type AgentSessionConfig, AgentSession } from './protocolAgent'
import { type IntentKind, type ProtocolEnvelope } from './protocol'
import { encodeEnvelope, type WireEnvelope, type WireFormat } from './protocolTransport'

export interface AipAdapterConfig extends AgentSessionConfig {
  wireFormat?: WireFormat
}

export class AipAgentAdapter {
  private readonly session: AgentSession
  private readonly wireFormat: WireFormat

  constructor(config: AipAdapterConfig) {
    this.session = new AgentSession(config)
    this.wireFormat = config.wireFormat ?? 'compact'
  }

  toRaw(envelope: ProtocolEnvelope): WireEnvelope {
    return encodeEnvelope(envelope, this.wireFormat)
  }

  async createRawIntent(input: {
    recipient?: string
    intent: IntentKind
    content: string
    capability?: string
    correlationId?: string
    ttlMs?: number
    messageId?: string
    nonce?: string
    nowMs?: number
  }): Promise<WireEnvelope> {
    const envelope = await this.session.createSignedIntent(input)
    return this.toRaw(envelope)
  }

  async receiveRaw(raw: WireEnvelope, nowMs = Date.now()): Promise<AgentReceiveResult> {
    return this.session.receiveAndRespond(raw, nowMs)
  }

  async handleRaw(
    raw: WireEnvelope,
    emitResponseRaw: (rawResponse: WireEnvelope, responseEnvelope: ProtocolEnvelope) => void | Promise<void>,
    nowMs = Date.now(),
  ): Promise<AgentReceiveResult> {
    const result = await this.session.receiveAndRespond(raw, nowMs)
    if (result.response) {
      await emitResponseRaw(this.toRaw(result.response), result.response)
    }
    return result
  }
}

export function createAipAgentAdapter(config: AipAdapterConfig): AipAgentAdapter {
  return new AipAgentAdapter(config)
}
