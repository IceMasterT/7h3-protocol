import type { WireFormat } from './protocolTransport'

export type AckMode = 'fast' | 'receipt'

export interface AipCapabilities {
  agent: string
  capabilities: string[]
  wireFormats: WireFormat[]
  batchMax: number
  ackModes: AckMode[]
}

export interface NegotiatedAipCapabilities {
  wireFormat: WireFormat
  batchMax: number
  ackMode: AckMode
}

const WIRE_FORMAT_ORDER: WireFormat[] = ['binary', 'compact', 'json']
const ACK_MODE_ORDER: AckMode[] = ['fast', 'receipt']

export function createAipCapabilities(input: {
  agent: string
  capabilities?: string[]
  wireFormats?: WireFormat[]
  batchMax?: number
  ackModes?: AckMode[]
}): AipCapabilities {
  return {
    agent: input.agent,
    capabilities: input.capabilities ?? [],
    wireFormats: input.wireFormats ?? ['compact', 'json'],
    batchMax: input.batchMax ?? 1,
    ackModes: input.ackModes ?? ['receipt'],
  }
}

export function encodeAipCapabilities(capabilities: AipCapabilities): string {
  return JSON.stringify(capabilities)
}

export function parseAipCapabilities(raw: string): AipCapabilities | null {
  try {
    const parsed = JSON.parse(raw) as Partial<AipCapabilities>
    if (typeof parsed.agent !== 'string') return null
    if (!Array.isArray(parsed.capabilities)) return null
    if (!Array.isArray(parsed.wireFormats)) return null
    if (!Array.isArray(parsed.ackModes)) return null
    if (typeof parsed.batchMax !== 'number' || parsed.batchMax < 1) return null
    return {
      agent: parsed.agent,
      capabilities: parsed.capabilities.filter((item): item is string => typeof item === 'string'),
      wireFormats: parsed.wireFormats.filter((item): item is WireFormat => item === 'json' || item === 'compact' || item === 'binary'),
      batchMax: Math.floor(parsed.batchMax),
      ackModes: parsed.ackModes.filter((item): item is AckMode => item === 'fast' || item === 'receipt'),
    }
  } catch {
    return null
  }
}

export function negotiateAipCapabilities(local: AipCapabilities, remote: AipCapabilities): NegotiatedAipCapabilities {
  const wireFormat = WIRE_FORMAT_ORDER.find((format) => local.wireFormats.includes(format) && remote.wireFormats.includes(format)) ?? 'compact'
  const ackMode = ACK_MODE_ORDER.find((mode) => local.ackModes.includes(mode) && remote.ackModes.includes(mode)) ?? 'receipt'
  return {
    wireFormat,
    batchMax: Math.max(1, Math.min(local.batchMax, remote.batchMax)),
    ackMode,
  }
}
