import type { ProtocolEnvelope } from './protocol'

export interface ConformanceVector {
  id: string
  secret: string
  keyId: string
  envelope: Omit<ProtocolEnvelope, 'signature'>
  canonical: string
  signature: string
}

export interface Ed25519ConformanceVector {
  id: string
  keyId: string
  publicKey: string
  privateKey: string
  envelope: Omit<ProtocolEnvelope, 'signature'>
  canonical: string
  signature: string
}

export const AIP_V01_CONFORMANCE_VECTORS: ConformanceVector[] = [
  {
    id: 'task-with-capability-and-recipient',
    secret: 'vector-secret-1',
    keyId: 'vector-key-1',
    envelope: {
      header: {
        version: 'aip/0.1',
        messageId: 'vec-1',
        timestampMs: 1712500000000,
        ttlMs: 60000,
        sender: 'agent.alpha',
        recipient: 'agent.beta',
        nonce: 'nonce-vec-1',
      },
      body: {
        intent: 'TASK',
        content: 'route:alpha->beta',
        capability: 'task.plan',
        correlationId: 'corr-1',
      },
    },
    canonical:
      '{"body":{"capability":"task.plan","content":"route:alpha->beta","correlationId":"corr-1","intent":"TASK"},"header":{"messageId":"vec-1","nonce":"nonce-vec-1","recipient":"agent.beta","sender":"agent.alpha","timestampMs":1712500000000,"ttlMs":60000,"version":"aip/0.1"}}',
    signature: 'Ol7lQkRY3lRSIa05vhkCyZ23opYsRQ9AbPwFp2cx2D0',
  },
  {
    id: 'result-with-minimal-fields',
    secret: 'vector-secret-2',
    keyId: 'vector-key-2',
    envelope: {
      header: {
        version: 'aip/0.1',
        messageId: 'vec-2',
        timestampMs: 1712500005000,
        ttlMs: 30000,
        sender: 'memory.agent',
        nonce: 'nonce-vec-2',
      },
      body: {
        intent: 'RESULT',
        content: 'memory:ok',
      },
    },
    canonical:
      '{"body":{"content":"memory:ok","intent":"RESULT"},"header":{"messageId":"vec-2","nonce":"nonce-vec-2","sender":"memory.agent","timestampMs":1712500005000,"ttlMs":30000,"version":"aip/0.1"}}',
    signature: 'ZWwZPExw2dcAAl5BxPz31378mCQ5-gGh9UfXu6pZKdo',
  },
]

export const AIP_V01_ED25519_CONFORMANCE_VECTORS: Ed25519ConformanceVector[] = [
  {
    id: 'task-ed25519-with-recipient',
    keyId: 'ed-vector-key-1',
    publicKey: 'MCowBQYDK2VwAyEA-mUFiTQtcKN4nnD19V_-Wyy4q19OivnAutRUPhOcC78',
    privateKey: 'MC4CAQAwBQYDK2VwBCIEICheZbQGuDVb6hezIlcs0QnCHGxz6IhiLkC9M0qr8OOZ',
    envelope: {
      header: {
        version: 'aip/0.1',
        messageId: 'vec-ed-1',
        timestampMs: 1712500010000,
        ttlMs: 45000,
        sender: 'agent.ed',
        recipient: 'agent.verify',
        nonce: 'nonce-ed-1',
      },
      body: {
        intent: 'TASK',
        content: 'route:ed25519',
        capability: 'task.sign',
        correlationId: 'corr-ed-1',
      },
    },
    canonical:
      '{"body":{"capability":"task.sign","content":"route:ed25519","correlationId":"corr-ed-1","intent":"TASK"},"header":{"messageId":"vec-ed-1","nonce":"nonce-ed-1","recipient":"agent.verify","sender":"agent.ed","timestampMs":1712500010000,"ttlMs":45000,"version":"aip/0.1"}}',
    signature: 'wxyAgNIKof4MV4xHwWizsb3f6k2jWAh2Zzq2p9ghASEk_FJAW4gt6b91zv2z63DPksAoHZ6Q53JdejHoaP1oBQ',
  },
]
