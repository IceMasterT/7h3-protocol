import { describe, expect, it } from 'vitest'
import { createEnvelope, signEnvelopeHmac } from './protocol'
import { RollingKeyring, createKeyringSignatureResolver } from './keyRotation'
import { InMemoryReplayCache } from './protocolReplay'
import { receiveEnvelope } from './protocolTransport'

describe('rolling keyring', () => {
  it('selects newest active signing key and enforces revocation', () => {
    const ring = new RollingKeyring([
      {
        sender: 'agent.alpha',
        keyId: 'k-old',
        alg: 'HS256',
        status: 'verify-only',
        notBeforeMs: 1000,
        notAfterMs: 5000,
        material: { alg: 'HS256', secret: 'old-secret' },
      },
      {
        sender: 'agent.alpha',
        keyId: 'k-new',
        alg: 'HS256',
        status: 'active',
        notBeforeMs: 4000,
        notAfterMs: 9000,
        material: { alg: 'HS256', secret: 'new-secret' },
      },
    ])

    expect(ring.selectSigningKey('agent.alpha', 'HS256', 4500)?.keyId).toBe('k-new')
    expect(ring.revoke('agent.alpha', 'k-new', 4600)).toBe(true)
    expect(ring.selectSigningKey('agent.alpha', 'HS256', 4700)).toBeNull()
  })

  it('resolves verification material and integrates with transport signatureResolver', async () => {
    const ring = new RollingKeyring([
      {
        sender: 'agent.alpha',
        keyId: 'k1',
        alg: 'HS256',
        status: 'active',
        notBeforeMs: 1000,
        notAfterMs: 9000,
        material: { alg: 'HS256', secret: 'shared-secret' },
      },
    ])

    const envelope = await signEnvelopeHmac(
      createEnvelope({
        sender: 'agent.alpha',
        intent: 'PING',
        content: 'hello',
        messageId: 'kr-1',
        nonce: 'kr-n1',
        nowMs: 2000,
        ttlMs: 60_000,
      }),
      'shared-secret',
      'k1',
    )

    const ok = await receiveEnvelope(envelope, {
      nowMs: 3000,
      replayCache: new InMemoryReplayCache(),
      signatureResolver: createKeyringSignatureResolver(ring, () => 3000),
    })
    expect(ok.ok).toBe(true)

    ring.revoke('agent.alpha', 'k1', 3100)
    const blocked = await receiveEnvelope(envelope, {
      nowMs: 3200,
      replayCache: new InMemoryReplayCache(),
      signatureResolver: createKeyringSignatureResolver(ring, () => 3200),
    })
    expect(blocked.ok).toBe(false)
    expect(blocked.diagnostics.some((d) => d.message.includes('No signature verification material'))).toBe(true)
  })
})
