import { describe, expect, it } from 'vitest'
import { DistributedReplayCache, InMemoryReplayCache } from './protocolReplay'
import { createEnvelope, generateEd25519KeypairBase64Url, signEnvelopeEd25519 } from './protocol'
import {
  InMemoryVerificationMaterialCache,
  SessionTransport,
  createSignedMessage,
  decodeEnvelopeBatch,
  encodeEnvelope,
  encodeEnvelopeBatch,
  receiveEnvelope,
  receiveEnvelopeBatch,
} from './protocolTransport'

describe('AIP transport and replay protection', () => {
  it('accepts a valid signed message', async () => {
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'TASK',
      content: 'route:optimize',
      messageId: 'tx-1',
      nonce: 'n-1',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    const result = await receiveEnvelope(encodeEnvelope(envelope), {
      nowMs: 2000,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async (keyId, sender) => (keyId === 'k1' && sender === 'agent.alpha' ? 'shared-secret' : undefined),
    })

    expect(result.ok).toBe(true)
    expect(result.diagnostics.filter((d) => d.level === 'error')).toHaveLength(0)
  })

  it('accepts compact wire format', async () => {
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'TASK',
      content: 'route:compact',
      messageId: 'tx-c1',
      nonce: 'n-c1',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    const result = await receiveEnvelope(encodeEnvelope(envelope, 'compact'), {
      nowMs: 1001,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'shared-secret',
    })

    expect(result.ok).toBe(true)
    expect(result.envelope?.body.content).toBe('route:compact')
  })

  it('accepts binary wire format', async () => {
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'TASK',
      content: 'route:binary-transport',
      messageId: 'tx-bin-1',
      nonce: 'n-bin-1',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    const raw = encodeEnvelope(envelope, 'binary')
    expect(raw).toBeInstanceOf(Uint8Array)

    const result = await receiveEnvelope(raw, {
      nowMs: 1001,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'shared-secret',
    })

    expect(result.ok).toBe(true)
    expect(result.envelope).toEqual(envelope)
  })

  it('receives a compact batch and validates each message', async () => {
    const first = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'PING',
      content: 'one',
      messageId: 'tx-b1',
      nonce: 'n-b1',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })
    const second = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'PING',
      content: 'two',
      messageId: 'tx-b2',
      nonce: 'n-b2',
      nowMs: 1001,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    const batchRaw = encodeEnvelopeBatch([first, second], 'compact')
    const decodedBatch = decodeEnvelopeBatch(batchRaw)
    expect(decodedBatch).toHaveLength(2)
    expect(decodedBatch.every((item) => item.ok)).toBe(true)

    const results = await receiveEnvelopeBatch(batchRaw, {
      nowMs: 1100,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'shared-secret',
    })

    expect(results).toHaveLength(2)
    expect(results.every((item) => item.ok)).toBe(true)
    expect(results[0]?.envelope?.body.content).toBe('one')
    expect(results[1]?.envelope?.body.content).toBe('two')
  })

  it('receives mixed binary and compact array batches in input order', async () => {
    const first = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'PING',
      content: 'binary-one',
      messageId: 'tx-mix-1',
      nonce: 'n-mix-1',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })
    const second = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'PING',
      content: 'compact-two',
      messageId: 'tx-mix-2',
      nonce: 'n-mix-2',
      nowMs: 1001,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    const results = await receiveEnvelopeBatch([encodeEnvelope(first, 'binary'), encodeEnvelope(second, 'compact')], {
      nowMs: 1100,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'shared-secret',
    })

    expect(results).toHaveLength(2)
    expect(results.every((item) => item.ok)).toBe(true)
    expect(results[0]?.envelope?.body.content).toBe('binary-one')
    expect(results[1]?.envelope?.body.content).toBe('compact-two')
  })

  it('limits batch receive concurrency while preserving result order', async () => {
    const envelopes = await Promise.all(
      [1, 2, 3].map((index) =>
        createSignedMessage({
          sender: 'agent.alpha',
          recipient: 'agent.beta',
          intent: 'PING',
          content: `bounded-${index}`,
          messageId: `tx-bounded-${index}`,
          nonce: `n-bounded-${index}`,
          nowMs: 1000 + index,
          ttlMs: 60_000,
          secret: 'shared-secret',
          keyId: 'k1',
        }),
      ),
    )
    let active = 0
    let maxActive = 0
    const results = await receiveEnvelopeBatch(envelopes, {
      nowMs: 1100,
      replayCache: new InMemoryReplayCache(),
      batchConcurrency: 1,
      secretResolver: async () => {
        active += 1
        maxActive = Math.max(maxActive, active)
        await Promise.resolve()
        active -= 1
        return 'shared-secret'
      },
    })

    expect(results.map((result) => result.envelope?.body.content)).toEqual(['bounded-1', 'bounded-2', 'bounded-3'])
    expect(maxActive).toBe(1)
  })

  it('rejects duplicate envelopes inside the same batch', async () => {
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'PING',
      content: 'duplicate-batch',
      messageId: 'tx-duplicate-batch',
      nonce: 'n-duplicate-batch',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    const results = await receiveEnvelopeBatch([envelope, envelope], {
      nowMs: 1100,
      replayCache: new InMemoryReplayCache(),
      batchConcurrency: 2,
      secretResolver: async () => 'shared-secret',
    })

    expect(results.filter((result) => result.ok)).toHaveLength(1)
    expect(results.filter((result) => !result.ok)[0]?.diagnostics.some((d) => d.message.includes('Replay detected'))).toBe(true)
  })

  it('emits batch summary telemetry', async () => {
    const events: string[] = []
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'PING',
      content: 'batch-telemetry',
      messageId: 'tx-batch-telemetry',
      nonce: 'n-batch-telemetry',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    await receiveEnvelopeBatch([envelope], {
      nowMs: 1100,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'shared-secret',
      telemetry: async (event) => {
        events.push(event.phase)
      },
    })

    expect(events).toContain('batch_summary')
  })

  it('shares replay protection across a long-lived session transport', async () => {
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'TASK',
      content: 'route:session',
      messageId: 'tx-s1',
      nonce: 'n-s1',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    const transport = new SessionTransport({
      secretResolver: async () => 'shared-secret',
    })

    const first = await transport.receive(envelope, 1001)
    const second = await transport.receive(envelope, 1002)

    expect(first.ok).toBe(true)
    expect(second.ok).toBe(false)
    expect(second.diagnostics.some((d) => d.message.includes('Replay detected'))).toBe(true)
  })

  it('caches resolved verification material across session receives', async () => {
    const first = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'TASK',
      content: 'route:cache-1',
      messageId: 'tx-vc-1',
      nonce: 'n-vc-1',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k-cache',
    })
    const second = await createSignedMessage({
      sender: 'agent.alpha',
      recipient: 'agent.beta',
      intent: 'TASK',
      content: 'route:cache-2',
      messageId: 'tx-vc-2',
      nonce: 'n-vc-2',
      nowMs: 1001,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k-cache',
    })

    let resolverCalls = 0
    const transport = new SessionTransport({
      verificationMaterialCache: new InMemoryVerificationMaterialCache(),
      secretResolver: async () => {
        resolverCalls += 1
        return 'shared-secret'
      },
    })

    const r1 = await transport.receive(first, 1002)
    const r2 = await transport.receive(second, 1003)

    expect(r1.ok).toBe(true)
    expect(r2.ok).toBe(true)
    expect(resolverCalls).toBe(1)
  })

  it('rejects replayed envelope', async () => {
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'hello',
      messageId: 'tx-2',
      nonce: 'n-2',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })
    const cache = new InMemoryReplayCache()
    const options = {
      nowMs: 2000,
      replayCache: cache,
      secretResolver: async () => 'shared-secret',
    }

    const first = await receiveEnvelope(envelope, options)
    const second = await receiveEnvelope(envelope, options)

    expect(first.ok).toBe(true)
    expect(second.ok).toBe(false)
    expect(second.diagnostics.some((d) => d.message.includes('Replay detected'))).toBe(true)
  })

  it('rejects invalid signature', async () => {
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      intent: 'RESULT',
      content: 'done',
      messageId: 'tx-3',
      nonce: 'n-3',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'real-secret',
      keyId: 'k1',
    })

    const result = await receiveEnvelope(envelope, {
      nowMs: 2000,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'wrong-secret',
    })

    expect(result.ok).toBe(false)
    expect(result.diagnostics.some((d) => d.message === 'Signature verification failed')).toBe(true)
  })

  it('does not reserve replay keys for invalid signatures', async () => {
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      intent: 'RESULT',
      content: 'valid-after-invalid',
      messageId: 'tx-bad-first',
      nonce: 'n-bad-first',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'real-secret',
      keyId: 'k1',
    })

    const replayCache = new InMemoryReplayCache()
    const bad = await receiveEnvelope(envelope, {
      nowMs: 2000,
      replayCache,
      secretResolver: async () => 'wrong-secret',
    })
    const good = await receiveEnvelope(envelope, {
      nowMs: 2001,
      replayCache,
      secretResolver: async () => 'real-secret',
    })

    expect(bad.ok).toBe(false)
    expect(bad.diagnostics.some((d) => d.message === 'Signature verification failed')).toBe(true)
    expect(good.ok).toBe(true)
  })

  it('supports async distributed replay cache semantics', async () => {
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'hello-distributed',
      messageId: 'tx-dist-1',
      nonce: 'n-dist-1',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    const reserved = new Set<string>()
    const replayCache = new DistributedReplayCache({
      reserve: async (key) => {
        if (reserved.has(key)) return false
        reserved.add(key)
        return true
      },
    })

    const first = await receiveEnvelope(envelope, {
      nowMs: 2000,
      replayCache,
      secretResolver: async () => 'shared-secret',
    })
    const second = await receiveEnvelope(envelope, {
      nowMs: 2001,
      replayCache,
      secretResolver: async () => 'shared-secret',
    })

    expect(first.ok).toBe(true)
    expect(second.ok).toBe(false)
    expect(second.diagnostics.some((d) => d.message.includes('Replay detected'))).toBe(true)
  })

  it('accepts Ed25519 signatures via signatureResolver', async () => {
    const keys = await generateEd25519KeypairBase64Url()
    const unsigned = createEnvelope({
      sender: 'agent.alpha',
      intent: 'TASK',
      content: 'route:ed25519',
      messageId: 'tx-ed1',
      nonce: 'n-ed1',
      nowMs: 1000,
      ttlMs: 60_000,
    })
    const envelope = await signEnvelopeEd25519(unsigned, keys.privateKey, 'ed-k1')

    const result = await receiveEnvelope(encodeEnvelope(envelope, 'compact'), {
      nowMs: 1001,
      replayCache: new InMemoryReplayCache(),
      signatureResolver: async (signature) =>
        signature.alg === 'ED25519' && signature.keyId === 'ed-k1' ? { alg: 'ED25519', publicKey: keys.publicKey } : undefined,
    })

    expect(result.ok).toBe(true)
    expect(result.envelope?.signature?.alg).toBe('ED25519')
  })

  it('rejects ED25519 signatures when resolver material is missing', async () => {
    const keys = await generateEd25519KeypairBase64Url()
    const unsigned = createEnvelope({
      sender: 'agent.alpha',
      intent: 'TASK',
      content: 'route:ed25519-missing',
      messageId: 'tx-ed2',
      nonce: 'n-ed2',
      nowMs: 1000,
      ttlMs: 60_000,
    })
    const envelope = await signEnvelopeEd25519(unsigned, keys.privateKey, 'ed-k2')

    const result = await receiveEnvelope(encodeEnvelope(envelope), {
      nowMs: 1001,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'unused-secret',
    })

    expect(result.ok).toBe(false)
    expect(result.diagnostics.some((d) => d.message.includes('No signature verification material'))).toBe(true)
  })

  it('rejects messages that exceed configured future clock skew', async () => {
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      intent: 'PING',
      content: 'clock-skew',
      messageId: 'tx-skew-1',
      nonce: 'n-skew-1',
      nowMs: 5000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    const result = await receiveEnvelope(envelope, {
      nowMs: 1000,
      maxClockSkewMs: 200,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'shared-secret',
    })

    expect(result.ok).toBe(false)
    expect(result.diagnostics.some((d) => d.message === 'Message timestamp exceeds allowed clock skew')).toBe(true)
  })

  it('emits telemetry events for reject and accept paths', async () => {
    const events: string[] = []
    const envelope = await createSignedMessage({
      sender: 'agent.alpha',
      intent: 'TASK',
      content: 'telemetry',
      messageId: 'tx-tele-1',
      nonce: 'n-tele-1',
      nowMs: 1000,
      ttlMs: 60_000,
      secret: 'shared-secret',
      keyId: 'k1',
    })

    const bad = await receiveEnvelope(envelope, {
      nowMs: 1001,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'wrong-secret',
      telemetry: async (event) => {
        events.push(event.phase)
      },
    })
    expect(bad.ok).toBe(false)

    const good = await receiveEnvelope(envelope, {
      nowMs: 1002,
      replayCache: new InMemoryReplayCache(),
      secretResolver: async () => 'shared-secret',
      telemetry: async (event) => {
        events.push(event.phase)
      },
    })
    expect(good.ok).toBe(true)

    expect(events).toContain('decoded')
    expect(events).toContain('rejected_bad_signature')
    expect(events).toContain('accepted')
  })
})
