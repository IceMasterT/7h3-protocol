import { describe, it, expect, vi } from 'vitest'
import {
  signGrpcCall,
  verifyGrpcCall,
  withGrpcVerification,
  GRPC_METADATA_KEY,
} from './grpcBinding'
import { createStaticKeyRegistry } from './keyRegistry'
import {
  generateEd25519KeypairBase64Url,
  createEnvelope,
  signEnvelopeEd25519,
  type ProtocolEnvelope,
} from './protocol'

describe('signGrpcCall', () => {
  it('produces metadata with the correct key', async () => {
    const { privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'grpc-client-agent'

    const metadata = await signGrpcCall({ privateKey, sender })

    expect(metadata[GRPC_METADATA_KEY]).toBeDefined()
    expect(typeof metadata[GRPC_METADATA_KEY]).toBe('string')

    // Parse and validate structure
    const parsed = JSON.parse(metadata[GRPC_METADATA_KEY]) as ProtocolEnvelope
    expect(parsed.header.sender).toBe(sender)
    expect(parsed.signature?.alg).toBe('ED25519')
  })

  it('uses a custom metadataKey when provided', async () => {
    const { privateKey } = await generateEd25519KeypairBase64Url()
    const customKey = 'x-custom-grpc-sig'

    const metadata = await signGrpcCall({ privateKey, sender: 'agent-x', metadataKey: customKey })

    expect(metadata[customKey]).toBeDefined()
    expect(metadata[GRPC_METADATA_KEY]).toBeUndefined()
  })
})

describe('verifyGrpcCall', () => {
  it('valid signed call returns ok:true with envelope', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'grpc-server-agent'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const metadata = await signGrpcCall({ privateKey, sender })
    const result = await verifyGrpcCall(metadata, { keyRegistry: registry })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.envelope.header.sender).toBe(sender)
      expect(result.envelope.body.intent).toBe('TASK')
    }
  })

  it('missing metadata returns ok:false with code 16', async () => {
    const registry = createStaticKeyRegistry({})
    const result = await verifyGrpcCall({}, { keyRegistry: registry })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.code).toBe(16)
      expect(result.message).toContain('missing')
    }
  })

  it('tampered envelope returns ok:false with code 16', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'grpc-tamper-agent'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const env = createEnvelope({ sender, intent: 'TASK', content: 'original', ttlMs: 60_000 })
    const signed = await signEnvelopeEd25519(env, privateKey)

    // Tamper with content after signing
    const tampered: ProtocolEnvelope = {
      ...signed,
      body: { ...signed.body, content: 'tampered' },
    }
    const metadata = { [GRPC_METADATA_KEY]: JSON.stringify(tampered) }

    const result = await verifyGrpcCall(metadata, { keyRegistry: registry })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.code).toBe(16)
    }
  })

  it('expired envelope returns ok:false with code 4', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'grpc-expired-agent'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const pastNow = Date.now() - 120_000 // 2 minutes ago
    const env = createEnvelope({
      sender,
      intent: 'TASK',
      content: 'expired-task',
      ttlMs: 1_000, // 1 second TTL — already expired
      nowMs: pastNow,
    })
    const signed = await signEnvelopeEd25519(env, privateKey)
    const metadata = { [GRPC_METADATA_KEY]: JSON.stringify(signed) }

    const result = await verifyGrpcCall(metadata, { keyRegistry: registry, strictTtl: true })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.code).toBe(4)
    }
  })

  it('unknown sender returns ok:false with code 16', async () => {
    const { privateKey } = await generateEd25519KeypairBase64Url()
    const registry = createStaticKeyRegistry({}) // empty registry

    const env = createEnvelope({ sender: 'unknown-grpc-agent', intent: 'TASK', content: 'hi', ttlMs: 60_000 })
    const signed = await signEnvelopeEd25519(env, privateKey)
    const metadata = { [GRPC_METADATA_KEY]: JSON.stringify(signed) }

    const result = await verifyGrpcCall(metadata, { keyRegistry: registry })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.code).toBe(16)
      expect(result.message).toContain('unknown-grpc-agent')
    }
  })

  it('accepts Buffer values in metadata', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'grpc-buffer-agent'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const env = createEnvelope({ sender, intent: 'TASK', content: 'buf-test', ttlMs: 60_000 })
    const signed = await signEnvelopeEd25519(env, privateKey)
    const metadata: Record<string, Buffer> = {
      [GRPC_METADATA_KEY]: Buffer.from(JSON.stringify(signed), 'utf8'),
    }

    const result = await verifyGrpcCall(metadata, { keyRegistry: registry })
    expect(result.ok).toBe(true)
  })

  it('accepts string array values in metadata', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'grpc-array-agent'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const env = createEnvelope({ sender, intent: 'TASK', content: 'arr-test', ttlMs: 60_000 })
    const signed = await signEnvelopeEd25519(env, privateKey)
    const metadata: Record<string, string[]> = {
      [GRPC_METADATA_KEY]: [JSON.stringify(signed)],
    }

    const result = await verifyGrpcCall(metadata, { keyRegistry: registry })
    expect(result.ok).toBe(true)
  })
})

describe('withGrpcVerification', () => {
  it('calls handler on valid call and attaches envelope to call object', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const sender = 'grpc-wrap-agent'
    const registry = createStaticKeyRegistry({ [sender]: publicKey })

    const signedMeta = await signGrpcCall({ privateKey, sender })
    const call = { metadata: signedMeta, someField: 'value' }

    const handler = vi.fn().mockResolvedValue({ status: 'ok' })
    const wrapped = withGrpcVerification(handler, { keyRegistry: registry })

    const response = await wrapped(call)

    expect(handler).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledWith(call)
    expect(response).toEqual({ status: 'ok' })
    expect((call as any)['7h3Envelope']).toBeDefined()
    expect((call as any)['7h3Envelope'].header.sender).toBe(sender)
  })

  it('throws on invalid call and does not invoke handler', async () => {
    const registry = createStaticKeyRegistry({})
    const call = { metadata: {} } // no envelope metadata

    const handler = vi.fn().mockResolvedValue({ status: 'ok' })
    const wrapped = withGrpcVerification(handler, { keyRegistry: registry })

    await expect(wrapped(call)).rejects.toThrow()
    expect(handler).not.toHaveBeenCalled()

    // The thrown error should carry the gRPC status code
    try {
      await wrapped(call)
    } catch (err: any) {
      expect(err.code).toBe(16)
    }
  })
})
