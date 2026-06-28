import { describe, it, expect, beforeAll } from 'vitest'
import { signResponse, verifyResponse, RESPONSE_HEADER } from './signedResponse'
import { generateEd25519KeypairBase64Url } from './protocol'

let keys: { publicKey: string; privateKey: string }
let wrongKeys: { publicKey: string; privateKey: string }

beforeAll(async () => {
  keys = await generateEd25519KeypairBase64Url()
  wrongKeys = await generateEd25519KeypairBase64Url()
})

describe('signedResponse', () => {
  it('round-trip: signs and verifies correctly', async () => {
    const body = 'hello world'
    const { headers } = await signResponse(body, {
      privateKey: keys.privateKey,
      sender: 'gateway-agent',
    })

    const result = await verifyResponse(body, headers, { publicKey: keys.publicKey })
    expect(result.ok).toBe(true)
    expect(result.envelope?.body.intent).toBe('RESULT')
    expect(result.envelope?.body.content).toBe(body)
  })

  it('fails when body does not match envelope content', async () => {
    const body = 'original body'
    const { headers } = await signResponse(body, {
      privateKey: keys.privateKey,
      sender: 'gateway-agent',
    })

    const result = await verifyResponse('tampered body', headers, { publicKey: keys.publicKey })
    expect(result.ok).toBe(false)
    expect(result.reason).toBe('content-mismatch')
  })

  it('fails with wrong public key', async () => {
    const body = 'some content'
    const { headers } = await signResponse(body, {
      privateKey: keys.privateKey,
      sender: 'gateway-agent',
    })

    const result = await verifyResponse(body, headers, { publicKey: wrongKeys.publicKey })
    expect(result.ok).toBe(false)
    expect(result.reason).toBe('invalid-signature')
  })

  it('fails when header is missing', async () => {
    const result = await verifyResponse('body', {}, { publicKey: keys.publicKey })
    expect(result.ok).toBe(false)
    expect(result.reason).toBe('missing-header')
  })

  it('fails when envelope TTL is expired', async () => {
    // Sign with 1ms ttl — immediately expired
    const body = 'ttl-test'
    const { headers } = await signResponse(body, {
      privateKey: keys.privateKey,
      sender: 'gateway-agent',
      ttlMs: 1,
    })

    // Wait a tick to ensure expiry
    await new Promise(r => setTimeout(r, 10))

    const result = await verifyResponse(body, headers, { publicKey: keys.publicKey })
    expect(result.ok).toBe(false)
    expect(result.reason).toBe('ttl-expired')
  })

  it('fails when maxAgeMs exceeded', async () => {
    const body = 'max-age-test'
    const { headers } = await signResponse(body, {
      privateKey: keys.privateKey,
      sender: 'gateway-agent',
      ttlMs: 60_000, // long ttl
    })

    // Wait to ensure age exceeds maxAgeMs
    await new Promise(r => setTimeout(r, 10))

    const result = await verifyResponse(body, headers, {
      publicKey: keys.publicKey,
      maxAgeMs: 1, // tiny window
    })
    expect(result.ok).toBe(false)
    expect(result.reason).toBe('ttl-expired')
  })

  it('passes correlationId and recipient through envelope', async () => {
    const body = 'corr-test'
    const { headers } = await signResponse(body, {
      privateKey: keys.privateKey,
      sender: 'gateway-agent',
      recipient: 'client-agent',
      correlationId: 'req-123',
    })

    const result = await verifyResponse(body, headers, { publicKey: keys.publicKey })
    expect(result.ok).toBe(true)
    expect(result.envelope?.body.correlationId).toBe('req-123')
    expect(result.envelope?.header.recipient).toBe('client-agent')
  })

  it('RESPONSE_HEADER constant is x-7h3-response', () => {
    expect(RESPONSE_HEADER).toBe('x-7h3-response')
  })
})
