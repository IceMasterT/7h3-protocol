import { describe, it, expect } from 'vitest'
import {
  signWebhook,
  verifyWebhook,
  signWebhookHmac,
  verifyWebhookHmac,
  consumeWebhook,
  generateEd25519KeypairBase64Url,
  WEBHOOK_SIG_HEADER,
  WEBHOOK_TS_HEADER,
} from './webhookBinding'

describe('webhookBinding', () => {
  // 1. Ed25519 sign + verify round trip
  it('signWebhook + verifyWebhook round trip (Ed25519)', async () => {
    const { privateKey, publicKey } = await generateEd25519KeypairBase64Url()
    const payload = JSON.stringify({ event: 'user.created', userId: '123' })
    const headers = await signWebhook(payload, { privateKey })
    const valid = await verifyWebhook(payload, headers, { publicKey })
    expect(valid).toBe(true)
  })

  // 2. HMAC sign + verify round trip
  it('signWebhookHmac + verifyWebhookHmac round trip', async () => {
    const secret = 'super-secret-webhook-key'
    const payload = JSON.stringify({ event: 'order.paid', orderId: 'abc' })
    const headers = await signWebhookHmac(payload, { secret })
    const valid = await verifyWebhookHmac(payload, headers, { secret })
    expect(valid).toBe(true)
  })

  // 3. Tampered payload returns false (Ed25519)
  it('tampered payload returns false (Ed25519)', async () => {
    const { privateKey, publicKey } = await generateEd25519KeypairBase64Url()
    const payload = JSON.stringify({ event: 'user.created', userId: '123' })
    const headers = await signWebhook(payload, { privateKey })
    const tamperedPayload = JSON.stringify({ event: 'user.created', userId: '999' })
    const valid = await verifyWebhook(tamperedPayload, headers, { publicKey })
    expect(valid).toBe(false)
  })

  // 3b. Tampered payload returns false (HMAC)
  it('tampered payload returns false (HMAC)', async () => {
    const secret = 'super-secret-webhook-key'
    const payload = JSON.stringify({ event: 'order.paid', orderId: 'abc' })
    const headers = await signWebhookHmac(payload, { secret })
    const tamperedPayload = JSON.stringify({ event: 'order.paid', orderId: 'TAMPERED' })
    const valid = await verifyWebhookHmac(tamperedPayload, headers, { secret })
    expect(valid).toBe(false)
  })

  // 4. Expired timestamp returns false
  it('expired timestamp returns false', async () => {
    const { privateKey, publicKey } = await generateEd25519KeypairBase64Url()
    const payload = JSON.stringify({ event: 'ping' })
    const headers = await signWebhook(payload, { privateKey })
    // Backdate the timestamp to be 10 minutes ago
    const expiredHeaders = {
      ...headers,
      [WEBHOOK_TS_HEADER]: String(Date.now() - 10 * 60 * 1000),
    }
    const valid = await verifyWebhook(payload, expiredHeaders, { publicKey, maxAgeMs: 300_000 })
    expect(valid).toBe(false)
  })

  // 5. Wrong key returns false
  it('wrong public key returns false', async () => {
    const { privateKey } = await generateEd25519KeypairBase64Url()
    const { publicKey: wrongPublicKey } = await generateEd25519KeypairBase64Url()
    const payload = JSON.stringify({ event: 'test' })
    const headers = await signWebhook(payload, { privateKey })
    const valid = await verifyWebhook(payload, headers, { publicKey: wrongPublicKey })
    expect(valid).toBe(false)
  })

  // 5b. Wrong HMAC secret returns false
  it('wrong HMAC secret returns false', async () => {
    const secret = 'correct-secret'
    const payload = JSON.stringify({ event: 'test' })
    const headers = await signWebhookHmac(payload, { secret })
    const valid = await verifyWebhookHmac(payload, headers, { secret: 'wrong-secret' })
    expect(valid).toBe(false)
  })

  // 6. consumeWebhook parses valid payload
  it('consumeWebhook parses valid payload and returns parsed object', async () => {
    const { privateKey, publicKey } = await generateEd25519KeypairBase64Url()
    const data = { event: 'invoice.paid', amount: 9900, currency: 'usd' }
    const payload = JSON.stringify(data)
    const headers = await signWebhook(payload, { privateKey })
    const result = await consumeWebhook<typeof data>(payload, headers as unknown as Record<string, string>, { publicKey })
    expect(result).toEqual(data)
  })

  // 7. consumeWebhook throws on invalid signature
  it('consumeWebhook throws on invalid signature', async () => {
    const { privateKey } = await generateEd25519KeypairBase64Url()
    const { publicKey: wrongPublicKey } = await generateEd25519KeypairBase64Url()
    const payload = JSON.stringify({ event: 'invoice.paid' })
    const headers = await signWebhook(payload, { privateKey })
    await expect(
      consumeWebhook(payload, headers as unknown as Record<string, string>, { publicKey: wrongPublicKey })
    ).rejects.toThrow('7h3: webhook signature verification failed')
  })

  // 7b. consumeWebhook throws on expired timestamp
  it('consumeWebhook throws on expired timestamp', async () => {
    const { privateKey, publicKey } = await generateEd25519KeypairBase64Url()
    const payload = JSON.stringify({ event: 'test' })
    const headers = await signWebhook(payload, { privateKey })
    const expiredHeaders = {
      ...headers,
      [WEBHOOK_TS_HEADER]: String(Date.now() - 10 * 60 * 1000),
    }
    await expect(
      consumeWebhook(payload, expiredHeaders as Record<string, string>, { publicKey, maxAgeMs: 300_000 })
    ).rejects.toThrow('7h3: webhook signature verification failed')
  })

  // Edge: missing headers return false
  it('missing sig header returns false', async () => {
    const { publicKey } = await generateEd25519KeypairBase64Url()
    const payload = 'hello'
    const valid = await verifyWebhook(payload, { [WEBHOOK_TS_HEADER]: String(Date.now()) } as Record<string, string>, { publicKey })
    expect(valid).toBe(false)
  })

  it('missing ts header returns false', async () => {
    const { publicKey } = await generateEd25519KeypairBase64Url()
    const payload = 'hello'
    const valid = await verifyWebhook(payload, { [WEBHOOK_SIG_HEADER]: 'fakesig' } as Record<string, string>, { publicKey })
    expect(valid).toBe(false)
  })

  // Uint8Array payload works (Ed25519)
  it('Uint8Array payload signs and verifies (Ed25519)', async () => {
    const { privateKey, publicKey } = await generateEd25519KeypairBase64Url()
    const payloadStr = JSON.stringify({ binary: true })
    const payloadBytes = new TextEncoder().encode(payloadStr)
    const headers = await signWebhook(payloadBytes, { privateKey })
    const valid = await verifyWebhook(payloadBytes, headers, { publicKey })
    expect(valid).toBe(true)
  })
})
