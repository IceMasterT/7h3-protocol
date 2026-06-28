import { describe, it, expect, vi } from 'vitest'
import { wrapWebSocket, generateEd25519KeypairBase64Url, type WebSocketLike } from './wsBinding'
import { signEnvelopeEd25519, createEnvelope, type ProtocolEnvelope } from './protocol'
import { createStaticKeyRegistry } from './keyRegistry'

// Mock WebSocket class that buffers sent messages and lets you inject received messages
class MockWebSocket implements WebSocketLike {
  public sent: string[] = []
  private messageHandlers: Array<(e: { data: string }) => void> = []
  private closeHandlers: Array<() => void> = []
  readyState = 1

  send(data: string): void {
    this.sent.push(data)
  }

  addEventListener(event: string, handler: (...args: any[]) => void): void {
    if (event === 'message') {
      this.messageHandlers.push(handler as (e: { data: string }) => void)
    } else if (event === 'close') {
      this.closeHandlers.push(handler as () => void)
    }
  }

  removeEventListener(event: string, handler: (...args: unknown[]) => void): void {
    if (event === 'message') {
      const idx = this.messageHandlers.indexOf(handler as any)
      if (idx !== -1) this.messageHandlers.splice(idx, 1)
    } else if (event === 'close') {
      const idx = this.closeHandlers.indexOf(handler as any)
      if (idx !== -1) this.closeHandlers.splice(idx, 1)
    }
  }

  // Inject a received message
  receive(data: string): void {
    for (const h of this.messageHandlers) h({ data })
  }

  close(): void {
    for (const h of this.closeHandlers) h()
  }
}

describe('wrapWebSocket', () => {
  it('send() produces a signed JSON frame', async () => {
    const keypair = await generateEd25519KeypairBase64Url()
    const ws = new MockWebSocket()
    const registry = createStaticKeyRegistry({ 'agent-A': keypair.publicKey })

    const pws = wrapWebSocket(ws, {
      privateKey: keypair.privateKey,
      sender: 'agent-A',
      keyRegistry: registry,
    })

    await pws.send({ hello: 'world' })

    expect(ws.sent).toHaveLength(1)
    const frame = JSON.parse(ws.sent[0]) as ProtocolEnvelope
    expect(frame.header.sender).toBe('agent-A')
    expect(frame.signature).toBeDefined()
    expect(frame.signature?.alg).toBe('ED25519')
    expect(frame.body.intent).toBe('TASK')
    expect(frame.body.content).toBe(JSON.stringify({ hello: 'world' }))
  })

  it('incoming signed frame calls onMessage handler', async () => {
    const keypair = await generateEd25519KeypairBase64Url()
    const ws = new MockWebSocket()
    const registry = createStaticKeyRegistry({ 'agent-B': keypair.publicKey })

    const pws = wrapWebSocket(ws, {
      privateKey: keypair.privateKey,
      sender: 'agent-A',
      keyRegistry: registry,
    })

    const received: Array<{ payload: unknown; envelope: ProtocolEnvelope }> = []
    pws.onMessage((payload, envelope) => received.push({ payload, envelope }))

    // Create a valid signed frame from agent-B
    const envelope = createEnvelope({
      sender: 'agent-B',
      intent: 'TASK',
      content: JSON.stringify({ ping: true }),
      ttlMs: 30_000,
    })
    const signed = await signEnvelopeEd25519(envelope, keypair.privateKey)

    // Wait for async message processing
    await new Promise<void>(resolve => {
      pws.onMessage(() => resolve())
      ws.receive(JSON.stringify(signed))
    })

    expect(received).toHaveLength(1)
    expect(received[0].payload).toEqual({ ping: true })
    expect(received[0].envelope.header.sender).toBe('agent-B')
  })

  it('tampered frame calls onVerifyFail', async () => {
    const keypair = await generateEd25519KeypairBase64Url()
    const ws = new MockWebSocket()
    const registry = createStaticKeyRegistry({ 'agent-B': keypair.publicKey })

    const pws = wrapWebSocket(ws, {
      privateKey: keypair.privateKey,
      sender: 'agent-A',
      keyRegistry: registry,
    })

    const errors: Error[] = []
    pws.onVerifyFail((err) => errors.push(err))

    // Create a valid signed frame, then tamper with body content
    const envelope = createEnvelope({
      sender: 'agent-B',
      intent: 'TASK',
      content: 'original content',
      ttlMs: 30_000,
    })
    const signed = await signEnvelopeEd25519(envelope, keypair.privateKey)
    // Tamper with content after signing
    const tampered = { ...signed, body: { ...signed.body, content: 'tampered content' } }

    await new Promise<void>(resolve => {
      pws.onVerifyFail(() => resolve())
      ws.receive(JSON.stringify(tampered))
    })

    expect(errors).toHaveLength(1)
    expect(errors[0].message).toContain('invalid signature')
  })

  it('unknown sender calls onVerifyFail', async () => {
    const keypair = await generateEd25519KeypairBase64Url()
    const ws = new MockWebSocket()
    // Registry has no entry for 'unknown-agent'
    const registry = createStaticKeyRegistry({})

    const pws = wrapWebSocket(ws, {
      privateKey: keypair.privateKey,
      sender: 'agent-A',
      keyRegistry: registry,
    })

    const errors: Error[] = []
    pws.onVerifyFail((err) => errors.push(err))

    const envelope = createEnvelope({
      sender: 'unknown-agent',
      intent: 'TASK',
      content: 'hello',
      ttlMs: 30_000,
    })
    const signed = await signEnvelopeEd25519(envelope, keypair.privateKey)

    await new Promise<void>(resolve => {
      pws.onVerifyFail(() => resolve())
      ws.receive(JSON.stringify(signed))
    })

    expect(errors).toHaveLength(1)
    expect(errors[0].message).toContain('unknown sender')
  })

  it('malformed JSON calls onVerifyFail', async () => {
    const keypair = await generateEd25519KeypairBase64Url()
    const ws = new MockWebSocket()
    const registry = createStaticKeyRegistry({})

    const pws = wrapWebSocket(ws, {
      privateKey: keypair.privateKey,
      sender: 'agent-A',
      keyRegistry: registry,
    })

    const errors: Error[] = []
    pws.onVerifyFail((err) => errors.push(err))

    await new Promise<void>(resolve => {
      pws.onVerifyFail(() => resolve())
      ws.receive('this is not valid JSON {{{')
    })

    expect(errors).toHaveLength(1)
    expect(errors[0].message).toContain('malformed frame')
  })

  it('seq increments on each send', async () => {
    const keypair = await generateEd25519KeypairBase64Url()
    const ws = new MockWebSocket()
    const registry = createStaticKeyRegistry({ 'agent-A': keypair.publicKey })

    const pws = wrapWebSocket(ws, {
      privateKey: keypair.privateKey,
      sender: 'agent-A',
      keyRegistry: registry,
    })

    expect(pws.seq).toBe(0)

    await pws.send('first')
    expect(pws.seq).toBe(1)

    await pws.send('second')
    expect(pws.seq).toBe(2)

    await pws.send('third')
    expect(pws.seq).toBe(3)

    // Verify correlationId carries the seq number
    const frame1 = JSON.parse(ws.sent[0]) as ProtocolEnvelope
    const frame2 = JSON.parse(ws.sent[1]) as ProtocolEnvelope
    const frame3 = JSON.parse(ws.sent[2]) as ProtocolEnvelope
    expect(frame1.body.correlationId).toBe('1')
    expect(frame2.body.correlationId).toBe('2')
    expect(frame3.body.correlationId).toBe('3')
  })
})
