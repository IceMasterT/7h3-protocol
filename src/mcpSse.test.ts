import { describe, it, expect } from 'vitest'
import {
  SSE_CONTENT_TYPE,
  SignedSseReader,
  SignedSseWriter,
  SseVerificationError,
  readSignedSse,
  signedSseHeaders,
  type McpMessage,
} from './mcpSse'
import { createEnvelope, signEnvelopeHmac } from './protocol'
import { encodeEnvelope } from './protocolTransport'

const SECRET = 'sse-secret'
const server = 'agent.server'
const client = 'agent.client'

const writer = (over: Partial<ConstructorParameters<typeof SignedSseWriter>[0]> = {}) =>
  new SignedSseWriter({
    selfAgentId: server,
    peerAgentId: client,
    sign: (e) => signEnvelopeHmac(e, SECRET, 'k'),
    ...over,
  })
const reader = (over: Partial<ConstructorParameters<typeof SignedSseReader>[0]> = {}) =>
  new SignedSseReader({ selfAgentId: client, peerAgentId: server, receive: { secretResolver: async () => SECRET }, ...over })

const msg = (n: number): McpMessage => ({ jsonrpc: '2.0', method: 'notifications/progress', params: { n } })

async function fullStream(count = 3, w = writer()): Promise<string[]> {
  const events: string[] = []
  for (let i = 0; i < count; i++) events.push(await w.message(msg(i)))
  events.push(await w.end())
  return events
}

const dataOf = (event: string): string => /^data: (.*)$/m.exec(event)![1]
const withData = (event: string, data: string): string => event.replace(/^data: .*$/m, `data: ${data}`)

async function feedAll(r: SignedSseReader, events: string[]) {
  const out = []
  for (const e of events) out.push(...(await r.feed(e)))
  r.finish()
  return out
}
const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p
    return 'no-error'
  } catch (e) {
    return e instanceof SseVerificationError ? e.code : `other:${String(e)}`
  }
}

describe('round trip', () => {
  it('delivers every message in order, then a verified end', async () => {
    const r = reader()
    const got = await feedAll(r, await fullStream(3))
    expect(got.map((g) => g.seq)).toEqual([0, 1, 2])
    expect(got.map((g) => (g.message.params as { n: number }).n)).toEqual([0, 1, 2])
    expect(r.done).toBe(true)
  })

  it('emits SSE framing a standard client understands', async () => {
    const [first] = await fullStream(1)
    expect(first).toMatch(/^id: 0\nevent: message\ndata: \{.*\}\n\n$/)
    expect(first.split('\n').filter((l) => l.startsWith('data:')).length).toBe(1)
    expect(signedSseHeaders()['content-type']).toBe(SSE_CONTENT_TYPE)
  })

  it('handles any chunking, including one character at a time and CRLF line endings', async () => {
    const events = (await fullStream(2)).join('').replace(/\n/g, '\r\n')
    const r = reader()
    const got = []
    for (const ch of events) got.push(...(await r.feed(ch)))
    r.finish()
    expect(got.length).toBe(2)
  })

  it('ignores comments, unknown fields, retry and unsigned ids; strips a BOM', async () => {
    const evs = await fullStream(2)
    const noisy = ['﻿: hello\n\n', SignedSseWriter.keepAlive(), 'retry: 5\n\n', 'foo: bar\n\n', evs[0].replace('id: 0', 'id: 999'), ': ping\n\n', evs[1], evs[2]]
    const got = await feedAll(reader(), noisy)
    expect(got.length).toBe(2)
  })

  it('carries JSON-RPC responses as well as notifications', async () => {
    const w = writer()
    const result: McpMessage = { jsonrpc: '2.0', id: 7, result: { ok: true } }
    const got = await feedAll(reader(), [await w.message(result), await w.end()])
    expect(got[0].message).toEqual(result)
  })
})

describe('attacks on the stream', () => {
  it('rejects an altered event', async () => {
    const evs = await fullStream(2)
    const env = JSON.parse(dataOf(evs[0]))
    env.body.content = env.body.content.replace('"n":0', '"n":9')
    expect(await code(feedAll(reader(), [withData(evs[0], JSON.stringify(env)), evs[1], evs[2]]))).toBe('verification-failed')
  })

  it('rejects an event injected by someone without the key', async () => {
    const evs = await fullStream(2)
    const forged = await writer({ sign: (e) => signEnvelopeHmac(e, 'wrong-secret', 'k') }).message(msg(1))
    expect(await code(feedAll(reader(), [evs[0], forged]))).toBe('verification-failed')
  })

  it('rejects unsigned junk and non-envelope data', async () => {
    expect(await code(reader().feed('data: {"jsonrpc":"2.0","method":"evil"}\n\n'))).toBe('verification-failed')
    expect(await code(reader().feed('data: not json\n\n'))).toBe('verification-failed')
  })

  it('rejects a well-formed but UNSIGNED envelope, even if the caller tries to switch signature checks off', async () => {
    const w = writer()
    const unsigned = createEnvelope({
      sender: server,
      recipient: client,
      intent: 'RESULT',
      content: JSON.stringify({ stream: w.streamId, seq: 0, message: msg(0) }),
    })
    const event = `data: ${encodeEnvelope(unsigned, 'json')}\n\n`
    expect(await code(reader().feed(event))).toBe('verification-failed')
    expect(await code(reader({ receive: { secretResolver: async () => SECRET, requireSignature: false } }).feed(event))).toBe('verification-failed')
  })

  it('rejects a dropped event (gap)', async () => {
    const evs = await fullStream(3)
    expect(await code(feedAll(reader(), [evs[0], evs[2], evs[3]]))).toBe('sequence-error')
  })

  it('rejects reordered events', async () => {
    const evs = await fullStream(3)
    expect(await code(feedAll(reader(), [evs[1], evs[0], evs[2], evs[3]]))).toBe('sequence-error')
  })

  it('rejects a replayed event', async () => {
    const evs = await fullStream(2)
    const r = reader()
    await r.feed(evs[0])
    expect(await code(r.feed(evs[0]))).toMatch(/verification-failed|sequence-error/)
  })

  it('reports a stream cut short as truncated, never as complete', async () => {
    const evs = await fullStream(3)
    const r = reader()
    await r.feed(evs.slice(0, 3).join(''))
    expect(await code(Promise.resolve().then(() => r.finish()))).toBe('stream-truncated')
  })

  it('rejects anything after the end event', async () => {
    const w = writer()
    const evs = [await w.message(msg(0)), await w.end()]
    const extra = await writer({ streamId: w.streamId }).message(msg(9))
    expect(await code(feedAll(reader(), [...evs, extra]))).toBe('event-after-end')
  })

  it('rejects a splice from a different stream, even from the real peer', async () => {
    const a = await fullStream(2, writer({ streamId: 'stream-a' }))
    const b = await fullStream(2, writer({ streamId: 'stream-b' }))
    expect(await code(feedAll(reader(), [a[0], b[1]]))).toBe('stream-mismatch')
  })

  it('pins the stream id and correlation id when the caller knows them', async () => {
    const evs = await fullStream(1, writer({ streamId: 'real', correlationId: 'req-1' }))
    expect(await code(feedAll(reader({ expectStreamId: 'real', expectCorrelationId: 'req-1' }), evs))).toBe('no-error')
    expect(await code(feedAll(reader({ expectStreamId: 'other' }), evs))).toBe('stream-mismatch')
    expect(await code(feedAll(reader({ expectCorrelationId: 'req-2' }), evs))).toBe('stream-mismatch')
  })

  it('rejects events from the wrong sender or addressed to someone else', async () => {
    const evs = await fullStream(1)
    expect(await code(feedAll(reader({ peerAgentId: 'agent.other' }), evs))).toBe('wrong-sender')
    expect(await code(feedAll(reader({ selfAgentId: 'agent.other' }), evs))).toBe('wrong-recipient')
  })

  it('rejects an end event that lies about the count', async () => {
    const w = writer()
    const first = await w.message(msg(0))
    const lie = createEnvelope({
      sender: server,
      recipient: client,
      intent: 'RESULT',
      content: JSON.stringify({ stream: w.streamId, seq: 1, end: true, count: 5 }),
    })
    const wire = encodeEnvelope(await signEnvelopeHmac(lie, SECRET, 'k'), 'json')
    expect(await code(feedAll(reader(), [first, `event: end\ndata: ${wire}\n\n`]))).toBe('count-mismatch')
  })

  it('rejects a message that is not JSON-RPC 2.0, and malformed payloads', async () => {
    const forge = async (content: string) => {
      const e = createEnvelope({ sender: server, recipient: client, intent: 'RESULT', content })
      return `data: ${encodeEnvelope(await signEnvelopeHmac(e, SECRET, 'k'), 'json')}\n\n`
    }
    expect(await code(reader().feed(await forge(JSON.stringify({ stream: 's', seq: 0, message: { hello: 1 } }))))).toBe('malformed-event')
    expect(await code(reader().feed(await forge(JSON.stringify({ stream: 's', seq: 0, message: [] }))))).toBe('malformed-event')
    expect(await code(reader().feed(await forge('not json')))).toBe('malformed-event')
    expect(await code(reader().feed(await forge(JSON.stringify({ seq: 0 }))))).toBe('malformed-event')
  })

  it('is unusable after the first violation', async () => {
    const evs = await fullStream(2)
    const r = reader()
    await code(r.feed(evs[1])) // sequence-error
    expect(await code(r.feed(evs[0]))).toBe('sequence-error')
    expect(await code(Promise.resolve().then(() => r.finish()))).toBe('sequence-error')
  })

  it('enforces size and count limits', async () => {
    expect(await code(reader({ maxEventBytes: 50 }).feed('data: ' + 'x'.repeat(200) + '\n\n'))).toBe('event-too-large')
    expect(await code(reader({ maxEventBytes: 50 }).feed('x'.repeat(200)))).toBe('event-too-large')
    const evs = await fullStream(3)
    expect(await code(feedAll(reader({ maxEvents: 2 }), evs))).toBe('too-many-events')
  })
})

describe('writer', () => {
  it('refuses writes after end and bad stream ids', async () => {
    const w = writer()
    await w.end()
    await expect(w.message(msg(0))).rejects.toThrow(/ended/)
    await expect(w.end()).rejects.toThrow(/ended/)
    expect(() => writer({ streamId: 'has space' })).toThrow(/streamId/)
    expect(() => writer({ streamId: '' })).toThrow()
  })

  it('generates distinct stream ids', () => {
    expect(writer().streamId).not.toBe(writer().streamId)
  })
})

describe('readSignedSse', () => {
  it('verifies an async iterable of byte chunks split mid-event', async () => {
    const body = new TextEncoder().encode((await fullStream(3)).join(''))
    async function* chunks() {
      for (let i = 0; i < body.length; i += 7) yield body.slice(i, i + 7)
    }
    const seen: number[] = []
    for await (const m of readSignedSse(chunks(), { selfAgentId: client, peerAgentId: server, receive: { secretResolver: async () => SECRET } })) seen.push(m.seq)
    expect(seen).toEqual([0, 1, 2])
  })

  it('verifies a web ReadableStream', async () => {
    const body = new TextEncoder().encode((await fullStream(2)).join(''))
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(body)
        c.close()
      },
    })
    const seen = []
    for await (const m of readSignedSse(stream, { selfAgentId: client, peerAgentId: server, receive: { secretResolver: async () => SECRET } })) seen.push(m)
    expect(seen.length).toBe(2)
  })

  it('throws truncated when the body ends without an end event', async () => {
    const body = (await fullStream(2)).slice(0, 2).join('')
    async function* chunks() {
      yield body
    }
    const run = async () => {
      for await (const m of readSignedSse(chunks(), { selfAgentId: client, peerAgentId: server, receive: { secretResolver: async () => SECRET } })) void m
    }
    expect(await code(run())).toBe('stream-truncated')
  })

  it('rejects invalid UTF-8', async () => {
    async function* chunks() {
      yield new Uint8Array([0xff, 0xfe, 0xfd])
    }
    const run = async () => {
      for await (const m of readSignedSse(chunks(), { selfAgentId: client, peerAgentId: server })) void m
    }
    expect(await code(run())).toBe('malformed-event')
  })
})
