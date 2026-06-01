import net from 'node:net'
import { afterAll, describe, expect, it } from 'vitest'
import type { RedisLikeClient, RedisSetOptions } from './redisClient'
import { createRedisReplayStore } from './replayStores'
import { createRedisRevocationStore } from './revocation'

/**
 * Minimal RESP client over a raw socket — just enough of the Redis wire
 * protocol to drive SET/GET/DEL. Dependency-free so the integration test can
 * run against a real redis-server without adding an npm Redis client.
 */
class NetRedisClient implements RedisLikeClient {
  private socket!: net.Socket
  private buffer = Buffer.alloc(0)
  private readonly waiters: Array<(reply: string | number | null | Error) => void> = []

  connect(host = '127.0.0.1', port = 6379): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = net.createConnection({ host, port }, resolve)
      this.socket.on('error', reject)
      this.socket.on('data', (chunk) => {
        this.buffer = Buffer.concat([this.buffer, chunk])
        this.drain()
      })
    })
  }

  close(): void {
    this.socket?.end()
  }

  private drain(): void {
    while (this.waiters.length > 0) {
      const parsed = this.parseReply(this.buffer)
      if (!parsed) return
      this.buffer = this.buffer.subarray(parsed.consumed)
      this.waiters.shift()!(parsed.value)
    }
  }

  private parseReply(buf: Buffer): { value: string | number | null | Error; consumed: number } | null {
    const end = buf.indexOf('\r\n')
    if (end < 0) return null
    const type = String.fromCharCode(buf[0]!)
    const line = buf.toString('utf8', 1, end)
    const headerConsumed = end + 2
    if (type === '+') return { value: line, consumed: headerConsumed }
    if (type === '-') return { value: new Error(line), consumed: headerConsumed }
    if (type === ':') return { value: Number(line), consumed: headerConsumed }
    if (type === '$') {
      const len = Number(line)
      if (len === -1) return { value: null, consumed: headerConsumed }
      const dataEnd = headerConsumed + len
      if (buf.length < dataEnd + 2) return null
      return { value: buf.toString('utf8', headerConsumed, dataEnd), consumed: dataEnd + 2 }
    }
    return { value: new Error(`unsupported RESP type: ${type}`), consumed: headerConsumed }
  }

  private command(args: string[]): Promise<string | number | null> {
    const payload = `*${args.length}\r\n${args.map((a) => `$${Buffer.byteLength(a)}\r\n${a}\r\n`).join('')}`
    return new Promise((resolve, reject) => {
      this.waiters.push((reply) => (reply instanceof Error ? reject(reply) : resolve(reply)))
      this.socket.write(payload)
    })
  }

  async set(key: string, value: string, options: RedisSetOptions = {}): Promise<'OK' | null> {
    const args = ['SET', key, value]
    if (options.pxMs !== undefined) args.push('PX', String(options.pxMs))
    if (options.nx) args.push('NX')
    const reply = await this.command(args)
    return reply === 'OK' ? 'OK' : null
  }

  async get(key: string): Promise<string | null> {
    const reply = await this.command(['GET', key])
    return reply === null ? null : String(reply)
  }

  async del(key: string): Promise<number> {
    const reply = await this.command(['DEL', key])
    return Number(reply)
  }
}

async function redisAvailable(): Promise<NetRedisClient | null> {
  const client = new NetRedisClient()
  try {
    await client.connect()
    return client
  } catch {
    return null
  }
}

const client = await redisAvailable()
const runOrSkip = client ? describe : describe.skip
if (!client) {
  console.warn('[redisIntegration] redis-server unreachable on 127.0.0.1:6379 — skipping live integration tests')
}

// Unique namespace per run so concurrent/previous runs never collide.
const ns = `aip:test:${Date.now()}:${Math.floor(Math.random() * 1e6)}:`

runOrSkip('Redis integration (live server)', () => {
  const touched: string[] = []

  afterAll(async () => {
    if (!client) return
    for (const key of touched) await client.del(key)
    client.close()
  })

  it('replay store reserves a key once against real Redis', async () => {
    const prefix = `${ns}replay:`
    const store = createRedisReplayStore(client!, { keyPrefix: prefix })
    const now = Date.now()
    touched.push(`${prefix}s|m1|n1`)
    expect(await store.reserve('s|m1|n1', now + 5000, now)).toBe(true)
    expect(await store.reserve('s|m1|n1', now + 5000, now)).toBe(false)
    expect(await store.reserve('s|m2|n2', now + 5000, now)).toBe(true)
    touched.push(`${prefix}s|m2|n2`)
  })

  it('revocation store reflects a revoke against real Redis', async () => {
    const prefix = `${ns}revoked:`
    const store = createRedisRevocationStore(client!, { keyPrefix: prefix, cacheTtlMs: 0 })
    touched.push(`${prefix}agent.a agent-k1`)
    expect(await store.isRevoked('agent.a', 'agent-k1')).toBe(false)
    await store.revoke('agent.a', 'agent-k1')
    expect(await store.isRevoked('agent.a', 'agent-k1')).toBe(true)
  })
})
