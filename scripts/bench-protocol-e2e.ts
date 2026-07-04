import { mkdir, writeFile } from 'node:fs/promises'
import http2 from 'node:http2'
import { performance } from 'node:perf_hooks'
import process from 'node:process'
import { WebSocket, WebSocketServer } from 'ws'
import {
  canonicalizeEnvelope,
  signCanonicalPayloadHmac,
  type ProtocolEnvelope,
  type ProtocolHeader,
} from '../src/protocol'
import { InMemoryReplayCache } from '../src/protocolReplay'
import { InMemoryVerificationMaterialCache, decodeEnvelope, encodeEnvelope, receiveEnvelope } from '../src/protocolTransport'

type ProfileName = 'quick' | 'full'
type Mode = 'inproc' | 'http' | 'ws' | 'agent-loop'

interface Profile {
  warmupMs: number
  measureMs: number
}

interface Scenario {
  mode: Mode
  payloadBytes: number
  concurrency: number
}

interface StageTotals {
  buildMs: number
  canonicalizeMs: number
  macMs: number
  queueMs: number
  transportMs: number
  verifyMs: number
  decodeMs: number
}

interface ScenarioResult {
  mode: Mode
  payloadBytes: number
  concurrency: number
  ops: number
  opsPerSecond: number
  p50Ms: number
  p95Ms: number
  p99Ms: number
  cpuMsPer10kOps: number
  heapDeltaMb: number
  rssDeltaMb: number
  allocBytesPerOp: number
  stageBuildMsPerOp: number
  stageCanonicalizeMsPerOp: number
  stageMacMsPerOp: number
  stageQueueMsPerOp: number
  stageTransportMsPerOp: number
  stageVerifyMsPerOp: number
  stageDecodeMsPerOp: number
}

interface TransportTrace {
  queueMs: number
  transportMs: number
  verifyMs: number
  decodeMs: number
}

interface TransportAdapter {
  start(): Promise<void>
  send(rawEnvelope: string): Promise<TransportTrace>
  stop(): Promise<void>
}

interface BenchEnvelopeTemplate {
  headerBase: Omit<ProtocolHeader, 'messageId' | 'timestampMs' | 'nonce'>
  intent: 'TASK'
  capability: string
}

interface ServerAck {
  ok: boolean
  queueMs: number
  verifyMs: number
  decodeMs: number
  error?: string
}

const ACK_HEADER_OK = 'x-aip-ok'
const ACK_HEADER_QUEUE_MS = 'x-aip-queue-ms'
const ACK_HEADER_VERIFY_MS = 'x-aip-verify-ms'
const ACK_HEADER_DECODE_MS = 'x-aip-decode-ms'

const SHARED_SECRET = 'bench-shared-secret'
const SHARED_SECRET_RESOLVER = async (): Promise<string> => SHARED_SECRET
const PROFILES: Record<ProfileName, Profile> = {
  quick: {
    warmupMs: 300,
    measureMs: 1500,
  },
  full: {
    warmupMs: 1200,
    measureMs: 8000,
  },
}

const PAYLOAD_SIZES = [256, 1024, 4096, 16384]
const CONCURRENCY_LEVELS = [1, 10, 100, 1000]
const MAX_LATENCY_SAMPLES = 200_000

function parseProfile(argv: string[]): ProfileName {
  const idx = argv.indexOf('--profile')
  if (idx >= 0) {
    const value = argv[idx + 1]
    if (value === 'quick' || value === 'full') return value
  }
  return 'quick'
}

function parseCsvArg(flag: string, argv: string[]): string[] {
  const idx = argv.indexOf(flag)
  if (idx < 0) return []
  const raw = argv[idx + 1]
  if (!raw) return []
  return raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
}

function parseModeSelection(argv: string[], fallback: Mode[]): Mode[] {
  const rawModes = parseCsvArg('--modes', argv)
  if (rawModes.length === 0) return fallback
  const allowed = new Set<Mode>(['inproc', 'http', 'ws', 'agent-loop'])
  const parsed = rawModes.filter((raw): raw is Mode => allowed.has(raw as Mode))
  return parsed.length > 0 ? parsed : fallback
}

function parseNumberSelection(argv: string[], flag: string, fallback: number[]): number[] {
  const rawValues = parseCsvArg(flag, argv)
  if (rawValues.length === 0) return fallback
  const parsed = rawValues
    .map((raw) => Number(raw))
    .filter((value) => Number.isFinite(value) && value > 0)
    .map((value) => Math.floor(value))
  return parsed.length > 0 ? parsed : fallback
}

function payloadOfSize(bytes: number): string {
  if (bytes <= 0) return ''
  return 'x'.repeat(bytes)
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0
  const index = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[index] ?? 0
}

function round3(value: number): number {
  return Number(value.toFixed(3))
}

function nowMs(): number {
  return Date.now()
}

function maybeGc(): void {
  const withGc = globalThis as unknown as { gc?: () => void }
  withGc.gc?.()
}

function emptyStageTotals(): StageTotals {
  return {
    buildMs: 0,
    canonicalizeMs: 0,
    macMs: 0,
    queueMs: 0,
    transportMs: 0,
    verifyMs: 0,
    decodeMs: 0,
  }
}

function addStageTotals(target: StageTotals, delta: TransportTrace & { buildMs: number; canonicalizeMs: number; macMs: number }): void {
  target.buildMs += delta.buildMs
  target.canonicalizeMs += delta.canonicalizeMs
  target.macMs += delta.macMs
  target.queueMs += delta.queueMs
  target.transportMs += delta.transportMs
  target.verifyMs += delta.verifyMs
  target.decodeMs += delta.decodeMs
}

function buildEnvelope(template: BenchEnvelopeTemplate, payload: string, sequence: number): Omit<ProtocolEnvelope, 'signature'> {
  return {
    header: {
      ...template.headerBase,
      messageId: `m-${sequence}`,
      timestampMs: nowMs(),
      nonce: `n-${sequence}`,
    },
    body: {
      intent: template.intent,
      content: payload,
      capability: template.capability,
      correlationId: `corr-${sequence}`,
    },
  }
}

function parseServerAck(raw: string): ServerAck {
  const parsed = JSON.parse(raw) as Partial<ServerAck>
  return {
    ok: parsed.ok === true,
    queueMs: parsed.queueMs ?? 0,
    verifyMs: parsed.verifyMs ?? 0,
    decodeMs: parsed.decodeMs ?? 0,
    error: parsed.error,
  }
}

class InProcessAdapter implements TransportAdapter {
  private readonly replayCache = new InMemoryReplayCache(1_000_000)
  private readonly verificationMaterialCache = new InMemoryVerificationMaterialCache()

  async start(): Promise<void> {}

  async send(rawEnvelope: string): Promise<TransportTrace> {
    const queueStart = performance.now()
    await new Promise<void>((resolve) => setImmediate(resolve))
    const queueMs = performance.now() - queueStart

    const decodeStart = performance.now()
    const decoded = decodeEnvelope(rawEnvelope)
    const decodeMs = performance.now() - decodeStart
    if (!decoded.ok || !decoded.envelope) {
      throw new Error(decoded.diagnostics.map((d) => d.message).join('; '))
    }

    const verifyStart = performance.now()
    const result = await receiveEnvelope(decoded.envelope, {
      nowMs: nowMs(),
      replayCache: this.replayCache,
      verificationMaterialCache: this.verificationMaterialCache,
      secretResolver: SHARED_SECRET_RESOLVER,
    })
    const verifyMs = performance.now() - verifyStart
    if (!result.ok) {
      throw new Error(result.diagnostics.map((d) => d.message).join('; '))
    }

    return {
      queueMs,
      transportMs: 0,
      verifyMs,
      decodeMs,
    }
  }

  async stop(): Promise<void> {}
}

class HttpAdapter implements TransportAdapter {
  private readonly replayCache = new InMemoryReplayCache(1_000_000)
  private readonly verificationMaterialCache = new InMemoryVerificationMaterialCache()
  private server: http2.Http2Server | null = null
  private client: http2.ClientHttp2Session | null = null
  private port = 0
  private readonly fastAck: boolean

  constructor(fastAck = true) {
    this.fastAck = fastAck
  }

  async start(): Promise<void> {
    this.server = http2.createServer({
      settings: {
        maxConcurrentStreams: 4096,
      },
    })
    this.server.on('stream', (stream: http2.ServerHttp2Stream, headers: http2.IncomingHttpHeaders) => {
      if (headers[':method'] !== 'POST') {
        stream.respond({ ':status': 405 })
        stream.end()
        return
      }

      const queueStart = performance.now()
      const chunks: Buffer[] = []
      stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      stream.on('end', async () => {
        const queueMs = performance.now() - queueStart
        const raw = Buffer.concat(chunks).toString('utf8')

        try {
          const decodeStart = performance.now()
          const decoded = decodeEnvelope(raw)
          const decodeMs = performance.now() - decodeStart
          if (!decoded.ok || !decoded.envelope) {
            stream.respond({ ':status': 400, 'content-type': 'application/json' })
            stream.end(JSON.stringify({ ok: false, queueMs, decodeMs, verifyMs: 0, error: 'decode failed' }))
            return
          }

          const verifyStart = performance.now()
          const result = await receiveEnvelope(decoded.envelope, {
            nowMs: nowMs(),
            replayCache: this.replayCache,
            verificationMaterialCache: this.verificationMaterialCache,
            secretResolver: SHARED_SECRET_RESOLVER,
          })
          const verifyMs = performance.now() - verifyStart
          const ack: ServerAck = {
            ok: result.ok,
            queueMs,
            decodeMs,
            verifyMs,
            error: result.ok ? undefined : result.diagnostics.map((d) => d.message).join('; '),
          }

          if (result.ok && this.fastAck) {
            stream.respond({
              ':status': 204,
              [ACK_HEADER_OK]: '1',
              [ACK_HEADER_QUEUE_MS]: String(queueMs),
              [ACK_HEADER_VERIFY_MS]: String(verifyMs),
              [ACK_HEADER_DECODE_MS]: String(decodeMs),
            })
            stream.end()
            return
          }

          stream.respond({ ':status': result.ok ? 200 : 400, 'content-type': 'application/json' })
          stream.end(JSON.stringify(ack))
        } catch {
          stream.respond({ ':status': 500, 'content-type': 'application/json' })
          stream.end(JSON.stringify({ ok: false, queueMs, decodeMs: 0, verifyMs: 0, error: 'internal http receive error' }))
        }
      })
    })

    await new Promise<void>((resolve, reject) => {
      this.server?.once('error', reject)
      this.server?.listen(0, '127.0.0.1', () => resolve())
    })

    const address = this.server.address()
    if (!address || typeof address === 'string') {
      throw new Error('Could not resolve HTTP server address')
    }
    this.port = address.port

    this.client = http2.connect(`http://127.0.0.1:${this.port}`)
    await new Promise<void>((resolve, reject) => {
      const client = this.client
      if (!client) {
        reject(new Error('Failed to initialize HTTP/2 client'))
        return
      }
      client.once('error', reject)
      client.once('connect', () => {
        client.off('error', reject)
        resolve()
      })
    })
  }

  async send(rawEnvelope: string): Promise<TransportTrace> {
    const transportStart = performance.now()

    if (!this.client) {
      throw new Error('HTTP/2 client not started')
    }

    const response = await new Promise<{ body: string; headers: http2.IncomingHttpHeaders }>((resolve, reject) => {
      const request = this.client!.request({
        ':method': 'POST',
        ':path': '/envelope',
        'content-type': 'application/json',
      })

      let statusCode = 500
      let responseHeaders: http2.IncomingHttpHeaders = {}
      const chunks: Buffer[] = []

      request.on('response', (headers) => {
        const code = headers[':status']
        statusCode = typeof code === 'number' ? code : Number(code ?? 500)
        responseHeaders = headers
      })
      request.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      request.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8')
        if (statusCode >= 400) {
          reject(new Error(`HTTP status ${statusCode}: ${body}`))
          return
        }
        resolve({ body, headers: responseHeaders })
      })

      request.on('error', reject)
      request.end(rawEnvelope)
    })
    const transportMs = performance.now() - transportStart

    const ack = this.fastAck && readHeaderString(response.headers, ACK_HEADER_OK) === '1' ? ackFromHeaders(response.headers) : parseServerAck(response.body)
    if (!ack.ok) {
      throw new Error(ack.error ?? 'HTTP adapter received non-ok response')
    }

    return {
      queueMs: ack.queueMs,
      transportMs,
      verifyMs: ack.verifyMs,
      decodeMs: ack.decodeMs,
    }
  }

  async stop(): Promise<void> {
    if (this.client) {
      await new Promise<void>((resolve) => {
        const client = this.client
        if (!client) {
          resolve()
          return
        }
        client.once('close', () => resolve())
        client.close()
      })
      this.client = null
    }
    if (!this.server) return
    await new Promise<void>((resolve, reject) => {
      this.server?.close((error) => (error ? reject(error) : resolve()))
    })
    this.server = null
  }
}

function readHeaderString(headers: http2.IncomingHttpHeaders, key: string): string | undefined {
  const value = headers[key]
  if (typeof value === 'string') return value
  if (typeof value === 'number') return String(value)
  if (Array.isArray(value)) {
    const first = value[0]
    return typeof first === 'string' ? first : undefined
  }
  return undefined
}

function readHeaderNumber(headers: http2.IncomingHttpHeaders, key: string): number {
  const raw = readHeaderString(headers, key)
  if (!raw) return 0
  const parsed = Number(raw)
  return Number.isFinite(parsed) ? parsed : 0
}

function ackFromHeaders(headers: http2.IncomingHttpHeaders): ServerAck {
  return {
    ok: readHeaderString(headers, ACK_HEADER_OK) === '1',
    queueMs: readHeaderNumber(headers, ACK_HEADER_QUEUE_MS),
    verifyMs: readHeaderNumber(headers, ACK_HEADER_VERIFY_MS),
    decodeMs: readHeaderNumber(headers, ACK_HEADER_DECODE_MS),
  }
}

class WsAdapter implements TransportAdapter {
  private readonly replayCache = new InMemoryReplayCache(1_000_000)
  private readonly verificationMaterialCache = new InMemoryVerificationMaterialCache()
  private server: WebSocketServer | null = null
  private client: WebSocket | null = null
  private nextId = 1
  private readonly pending = new Map<number, { resolve: (trace: TransportTrace) => void; reject: (error: Error) => void }>()

  async start(): Promise<void> {
    this.server = new WebSocketServer({ port: 0, host: '127.0.0.1' })

    this.server.on('connection', (socket) => {
      socket.on('message', async (data) => {
        const queueStart = performance.now()
        let message: { id: number; payload: string }
        try {
          message = JSON.parse(Buffer.isBuffer(data) ? data.toString('utf8') : String(data)) as {
            id: number
            payload: string
          }
        } catch {
          socket.send(Buffer.from(JSON.stringify({ id: 0, ok: false, error: 'invalid frame' }), 'utf8'))
          return
        }

        const queueMs = performance.now() - queueStart
        try {
          const decodeStart = performance.now()
          const decoded = decodeEnvelope(message.payload)
          const decodeMs = performance.now() - decodeStart
          if (!decoded.ok || !decoded.envelope) {
            socket.send(
              Buffer.from(
                JSON.stringify({ id: message.id, ok: false, queueMs, decodeMs, verifyMs: 0, error: 'decode failed' }),
                'utf8',
              ),
            )
            return
          }

          const verifyStart = performance.now()
          const result = await receiveEnvelope(decoded.envelope, {
            nowMs: nowMs(),
            replayCache: this.replayCache,
            verificationMaterialCache: this.verificationMaterialCache,
            secretResolver: SHARED_SECRET_RESOLVER,
          })
          const verifyMs = performance.now() - verifyStart

          socket.send(
            Buffer.from(
              JSON.stringify({
                id: message.id,
                ok: result.ok,
                queueMs,
                decodeMs,
                verifyMs,
                error: result.ok ? undefined : result.diagnostics.map((d) => d.message).join('; '),
              }),
              'utf8',
            ),
          )
        } catch {
          socket.send(
            Buffer.from(
              JSON.stringify({ id: message.id, ok: false, queueMs, decodeMs: 0, verifyMs: 0, error: 'internal ws receive error' }),
              'utf8',
            ),
          )
        }
      })
    })

    const port = await new Promise<number>((resolve, reject) => {
      this.server?.once('error', reject)
      this.server?.once('listening', () => {
        const address = this.server?.address()
        if (!address || typeof address === 'string') {
          reject(new Error('Could not resolve WS server address'))
          return
        }
        resolve(address.port)
      })
    })

    this.client = await new Promise<WebSocket>((resolve, reject) => {
      const socket = new WebSocket(`ws://127.0.0.1:${port}`)
      socket.once('open', () => resolve(socket))
      socket.once('error', reject)
    })

    this.client.on('message', (data) => {
      let frame: { id: number; ok: boolean; queueMs: number; verifyMs: number; decodeMs: number; error?: string }
      try {
        frame = JSON.parse(Buffer.isBuffer(data) ? data.toString('utf8') : String(data)) as {
          id: number
          ok: boolean
          queueMs: number
          verifyMs: number
          decodeMs: number
          error?: string
        }
      } catch {
        return
      }
      const pending = this.pending.get(frame.id)
      if (!pending) return
      this.pending.delete(frame.id)
      if (!frame.ok) {
        pending.reject(new Error(frame.error ?? 'ws adapter received non-ok response'))
        return
      }
      pending.resolve({
        queueMs: frame.queueMs,
        transportMs: 0,
        verifyMs: frame.verifyMs,
        decodeMs: frame.decodeMs,
      })
    })
  }

  async send(rawEnvelope: string): Promise<TransportTrace> {
    if (!this.client || this.client.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket client is not open')
    }

    const id = this.nextId
    this.nextId += 1
    const sendStart = performance.now()

    const completion = new Promise<TransportTrace>((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
    })

    this.client.send(Buffer.from(JSON.stringify({ id, payload: rawEnvelope }), 'utf8'))
    const trace = await completion
    return {
      ...trace,
      transportMs: performance.now() - sendStart,
    }
  }

  async stop(): Promise<void> {
    if (this.client) {
      await new Promise<void>((resolve) => {
        this.client?.once('close', () => resolve())
        this.client?.close()
      })
      this.client = null
    }

    if (this.server) {
      await new Promise<void>((resolve, reject) => {
        this.server?.close((error) => (error ? reject(error) : resolve()))
      })
      this.server = null
    }
  }
}

async function runAgentLoop(payload: string): Promise<void> {
  const input = payload
  const plan = `plan:${input.length}`
  const toolResult = await Promise.resolve(plan.length + input.length)
  const memoryUpdate = `${plan}:${toolResult}`
  const response = `ok:${memoryUpdate}`
  if (response.length === 0) {
    throw new Error('unexpected empty response')
  }
}

async function buildSignAndEncodeEnvelope(
  template: BenchEnvelopeTemplate,
  payload: string,
  sequence: number,
): Promise<{
  raw: string
  buildMs: number
  canonicalizeMs: number
  macMs: number
}> {
  const buildStart = performance.now()
  const unsigned = buildEnvelope(template, payload, sequence)
  const buildMs = performance.now() - buildStart

  const canonicalizeStart = performance.now()
  const canonicalPayload = canonicalizeEnvelope(unsigned)
  const canonicalizeMs = performance.now() - canonicalizeStart

  const macStart = performance.now()
  const signature = await signCanonicalPayloadHmac(canonicalPayload, SHARED_SECRET)
  const macMs = performance.now() - macStart

  const signedEnvelope: ProtocolEnvelope = {
    ...unsigned,
    signature: {
      alg: 'HS256',
      keyId: 'bench-k1',
      value: signature,
    },
  }

  return {
    raw: encodeEnvelope(signedEnvelope, 'compact'),
    buildMs,
    canonicalizeMs,
    macMs,
  }
}

async function runPhase(options: {
  durationMs: number
  concurrency: number
  payload: string
  execute: (payload: string) => Promise<TransportTrace & { buildMs: number; canonicalizeMs: number; macMs: number }>
  collectLatencies: boolean
}): Promise<{ latencies: number[]; completed: number; stages: StageTotals }> {
  const latencies: number[] = []
  const stages = emptyStageTotals()
  const deadline = performance.now() + options.durationMs
  let inFlight = 0
  let completed = 0

  return new Promise((resolve, reject) => {
    let settled = false

    const finish = () => {
      if (settled) return
      settled = true
      resolve({ latencies, completed, stages })
    }

    const maybeLaunch = () => {
      while (inFlight < options.concurrency && performance.now() < deadline) {
        inFlight += 1
        const opStart = performance.now()

        options
          .execute(options.payload)
          .then((trace) => {
            completed += 1
            addStageTotals(stages, trace)
            if (options.collectLatencies) {
              const elapsed = performance.now() - opStart
              if (latencies.length < MAX_LATENCY_SAMPLES) {
                latencies.push(elapsed)
              } else {
                const sampleIndex = Math.floor(Math.random() * completed)
                if (sampleIndex < MAX_LATENCY_SAMPLES) {
                  latencies[sampleIndex] = elapsed
                }
              }
            }
          })
          .catch((error: unknown) => {
            if (settled) return
            settled = true
            reject(error)
          })
          .finally(() => {
            inFlight -= 1
            if (settled) return
            if (performance.now() < deadline) {
              maybeLaunch()
              return
            }
            if (inFlight === 0) {
              finish()
            }
          })
      }
    }

    maybeLaunch()
    if (inFlight === 0) {
      finish()
    }
  })
}

async function runScenario(profile: Profile, scenario: Scenario): Promise<ScenarioResult> {
  const payload = payloadOfSize(scenario.payloadBytes)
  const template: BenchEnvelopeTemplate = {
    headerBase: {
      version: '7h3/0.1',
      ttlMs: 120_000,
      sender: 'bench.sender',
      recipient: 'bench.receiver',
    },
    intent: 'TASK',
    capability: 'task.plan',
  }

  const adapter: TransportAdapter | null =
    scenario.mode === 'inproc' ? new InProcessAdapter() : scenario.mode === 'http' ? new HttpAdapter() : scenario.mode === 'ws' ? new WsAdapter() : null

  try {
    if (adapter) await adapter.start()

    let sequence = 0
    const execute = async (content: string): Promise<TransportTrace & { buildMs: number; canonicalizeMs: number; macMs: number }> => {
      if (scenario.mode === 'agent-loop') {
        const buildStart = performance.now()
        await runAgentLoop(content)
        return {
          buildMs: performance.now() - buildStart,
          canonicalizeMs: 0,
          macMs: 0,
          queueMs: 0,
          transportMs: 0,
          verifyMs: 0,
          decodeMs: 0,
        }
      }

      sequence += 1
      const built = await buildSignAndEncodeEnvelope(template, content, sequence)
      const trace = await adapter!.send(built.raw)
      return {
        ...trace,
        buildMs: built.buildMs,
        canonicalizeMs: built.canonicalizeMs,
        macMs: built.macMs,
      }
    }

    await runPhase({
      durationMs: profile.warmupMs,
      concurrency: scenario.concurrency,
      payload,
      execute,
      collectLatencies: false,
    })

    maybeGc()
    const cpuStart = process.cpuUsage()
    const memStart = process.memoryUsage()

    const measured = await runPhase({
      durationMs: profile.measureMs,
      concurrency: scenario.concurrency,
      payload,
      execute,
      collectLatencies: true,
    })

    const cpuEnd = process.cpuUsage(cpuStart)
    const memEnd = process.memoryUsage()
    const elapsedSeconds = profile.measureMs / 1000

    const sortedLatencies = measured.latencies.slice().sort((a, b) => a - b)
    const completed = measured.completed
    const opsPerSecond = completed / elapsedSeconds
    const cpuMs = (cpuEnd.user + cpuEnd.system) / 1000
    const stageScale = completed > 0 ? 1 / completed : 0

    const cpuMsPer10kOps = completed > 0 ? cpuMs / (completed / 10_000) : 0
    const heapDeltaBytes = memEnd.heapUsed - memStart.heapUsed
    const rssDeltaBytes = memEnd.rss - memStart.rss

    return {
      mode: scenario.mode,
      payloadBytes: scenario.payloadBytes,
      concurrency: scenario.concurrency,
      ops: completed,
      opsPerSecond: round3(opsPerSecond),
      p50Ms: round3(percentile(sortedLatencies, 50)),
      p95Ms: round3(percentile(sortedLatencies, 95)),
      p99Ms: round3(percentile(sortedLatencies, 99)),
      cpuMsPer10kOps: round3(cpuMsPer10kOps),
      heapDeltaMb: round3(heapDeltaBytes / (1024 * 1024)),
      rssDeltaMb: round3(rssDeltaBytes / (1024 * 1024)),
      allocBytesPerOp: round3(completed > 0 ? heapDeltaBytes / completed : 0),
      stageBuildMsPerOp: round3(measured.stages.buildMs * stageScale),
      stageCanonicalizeMsPerOp: round3(measured.stages.canonicalizeMs * stageScale),
      stageMacMsPerOp: round3(measured.stages.macMs * stageScale),
      stageQueueMsPerOp: round3(measured.stages.queueMs * stageScale),
      stageTransportMsPerOp: round3(measured.stages.transportMs * stageScale),
      stageVerifyMsPerOp: round3(measured.stages.verifyMs * stageScale),
      stageDecodeMsPerOp: round3(measured.stages.decodeMs * stageScale),
    }
  } finally {
    if (adapter) await adapter.stop()
  }
}

function renderMarkdown(profileName: ProfileName, profile: Profile, rows: ScenarioResult[]): string {
  const lines: string[] = []
  lines.push(`# Protocol E2E Benchmark (${profileName})`)
  lines.push('')
  lines.push(`- Warmup: ${profile.warmupMs}ms`)
  lines.push(`- Measure: ${profile.measureMs}ms`)
  lines.push('- Pipeline: build -> canonicalize -> MAC -> queue -> transport -> verify -> decode')
  lines.push('')
  lines.push('| mode | payload | concurrency | ops/s | p50 ms | p95 ms | p99 ms | cpu/10k ms | build ms/op | canon ms/op | mac ms/op | queue ms/op | transport ms/op | verify ms/op | decode ms/op |')
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |')

  for (const row of rows) {
    lines.push(
      `| ${row.mode} | ${row.payloadBytes} | ${row.concurrency} | ${row.opsPerSecond} | ${row.p50Ms} | ${row.p95Ms} | ${row.p99Ms} | ${row.cpuMsPer10kOps} | ${row.stageBuildMsPerOp} | ${row.stageCanonicalizeMsPerOp} | ${row.stageMacMsPerOp} | ${row.stageQueueMsPerOp} | ${row.stageTransportMsPerOp} | ${row.stageVerifyMsPerOp} | ${row.stageDecodeMsPerOp} |`,
    )
  }

  return `${lines.join('\n')}\n`
}

async function main(): Promise<void> {
  const profileName = parseProfile(process.argv)
  const profile = PROFILES[profileName]
  if (!profile) {
    throw new Error(`Unknown profile '${profileName}'`)
  }

  const modes = parseModeSelection(process.argv, ['inproc', 'http', 'ws', 'agent-loop'])
  const payloadSizes = parseNumberSelection(process.argv, '--payloads', PAYLOAD_SIZES)
  const concurrencyLevels = parseNumberSelection(process.argv, '--concurrency', CONCURRENCY_LEVELS)
  const scenarios: Scenario[] = []
  for (const mode of modes) {
    for (const payloadBytes of payloadSizes) {
      for (const concurrency of concurrencyLevels) {
        scenarios.push({ mode, payloadBytes, concurrency })
      }
    }
  }

  const rows: ScenarioResult[] = []
  for (const scenario of scenarios) {
    const label = `[${scenario.mode}] payload=${scenario.payloadBytes}B concurrency=${scenario.concurrency}`
    console.log(`Running ${label}`)
    const result = await runScenario(profile, scenario)
    rows.push(result)
    console.log(
      `  ops/s=${result.opsPerSecond} p99=${result.p99Ms}ms build=${result.stageBuildMsPerOp}ms canon=${result.stageCanonicalizeMsPerOp}ms mac=${result.stageMacMsPerOp}ms transport=${result.stageTransportMsPerOp}ms verify=${result.stageVerifyMsPerOp}ms`,
    )
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
  const outputDir = 'dist/bench'
  await mkdir(outputDir, { recursive: true })

  const jsonPath = `${outputDir}/protocol-e2e.${profileName}.${timestamp}.json`
  const mdPath = `${outputDir}/protocol-e2e.${profileName}.${timestamp}.md`
  const latestJsonPath = `${outputDir}/protocol-e2e.${profileName}.latest.json`
  const latestMdPath = `${outputDir}/protocol-e2e.${profileName}.latest.md`

  const payload = {
    profile: profileName,
    warmupMs: profile.warmupMs,
    measureMs: profile.measureMs,
    results: rows,
  }

  await writeFile(jsonPath, JSON.stringify(payload, null, 2), 'utf8')
  await writeFile(latestJsonPath, JSON.stringify(payload, null, 2), 'utf8')

  const markdown = renderMarkdown(profileName, profile, rows)
  await writeFile(mdPath, markdown, 'utf8')
  await writeFile(latestMdPath, markdown, 'utf8')

  console.log('')
  console.log(`Wrote ${jsonPath}`)
  console.log(`Wrote ${mdPath}`)
  console.log(`Updated ${latestJsonPath}`)
  console.log(`Updated ${latestMdPath}`)
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
