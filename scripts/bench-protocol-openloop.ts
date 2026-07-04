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
import {
  InMemoryVerificationMaterialCache,
  decodeEnvelope,
  encodeEnvelope,
  receiveEnvelope,
} from '../src/protocolTransport'

type Mode = 'http' | 'ws' | 'http-binary' | 'http-batch' | 'http-binary-batch' | 'ws-batch' | 'ws-binary' | 'ws-binary-batch'
type ProfileName = 'quick' | 'full'
type RawEnvelope = string | Uint8Array

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

interface ResultRow {
  mode: Mode
  payloadBytes: number
  concurrency: number
  targetOpsPerSecond: number
  launched: number
  completed: number
  dropped: number
  dropPct: number
  sustainable: boolean
  opsPerSecond: number
  p50Ms: number
  p95Ms: number
  p99Ms: number
  cpuMsPer10kOps: number
  stageBuildMsPerOp: number
  stageCanonicalizeMsPerOp: number
  stageMacMsPerOp: number
  stageQueueMsPerOp: number
  stageTransportMsPerOp: number
  stageVerifyMsPerOp: number
  stageDecodeMsPerOp: number
}

interface AdaptiveConfig {
  enabled: boolean
  p99ThresholdMs: number
  dropThresholdPct: number
  maxDoublings: number
  binarySteps: number
}

interface ScenarioSelection {
  ciPreset: boolean
  modes: Mode[]
  payloadSizes: number[]
  concurrencyLevels: number[]
  allowUnsafeHttp: boolean
}

interface TransportTrace {
  queueMs: number
  transportMs: number
  verifyMs: number
  decodeMs: number
}

interface TransportAdapter {
  start(): Promise<void>
  send(rawEnvelope: RawEnvelope): Promise<TransportTrace>
  sendBatch(rawEnvelopes: RawEnvelope[]): Promise<TransportTrace[]>
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
const BATCH_SIZE = 32
const MAX_LATENCY_SAMPLES = 200_000
const WS_BINARY_MAGIC = [0x41, 0x49, 0x50, 0x46] as const // AIPF
const WS_BINARY_VERSION = 1
const WS_BINARY_KIND_SINGLE = 1
const WS_BINARY_KIND_BATCH = 2
const PAYLOAD_SIZES = [256, 1024, 4096, 16384]
const CONCURRENCY_LEVELS = [1, 10, 100, 1000]
const PROFILES: Record<ProfileName, Profile> = {
  quick: { warmupMs: 300, measureMs: 1500 },
  full: { warmupMs: 1200, measureMs: 8000 },
}

function parseProfile(argv: string[]): ProfileName {
  const idx = argv.indexOf('--profile')
  if (idx >= 0) {
    const value = argv[idx + 1]
    if (value === 'quick' || value === 'full') return value
  }
  return 'quick'
}

function hasFlag(flag: string, argv: string[]): boolean {
  return argv.includes(flag)
}

function parseNumberArgFromArgv(flag: string, argv: string[], fallback: number): number {
  const idx = argv.indexOf(flag)
  if (idx < 0) return fallback
  const raw = argv[idx + 1]
  if (!raw) return fallback
  const value = Number(raw)
  return Number.isFinite(value) ? value : fallback
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
  const allowed = new Set<Mode>(['http', 'ws', 'http-binary', 'http-batch', 'http-binary-batch', 'ws-batch', 'ws-binary', 'ws-binary-batch'])
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

function buildScenarioSelection(argv: string[]): ScenarioSelection {
  const ciPreset = hasFlag('--ci', argv)
  const allowUnsafeHttp = hasFlag('--allow-unsafe-http', argv)
  const defaultModes: Mode[] = ciPreset
    ? ['ws', 'ws-batch']
    : ['http', 'ws', 'http-binary', 'http-batch', 'http-binary-batch', 'ws-batch', 'ws-binary', 'ws-binary-batch']
  const defaultPayloads = ciPreset ? [256, 1024, 4096] : PAYLOAD_SIZES
  const defaultConcurrency = ciPreset ? [10, 100] : CONCURRENCY_LEVELS

  return {
    ciPreset,
    modes: parseModeSelection(argv, defaultModes),
    payloadSizes: parseNumberSelection(argv, '--payloads', defaultPayloads),
    concurrencyLevels: parseNumberSelection(argv, '--concurrency', defaultConcurrency),
    allowUnsafeHttp,
  }
}

function enforceHttpGuardrails(selection: ScenarioSelection): void {
  if (selection.allowUnsafeHttp) return

  const hasPlainHttp = selection.modes.includes('http')
  const hasHighConcurrency = selection.concurrencyLevels.some((level) => level >= 100)

  if (hasPlainHttp && hasHighConcurrency) {
    throw new Error(
      'Guardrail: plain http with concurrency >= 100 is blocked by default. Use http-binary-batch/ws-binary-batch, lower concurrency, or pass --allow-unsafe-http for stress runs.',
    )
  }
}

function round3(value: number): number {
  return Number(value.toFixed(3))
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0
  const index = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[index] ?? 0
}

function payloadOfSize(bytes: number): string {
  return bytes > 0 ? 'x'.repeat(bytes) : ''
}

function nowMs(): number {
  return Date.now()
}

function delayMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function emptyStages(): StageTotals {
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

function addStages(target: StageTotals, source: StageTotals): void {
  target.buildMs += source.buildMs
  target.canonicalizeMs += source.canonicalizeMs
  target.macMs += source.macMs
  target.queueMs += source.queueMs
  target.transportMs += source.transportMs
  target.verifyMs += source.verifyMs
  target.decodeMs += source.decodeMs
}

function targetRateFor(mode: Mode, concurrency: number): number {
  const perWorker =
    mode === 'http'
      ? 650
      : mode === 'ws' || mode === 'ws-binary'
        ? 900
        : mode === 'http-batch'
          ? 900
          : 1200
  return perWorker * concurrency
}

function isBinaryMode(mode: Mode): boolean {
  return mode === 'ws-binary' || mode === 'ws-binary-batch' || mode === 'http-binary' || mode === 'http-binary-batch'
}

function requireTextEnvelope(rawEnvelope: RawEnvelope): string {
  if (typeof rawEnvelope !== 'string') {
    throw new Error('HTTP transport requires string envelopes')
  }
  return rawEnvelope
}

function normalizeWsBytes(data: WebSocket.RawData): Uint8Array {
  if (Buffer.isBuffer(data)) return data
  if (data instanceof ArrayBuffer) return new Uint8Array(data)
  if (Array.isArray(data)) return Buffer.concat(data)
  return Buffer.from(data)
}

function encodeWsBinaryFrame(id: number, payloads: Uint8Array[]): Buffer {
  const size = 4 + 1 + 1 + 4 + 2 + payloads.reduce((total, payload) => total + 4 + payload.byteLength, 0)
  const out = Buffer.allocUnsafe(size)
  let offset = 0
  for (const value of WS_BINARY_MAGIC) {
    out[offset] = value
    offset += 1
  }
  out[offset] = WS_BINARY_VERSION
  offset += 1
  out[offset] = payloads.length === 1 ? WS_BINARY_KIND_SINGLE : WS_BINARY_KIND_BATCH
  offset += 1
  out.writeUInt32BE(id, offset)
  offset += 4
  out.writeUInt16BE(payloads.length, offset)
  offset += 2
  for (const payload of payloads) {
    out.writeUInt32BE(payload.byteLength, offset)
    offset += 4
    out.set(payload, offset)
    offset += payload.byteLength
  }
  return out
}

function decodeWsBinaryFrame(data: Uint8Array): { id: number; payloads: Uint8Array[] } | null {
  if (data.byteLength < 12) return null
  for (let index = 0; index < WS_BINARY_MAGIC.length; index += 1) {
    if (data[index] !== WS_BINARY_MAGIC[index]) return null
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const version = data[4]
  const kind = data[5]
  if (version !== WS_BINARY_VERSION || (kind !== WS_BINARY_KIND_SINGLE && kind !== WS_BINARY_KIND_BATCH)) return null
  const id = view.getUint32(6, false)
  const count = view.getUint16(10, false)
  if (count === 0 || (kind === WS_BINARY_KIND_SINGLE && count !== 1)) return null

  let offset = 12
  const payloads: Uint8Array[] = []
  for (let index = 0; index < count; index += 1) {
    if (data.byteLength - offset < 4) return null
    const length = view.getUint32(offset, false)
    offset += 4
    if (data.byteLength - offset < length) return null
    payloads.push(data.slice(offset, offset + length))
    offset += length
  }
  return offset === data.byteLength ? { id, payloads } : null
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

function recordLatencySamples(latencies: number[], completed: number, elapsedMs: number, count: number): void {
  for (let i = 0; i < count; i += 1) {
    if (latencies.length < MAX_LATENCY_SAMPLES) {
      latencies.push(elapsedMs)
      continue
    }
    const sampleIndex = Math.floor(Math.random() * (completed + i + 1))
    if (sampleIndex < MAX_LATENCY_SAMPLES) {
      latencies[sampleIndex] = elapsedMs
    }
  }
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

async function buildSignEncode(
  template: BenchEnvelopeTemplate,
  payload: string,
  sequence: number,
  binary: boolean,
): Promise<{ raw: RawEnvelope; stage: StageTotals }> {
  const stage = emptyStages()

  const buildStart = performance.now()
  const unsigned = buildEnvelope(template, payload, sequence)
  stage.buildMs = performance.now() - buildStart

  const canonicalizeStart = performance.now()
  const canonical = canonicalizeEnvelope(unsigned)
  stage.canonicalizeMs = performance.now() - canonicalizeStart

  const macStart = performance.now()
  const signature = await signCanonicalPayloadHmac(canonical, SHARED_SECRET)
  stage.macMs = performance.now() - macStart

  const envelope: ProtocolEnvelope = {
    ...unsigned,
    signature: {
      alg: 'HS256',
      keyId: 'bench-k1',
      value: signature,
    },
  }

  return { raw: encodeEnvelope(envelope, binary ? 'binary' : 'compact'), stage }
}

class HttpAdapter implements TransportAdapter {
  private readonly replayCache = new InMemoryReplayCache(1_000_000)
  private readonly verificationMaterialCache = new InMemoryVerificationMaterialCache()
  private server: http2.Http2Server | null = null
  private clients: http2.ClientHttp2Session[] = []
  private clientCursor = 0
  private port = 0
  private inFlight = 0
  private readonly maxServerInFlight: number
  private readonly fastAck: boolean
  private readonly batchConcurrency: number
  private readonly binaryMode: boolean
  private readonly binaryBatchMode: boolean
  private readonly poolSize: number
  private readonly requestTimeoutMs: number

  constructor(
    maxServerInFlight = 65536,
    fastAck = true,
    batchConcurrency = 64,
    binaryMode = false,
    binaryBatchMode = false,
    poolSize = 4,
    requestTimeoutMs = 5000,
  ) {
    this.maxServerInFlight = Math.max(64, maxServerInFlight)
    this.fastAck = fastAck
    this.batchConcurrency = Math.max(1, batchConcurrency)
    this.binaryMode = binaryMode
    this.binaryBatchMode = binaryBatchMode
    this.poolSize = Math.max(1, poolSize)
    this.requestTimeoutMs = Math.max(250, requestTimeoutMs)
  }

  private async createClient(): Promise<http2.ClientHttp2Session> {
    const client = http2.connect(`http://127.0.0.1:${this.port}`)
    await new Promise<void>((resolve, reject) => {
      client.once('error', reject)
      client.once('connect', () => {
        client.off('error', reject)
        resolve()
      })
    })
    client.on('error', () => {
      // Ignore background session errors; per-request path handles retries/failures.
    })
    return client
  }

  private isClientUsable(client: http2.ClientHttp2Session | undefined): client is http2.ClientHttp2Session {
    if (!client) return false
    return !(client.closed || client.destroyed)
  }

  private async replaceClient(index: number): Promise<http2.ClientHttp2Session> {
    const current = this.clients[index]
    if (current) {
      current.removeAllListeners('error')
      try {
        current.close()
      } catch {
        // best effort close
      }
    }
    const replacement = await this.createClient()
    this.clients[index] = replacement
    return replacement
  }

  async start(): Promise<void> {
    this.server = http2.createServer({
      settings: {
        maxConcurrentStreams: 65536,
      },
    })

      this.server.on('stream', (stream: http2.ServerHttp2Stream, headers: http2.IncomingHttpHeaders) => {
        stream.on('error', () => {
          // Ignore per-stream protocol errors under overload; client handles retries.
        })

        if (headers[':method'] !== 'POST') {
          stream.respond({ ':status': 405 })
          stream.end()
          return
        }

        if (this.inFlight >= this.maxServerInFlight) {
          stream.respond({
            ':status': 503,
            'content-type': 'application/json',
            'x-retry-after-ms': '2',
          })
          stream.end(JSON.stringify({ ok: false, error: 'overloaded' }))
          return
        }

        this.inFlight += 1
        const chunks: Buffer[] = []
        const queueStart = performance.now()
        stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
        stream.on('end', async () => {
          const queueMs = performance.now() - queueStart
          const isBinary = headers['content-type'] === 'application/aip-binary'
          const rawBody: string | Uint8Array = isBinary ? Buffer.concat(chunks) : Buffer.concat(chunks).toString('utf8')
        const path = typeof headers[':path'] === 'string' ? headers[':path'] : '/single'

        if (path === '/batch') {
          try {
            const isBinaryBatch = headers['content-type'] === 'application/aip-binary-batch'
            const payloads = isBinaryBatch
              ? (JSON.parse(rawBody as string) as string[]).map((b64) => Buffer.from(b64, 'base64'))
              : (JSON.parse(rawBody as string) as string[])
            if (!Array.isArray(payloads)) {
              stream.respond({ ':status': 400, 'content-type': 'application/json' })
              stream.end(JSON.stringify({ ok: false, error: 'batch payload must be array' }))
              return
            }

            const decodedItems = payloads.map((payload) => {
              const decodeStart = performance.now()
              const decoded = decodeEnvelope(payload)
              const decodeMs = performance.now() - decodeStart
              return { payload, decoded, decodeMs }
            })

            const results: ServerAck[] = new Array(decodedItems.length)
            let nextIndex = 0
            const workerCount = Math.min(this.batchConcurrency, decodedItems.length)

            const worker = async () => {
              while (nextIndex < decodedItems.length) {
                const index = nextIndex
                nextIndex += 1
                const { decoded, decodeMs } = decodedItems[index]

                if (!decoded.ok || !decoded.envelope) {
                  results[index] = { ok: false, queueMs, verifyMs: 0, decodeMs, error: 'decode failed' }
                  continue
                }

                const verifyStart = performance.now()
                const result = await receiveEnvelope(decoded.envelope, {
                  nowMs: nowMs(),
                  replayCache: this.replayCache,
                  verificationMaterialCache: this.verificationMaterialCache,
                  secretResolver: SHARED_SECRET_RESOLVER,
                })
                const verifyMs = performance.now() - verifyStart
                results[index] = {
                  ok: result.ok,
                  queueMs,
                  verifyMs,
                  decodeMs,
                  error: result.ok ? undefined : result.diagnostics.map((d) => d.message).join('; '),
                }
              }
            }

            await Promise.all(Array.from({ length: workerCount }, () => worker()))
            stream.respond({ ':status': results.some((r) => !r.ok) ? 400 : 200, 'content-type': 'application/json' })
            stream.end(JSON.stringify(results))
          } catch {
            stream.respond({ ':status': 500, 'content-type': 'application/json' })
            stream.end(JSON.stringify({ ok: false, error: 'internal http batch error' }))
          } finally {
            this.inFlight -= 1
          }
          return
        }

        try {
          const decodeStart = performance.now()
          const decoded = decodeEnvelope(rawBody)
          const decodeMs = performance.now() - decodeStart
          if (!decoded.ok || !decoded.envelope) {
            stream.respond({ ':status': 400, 'content-type': 'application/json' })
            stream.end(JSON.stringify({ ok: false, queueMs, verifyMs: 0, decodeMs, error: 'decode failed' }))
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
            verifyMs,
            decodeMs,
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
          stream.end(JSON.stringify({ ok: false, queueMs, verifyMs: 0, decodeMs: 0, error: 'internal http receive error' }))
        } finally {
          this.inFlight -= 1
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

    this.clients = await Promise.all(Array.from({ length: this.poolSize }, async () => this.createClient()))
  }

  async send(rawEnvelope: RawEnvelope): Promise<TransportTrace> {
    const body = this.binaryMode ? rawEnvelope : requireTextEnvelope(rawEnvelope)
    const { body: responseBody, elapsedMs, headers } = await this.request('/single', body)
    const ack = this.fastAck && readHeaderString(headers, ACK_HEADER_OK) === '1' ? ackFromHeaders(headers) : parseServerAck(responseBody)
    if (!ack.ok) throw new Error(ack.error ?? 'http single send failed')
    return {
      queueMs: ack.queueMs,
      transportMs: elapsedMs,
      verifyMs: ack.verifyMs,
      decodeMs: ack.decodeMs,
    }
  }

  async sendBatch(rawEnvelopes: RawEnvelope[]): Promise<TransportTrace[]> {
    let body: string
    let contentType: string
    if (this.binaryBatchMode) {
      contentType = 'application/aip-binary-batch'
      body = JSON.stringify(rawEnvelopes.map((e) => Buffer.from(e as Uint8Array).toString('base64')))
    } else if (this.binaryMode) {
      contentType = 'application/aip-binary'
      body = JSON.stringify(rawEnvelopes.map((e) => Buffer.from(e as Uint8Array).toString('base64')))
    } else {
      contentType = 'application/json'
      body = JSON.stringify(rawEnvelopes.map(requireTextEnvelope))
    }
    const { body: responseBody, elapsedMs } = await this.request('/batch', body, contentType)
    const parsed = JSON.parse(responseBody) as ServerAck[]
    if (!Array.isArray(parsed)) throw new Error('http batch response is not an array')
    return parsed.map((ack) => {
      if (!ack.ok) throw new Error(ack.error ?? 'http batch item failed')
      return {
        queueMs: ack.queueMs,
        transportMs: elapsedMs,
        verifyMs: ack.verifyMs,
        decodeMs: ack.decodeMs,
      }
    })
  }

  private async request(
    path: '/single' | '/batch',
    body: string | Uint8Array,
    contentType?: string,
  ): Promise<{ body: string; elapsedMs: number; headers: http2.IncomingHttpHeaders }> {
    const maxAttempts = 3
    let lastError: Error | null = null

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      const transportStart = performance.now()

      try {
        if (this.clients.length === 0) {
          throw new Error('HTTP/2 client pool is not started')
        }

        const clientIndex = this.clientCursor % this.clients.length
        let client = this.clients[clientIndex]
        if (!client) {
          throw new Error('No HTTP/2 client available in pool')
        }
        if (!this.isClientUsable(client)) {
          client = await this.replaceClient(clientIndex)
        }
        this.clientCursor = (this.clientCursor + 1) % this.clients.length

        const isBinaryBody = body instanceof Uint8Array
        const request = client.request({
          ':method': 'POST',
          ':path': path,
          'content-type': contentType ?? (isBinaryBody ? 'application/aip-binary' : 'application/json'),
        })
        request.setTimeout(this.requestTimeoutMs, () => {
          request.close(http2.constants.NGHTTP2_CANCEL)
        })

        const responsePromise = new Promise<{ body: string; headers: http2.IncomingHttpHeaders }>((resolve, reject) => {
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
            const payload = Buffer.concat(chunks).toString('utf8')
            if (statusCode >= 400) {
              const error = new Error(`http status ${statusCode}: ${payload}`)
              ;(error as Error & { statusCode?: number; retryAfterMs?: number }).statusCode = statusCode
              const retryAfter = responseHeaders['x-retry-after-ms']
              if (typeof retryAfter === 'string') {
                const parsed = Number(retryAfter)
                if (Number.isFinite(parsed) && parsed > 0) {
                  ;(error as Error & { retryAfterMs?: number }).retryAfterMs = parsed
                }
              }
              reject(error)
              return
            }
            resolve({ body: payload, headers: responseHeaders })
          })

          request.on('error', reject)
        })

        if (isBinaryBody) {
          request.write(body)
          request.end()
        } else {
          request.end(body)
        }

        const result = await responsePromise
        return { ...result, elapsedMs: performance.now() - transportStart }
      } catch (error) {
        const typed = error as Error & { statusCode?: number; retryAfterMs?: number; code?: string }
        if (typed.code === 'ERR_HTTP2_SESSION_ERROR' || typed.code === 'ERR_HTTP2_STREAM_ERROR') {
          const staleIndex = (this.clientCursor - 1 + this.clients.length) % this.clients.length
          try {
            await this.replaceClient(staleIndex)
          } catch {
            // keep retry path alive even if immediate replacement fails
          }
        }
        const retriable =
          typed.statusCode === 503 ||
          typed.code === 'ERR_HTTP2_SESSION_ERROR' ||
          typed.code === 'ERR_HTTP2_STREAM_ERROR' ||
          typed.code === 'ERR_HTTP2_INVALID_SESSION'
        lastError = typed
        if (!retriable || attempt === maxAttempts) {
          break
        }
        const backoff = typed.retryAfterMs ?? Math.min(16, 2 ** attempt)
        await delayMs(backoff)
      }
    }

    throw lastError ?? new Error('HTTP request failed')
  }

  async stop(): Promise<void> {
    const clients = this.clients.splice(0, this.clients.length)
    await Promise.all(
      clients.map(
        (client) =>
          new Promise<void>((resolve) => {
            client.once('close', () => resolve())
            client.close()
          }),
      ),
    )
    this.clientCursor = 0
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
  if (Array.isArray(value)) {
    const first = value[0]
    return typeof first === 'string' ? first : undefined
  }
  if (typeof value === 'number') return String(value)
  return undefined
}

function readHeaderNumber(headers: http2.IncomingHttpHeaders, key: string): number {
  const raw = readHeaderString(headers, key)
  if (!raw) return 0
  const value = Number(raw)
  return Number.isFinite(value) ? value : 0
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
  private readonly pending = new Map<number, { resolve: (value: TransportTrace[]) => void; reject: (error: Error) => void }>()

  private readonly binaryFrames: boolean

  constructor(binaryFrames = false) {
    this.binaryFrames = binaryFrames
  }

  async start(): Promise<void> {
    this.server = new WebSocketServer({ port: 0, host: '127.0.0.1' })

    this.server.on('connection', (socket) => {
      socket.on('message', async (data) => {
        const binaryFrame = this.binaryFrames ? decodeWsBinaryFrame(normalizeWsBytes(data)) : null
        let frame: { id: number; payloads: RawEnvelope[] }
        if (binaryFrame) {
          frame = binaryFrame
        } else {
          try {
            const parsed = JSON.parse(Buffer.isBuffer(data) ? data.toString('utf8') : String(data)) as {
              id: number
              payload?: string
              payloads?: string[]
            }
            frame = { id: parsed.id, payloads: parsed.payloads ?? (parsed.payload ? [parsed.payload] : []) }
          } catch {
            socket.send(Buffer.from(JSON.stringify({ id: 0, ok: false, traces: [], error: 'invalid frame' }), 'utf8'))
            return
          }
        }

        const payloads = frame.payloads
        const traces: Array<ServerAck> = []

        for (const payload of payloads) {
          const queueStart = performance.now()
          const decodeStart = performance.now()
          const decoded = decodeEnvelope(payload)
          const decodeMs = performance.now() - decodeStart
          const queueMs = performance.now() - queueStart

          if (!decoded.ok || !decoded.envelope) {
            traces.push({ ok: false, queueMs, decodeMs, verifyMs: 0, error: 'decode failed' })
            continue
          }

          const verifyStart = performance.now()
          const result = await receiveEnvelope(decoded.envelope, {
            nowMs: nowMs(),
            replayCache: this.replayCache,
            verificationMaterialCache: this.verificationMaterialCache,
            secretResolver: SHARED_SECRET_RESOLVER,
          })
          const verifyMs = performance.now() - verifyStart
          traces.push({
            ok: result.ok,
            queueMs,
            verifyMs,
            decodeMs,
            error: result.ok ? undefined : result.diagnostics.map((d) => d.message).join('; '),
          })
        }

        socket.send(Buffer.from(JSON.stringify({ id: frame.id, traces }), 'utf8'))
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
      let frame: { id: number; traces: ServerAck[] }
      try {
        frame = JSON.parse(Buffer.isBuffer(data) ? data.toString('utf8') : String(data)) as {
          id: number
          traces: ServerAck[]
        }
      } catch {
        return
      }

      const pending = this.pending.get(frame.id)
      if (!pending) return
      this.pending.delete(frame.id)

      if (!Array.isArray(frame.traces) || frame.traces.some((trace) => !trace.ok)) {
        const firstError = frame.traces.find((trace) => !trace.ok)?.error ?? 'ws trace error'
        pending.reject(new Error(firstError))
        return
      }

      pending.resolve(
        frame.traces.map((trace) => ({
          queueMs: trace.queueMs,
          transportMs: trace.queueMs + trace.decodeMs + trace.verifyMs,
          verifyMs: trace.verifyMs,
          decodeMs: trace.decodeMs,
        })),
      )
    })
  }

  async send(rawEnvelope: RawEnvelope): Promise<TransportTrace> {
    const traces = await this.sendFrame([rawEnvelope])
    return traces[0] as TransportTrace
  }

  async sendBatch(rawEnvelopes: RawEnvelope[]): Promise<TransportTrace[]> {
    return this.sendFrame(rawEnvelopes)
  }

  private async sendFrame(payloads: RawEnvelope[]): Promise<TransportTrace[]> {
    if (!this.client || this.client.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket client is not open')
    }

    const id = this.nextId
    this.nextId += 1
    const sendStart = performance.now()

    const completion = new Promise<TransportTrace[]>((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
    })

    if (this.binaryFrames) {
      const binaryPayloads = payloads.map((payload) => {
        if (!(payload instanceof Uint8Array)) throw new Error('Binary WebSocket mode requires binary envelopes')
        return payload
      })
      this.client.send(encodeWsBinaryFrame(id, binaryPayloads))
    } else {
      const textPayloads = payloads.map(requireTextEnvelope)
      const frame = textPayloads.length === 1 ? { id, payload: textPayloads[0] } : { id, payloads: textPayloads }
      this.client.send(Buffer.from(JSON.stringify(frame), 'utf8'))
    }
    const traces = await completion
    const elapsed = performance.now() - sendStart
    return traces.map((trace) => ({ ...trace, transportMs: elapsed }))
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

async function runOpenLoopScenario(profile: Profile, scenario: Scenario, targetRate: number, adaptive?: AdaptiveConfig): Promise<ResultRow> {
  const effectiveMode: Mode =
    scenario.mode === 'http' && scenario.concurrency >= 100 ? 'http-binary-batch' : scenario.mode
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

  const binaryWire = isBinaryMode(effectiveMode)
  const isHttp = effectiveMode.startsWith('http')
  const batchMode = effectiveMode.endsWith('batch')
  const binaryBatchMode = effectiveMode === 'http-binary-batch'
  const adapter = isHttp
    ? new HttpAdapter(Math.max(4096, scenario.concurrency * 16), true, 64, binaryWire && !batchMode, binaryBatchMode)
    : new WsAdapter(binaryWire)
  await adapter.start()

  let sequence = 0
  let inFlight = 0
  let launched = 0
  let completed = 0
  let dropped = 0
  const latencies: number[] = []
  const stageTotals = emptyStages()
  const tokensPerMs = targetRate / 1000
  const maxInFlight = Math.max(scenario.concurrency * 2, 32)
  const minInFlightCap = Math.max(8, scenario.concurrency)
  const maxInFlightCap = Math.max(maxInFlight, scenario.concurrency * 8)
  let dynamicInFlightCap = Math.max(minInFlightCap, Math.min(maxInFlightCap, maxInFlight))
  const baseBatchSize = batchMode ? BATCH_SIZE : 1
  const minBatchSize = batchMode ? 4 : 1
  const maxBatchSize = batchMode ? Math.max(BATCH_SIZE, 64) : 1
  let dynamicBatchSize = baseBatchSize
  let latencyEwmaMs = 0
  const latencyAlpha = 0.15

  const tuneFlowControl = (opLatencyMs: number, hadError: boolean): void => {
    latencyEwmaMs = latencyEwmaMs <= 0 ? opLatencyMs : latencyEwmaMs * (1 - latencyAlpha) + opLatencyMs * latencyAlpha

    if (hadError) {
      dynamicInFlightCap = Math.max(minInFlightCap, Math.floor(dynamicInFlightCap * 0.85))
      if (batchMode) {
        dynamicBatchSize = Math.max(minBatchSize, Math.floor(dynamicBatchSize * 0.8))
      }
      return
    }

    if (latencyEwmaMs > 25) {
      dynamicInFlightCap = Math.max(minInFlightCap, dynamicInFlightCap - 1)
      if (batchMode) dynamicBatchSize = Math.max(minBatchSize, dynamicBatchSize - 1)
      return
    }

    if (latencyEwmaMs < 8 && inFlight < dynamicInFlightCap * 0.8) {
      dynamicInFlightCap = Math.min(maxInFlightCap, dynamicInFlightCap + 1)
      if (batchMode) dynamicBatchSize = Math.min(maxBatchSize, dynamicBatchSize + 1)
    }
  }

  const runWindow = async (durationMs: number, collect: boolean): Promise<void> => {
    const start = performance.now()
    let credits = 0
    let lastTick = start

    while (performance.now() - start < durationMs || inFlight > 0) {
      const now = performance.now()
      const delta = now - lastTick
      lastTick = now
      if (performance.now() - start < durationMs) {
        credits += tokensPerMs * delta
      }

      const launches = Math.floor(credits)
      credits -= launches

      for (let i = 0; i < launches; i += 1) {
        const batchMode = effectiveMode.endsWith('batch')
        const opCount = batchMode ? dynamicBatchSize : 1
        if (inFlight >= dynamicInFlightCap) {
          credits += 1
          tuneFlowControl(30, true)
          break
        }

        inFlight += 1
        launched += opCount
        const opStart = performance.now()

        const dispatch = async (): Promise<void> => {
          let hadError = false
          try {
            const raws: RawEnvelope[] = []
            const stage = emptyStages()
            for (let j = 0; j < opCount; j += 1) {
              sequence += 1
              const built = await buildSignEncode(template, payload, sequence, binaryWire)
              raws.push(built.raw)
              addStages(stage, built.stage)
            }

            const first = raws[0]
            if (!first) throw new Error('No envelope built for dispatch')
            const traces = batchMode ? await adapter.sendBatch(raws) : [await adapter.send(first)]
            for (const trace of traces) {
              stage.queueMs += trace.queueMs
              stage.transportMs += trace.transportMs
              stage.verifyMs += trace.verifyMs
              stage.decodeMs += trace.decodeMs
            }

            if (collect) {
              completed += opCount
              addStages(stageTotals, stage)
              const opLatency = (performance.now() - opStart) / opCount
              recordLatencySamples(latencies, completed, opLatency, opCount)
              tuneFlowControl(opLatency, false)
            }
          } catch (error) {
            hadError = true
            if (collect) {
              const message = error instanceof Error ? error.message : String(error)
              const stillInActiveWindow = performance.now() - start < durationMs
              if (message.includes('http status 503') && stillInActiveWindow) {
                credits += 1
              } else {
                dropped += opCount
              }
            }
          } finally {
            if (collect && hadError) {
              const opLatency = performance.now() - opStart
              tuneFlowControl(opLatency, true)
            }
          }
        }

        void dispatch().finally(() => {
          inFlight -= 1
        })
      }

      await new Promise<void>((resolve) => setImmediate(resolve))
    }
  }

  try {
    await runWindow(profile.warmupMs, false)

    const cpuStart = process.cpuUsage()
    await runWindow(profile.measureMs, true)
    const cpuEnd = process.cpuUsage(cpuStart)

    const sortedLatencies = latencies.slice().sort((a, b) => a - b)
    const opsPerSecond = completed / (profile.measureMs / 1000)
    const cpuMs = (cpuEnd.user + cpuEnd.system) / 1000
    const stageScale = completed > 0 ? 1 / completed : 0
    const totalAttempts = completed + dropped
    const dropPct = totalAttempts > 0 ? (dropped / totalAttempts) * 100 : 0

    const result: ResultRow = {
      mode: effectiveMode,
      payloadBytes: scenario.payloadBytes,
      concurrency: scenario.concurrency,
      targetOpsPerSecond: round3(targetRate),
      launched,
      completed,
      dropped,
      dropPct: round3(dropPct),
      sustainable: false,
      opsPerSecond: round3(opsPerSecond),
      p50Ms: round3(percentile(sortedLatencies, 50)),
      p95Ms: round3(percentile(sortedLatencies, 95)),
      p99Ms: round3(percentile(sortedLatencies, 99)),
      cpuMsPer10kOps: round3(completed > 0 ? cpuMs / (completed / 10_000) : 0),
      stageBuildMsPerOp: round3(stageTotals.buildMs * stageScale),
      stageCanonicalizeMsPerOp: round3(stageTotals.canonicalizeMs * stageScale),
      stageMacMsPerOp: round3(stageTotals.macMs * stageScale),
      stageQueueMsPerOp: round3(stageTotals.queueMs * stageScale),
      stageTransportMsPerOp: round3(stageTotals.transportMs * stageScale),
      stageVerifyMsPerOp: round3(stageTotals.verifyMs * stageScale),
      stageDecodeMsPerOp: round3(stageTotals.decodeMs * stageScale),
    }

    if (adaptive) {
      result.sustainable = isSustainable(result, adaptive)
    }

    return result
  } finally {
    await adapter.stop()
  }
}

function isSustainable(row: ResultRow, adaptive: AdaptiveConfig): boolean {
  return row.p99Ms <= adaptive.p99ThresholdMs && row.dropPct <= adaptive.dropThresholdPct
}

async function runAdaptiveScenario(profile: Profile, scenario: Scenario, adaptive: AdaptiveConfig): Promise<ResultRow> {
  const baseTarget = targetRateFor(scenario.mode, scenario.concurrency)
  let lowTarget = Math.max(1, Math.floor(baseTarget / 8))
  let lowResult = await runOpenLoopScenario(profile, scenario, lowTarget, adaptive)

  let backoffSteps = 0
  while (!isSustainable(lowResult, adaptive) && lowTarget > 1 && backoffSteps < 8) {
    lowTarget = Math.max(1, Math.floor(lowTarget / 2))
    lowResult = await runOpenLoopScenario(profile, scenario, lowTarget, adaptive)
    backoffSteps += 1
  }

  if (!isSustainable(lowResult, adaptive)) {
    return lowResult
  }

  let highTarget = baseTarget
  let highResult = await runOpenLoopScenario(profile, scenario, highTarget, adaptive)
  let best = isSustainable(highResult, adaptive)
    ? {
        ...highResult,
        sustainable: true,
      }
    : {
        ...lowResult,
        sustainable: true,
      }

  let doubling = 0
  while (isSustainable(highResult, adaptive) && doubling < adaptive.maxDoublings) {
    lowTarget = highTarget
    highTarget = Math.floor(highTarget * 2)
    highResult = await runOpenLoopScenario(profile, scenario, highTarget, adaptive)
    if (isSustainable(highResult, adaptive)) {
      best = {
        ...highResult,
        sustainable: true,
      }
    }
    doubling += 1
  }

  let lowerBound = lowTarget
  let upperBound = highTarget
  for (let i = 0; i < adaptive.binarySteps; i += 1) {
    const mid = Math.floor((lowerBound + upperBound) / 2)
    if (mid <= lowerBound) break

    const result = await runOpenLoopScenario(profile, scenario, mid)
    if (isSustainable(result, adaptive)) {
      lowerBound = mid
      best = {
        ...result,
        sustainable: true,
      }
    } else {
      upperBound = mid
    }
  }

  return best
}

function renderMarkdown(profileName: ProfileName, profile: Profile, rows: ResultRow[], selection: ScenarioSelection): string {
  const lines: string[] = []
  lines.push(`# Protocol Open-Loop Benchmark (${profileName})`)
  lines.push('')
  lines.push(`- Warmup: ${profile.warmupMs}ms`)
  lines.push(`- Measure: ${profile.measureMs}ms`)
  lines.push(`- CI preset: ${selection.ciPreset ? 'enabled' : 'disabled'}`)
  lines.push(`- Modes: ${selection.modes.join(', ')}`)
  lines.push(`- Payloads: ${selection.payloadSizes.join(', ')}`)
  lines.push(`- Concurrency: ${selection.concurrencyLevels.join(', ')}`)
  lines.push(`- Batch size for batch modes: ${BATCH_SIZE}`)
  lines.push('')
  lines.push('| mode | payload | concurrency | target ops/s | completed ops/s | dropped | drop % | sustainable | p50 ms | p95 ms | p99 ms | cpu/10k ms | build | canon | mac | queue | transport | verify | decode |')
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |')

  for (const row of rows) {
    lines.push(
      `| ${row.mode} | ${row.payloadBytes} | ${row.concurrency} | ${row.targetOpsPerSecond} | ${row.opsPerSecond} | ${row.dropped} | ${row.dropPct} | ${row.sustainable ? 'yes' : 'no'} | ${row.p50Ms} | ${row.p95Ms} | ${row.p99Ms} | ${row.cpuMsPer10kOps} | ${row.stageBuildMsPerOp} | ${row.stageCanonicalizeMsPerOp} | ${row.stageMacMsPerOp} | ${row.stageQueueMsPerOp} | ${row.stageTransportMsPerOp} | ${row.stageVerifyMsPerOp} | ${row.stageDecodeMsPerOp} |`,
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

  const adaptive: AdaptiveConfig = {
    enabled: hasFlag('--adaptive', process.argv),
    p99ThresholdMs: parseNumberArgFromArgv('--p99-threshold', process.argv, 200),
    dropThresholdPct: parseNumberArgFromArgv('--drop-threshold-pct', process.argv, 1),
    maxDoublings: Math.max(0, Math.floor(parseNumberArgFromArgv('--adaptive-max-doublings', process.argv, 4))),
    binarySteps: Math.max(0, Math.floor(parseNumberArgFromArgv('--adaptive-binary-steps', process.argv, 6))),
  }
  const selection = buildScenarioSelection(process.argv)
  enforceHttpGuardrails(selection)

  const scenarios: Scenario[] = []
  for (const mode of selection.modes) {
    for (const payloadBytes of selection.payloadSizes) {
      for (const concurrency of selection.concurrencyLevels) {
        scenarios.push({ mode, payloadBytes, concurrency })
      }
    }
  }

  const rows: ResultRow[] = []
  for (const scenario of scenarios) {
    console.log(`Running [${scenario.mode}] payload=${scenario.payloadBytes}B concurrency=${scenario.concurrency}`)
    const result = adaptive.enabled
      ? await runAdaptiveScenario(profile, scenario, adaptive)
      : await runOpenLoopScenario(profile, scenario, targetRateFor(scenario.mode, scenario.concurrency), adaptive)
    if (!adaptive.enabled) {
      result.sustainable = isSustainable(result, adaptive)
    }
    rows.push(result)
    const sustainability = result.sustainable ? 'yes' : 'no'
    console.log(
      `  target=${result.targetOpsPerSecond} ops/s=${result.opsPerSecond} dropped=${result.dropped} dropPct=${result.dropPct}% p99=${result.p99Ms}ms sustainable=${sustainability}`,
    )
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
  const outputDir = 'dist/bench'
  await mkdir(outputDir, { recursive: true })

  const jsonPath = `${outputDir}/protocol-openloop.${profileName}.${timestamp}.json`
  const mdPath = `${outputDir}/protocol-openloop.${profileName}.${timestamp}.md`
  const latestJsonPath = `${outputDir}/protocol-openloop.${profileName}.latest.json`
  const latestMdPath = `${outputDir}/protocol-openloop.${profileName}.latest.md`

  const payload = {
    profile: profileName,
    warmupMs: profile.warmupMs,
    measureMs: profile.measureMs,
    batchSize: BATCH_SIZE,
    selection,
    adaptive,
    results: rows,
  }

  await writeFile(jsonPath, JSON.stringify(payload, null, 2), 'utf8')
  await writeFile(latestJsonPath, JSON.stringify(payload, null, 2), 'utf8')

  const markdown = renderMarkdown(profileName, profile, rows, selection)
  await writeFile(mdPath, markdown, 'utf8')
  await writeFile(latestMdPath, markdown, 'utf8')

  console.log('')
  console.log(`Wrote ${jsonPath}`)
  console.log(`Wrote ${mdPath}`)
  console.log(`Updated ${latestJsonPath}`)
  console.log(`Updated ${latestMdPath}`)

  if (adaptive.enabled && rows.some((row) => !row.sustainable)) {
    console.log('Adaptive gate failed: one or more scenarios are not sustainable at discovered rate')
    process.exitCode = 2
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
