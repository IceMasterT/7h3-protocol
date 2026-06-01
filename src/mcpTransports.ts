import readline from 'node:readline'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Readable, Writable } from 'node:stream'
import type { WireEnvelope } from './protocolTransport'

/**
 * Transport adapters for the MCP hardening wrapper.
 *
 * The wrapper (`wrapMcpServer` / `wrapMcpClient`) is transport-agnostic: it
 * operates on `WireEnvelope`s. These adapters connect it to real transports —
 * newline-delimited stdio and HTTP — so a secured server is deployable as-is.
 *
 * Note: the stdio adapter frames one envelope per line and therefore supports
 * the string wire formats (`json`, `compact`). For `binary`, use HTTP.
 */

type WireHandler = (raw: WireEnvelope) => Promise<WireEnvelope>

function assertStringWire(raw: WireEnvelope): string {
  if (typeof raw !== 'string') {
    throw new Error('stdio adapter supports json/compact (string) wire formats; use the HTTP adapter for binary')
  }
  return raw
}

export interface StdioServerHandle {
  close(): void
}

/**
 * Serves a wrapped MCP handler over newline-delimited streams (default
 * `process.stdin` / `process.stdout`). Lines are processed sequentially so
 * responses are emitted in request order.
 */
export function serveMcpOverStdio(
  handle: WireHandler,
  options: { input?: Readable; output?: Writable; onError?: (error: unknown) => void } = {},
): StdioServerHandle {
  const input = options.input ?? process.stdin
  const output = options.output ?? process.stdout
  const rl = readline.createInterface({ input, crlfDelay: Number.POSITIVE_INFINITY })

  let chain: Promise<void> = Promise.resolve()
  const onLine = (line: string): void => {
    const raw = line.trim()
    if (!raw) return
    chain = chain.then(async () => {
      try {
        const response = await handle(raw)
        output.write(`${assertStringWire(response)}\n`)
      } catch (error) {
        options.onError?.(error)
      }
    })
  }

  rl.on('line', onLine)
  return {
    close(): void {
      rl.off('line', onLine)
      rl.close()
    },
  }
}

export interface StdioClientHandle {
  send: WireHandler
  close(): void
}

/**
 * Creates a stdio client `send` function for `wrapMcpClient`. Requests and
 * responses are correlated by order over the single pipe (one envelope per line).
 */
export function createStdioMcpClient(options: { input: Readable; output: Writable }): StdioClientHandle {
  const rl = readline.createInterface({ input: options.input, crlfDelay: Number.POSITIVE_INFINITY })
  const pending: Array<(line: string) => void> = []

  const onLine = (line: string): void => {
    const raw = line.trim()
    if (!raw) return
    const resolve = pending.shift()
    if (resolve) resolve(raw)
  }
  rl.on('line', onLine)

  return {
    send(raw: WireEnvelope): Promise<WireEnvelope> {
      const line = assertStringWire(raw)
      return new Promise<WireEnvelope>((resolve) => {
        pending.push(resolve)
        options.output.write(`${line}\n`)
      })
    },
    close(): void {
      rl.off('line', onLine)
      rl.close()
    },
  }
}

/**
 * Creates a `node:http`-compatible request handler that runs the wrapped MCP
 * handler. The request body is the wire envelope; the response body is the
 * signed reply envelope.
 */
export function createHttpMcpHandler(
  handle: WireHandler,
  options: { binary?: boolean } = {},
): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('error', () => {
      res.writeHead(400)
      res.end()
    })
    req.on('end', () => {
      void (async () => {
        try {
          const buffer = Buffer.concat(chunks)
          const raw: WireEnvelope = options.binary ? new Uint8Array(buffer) : buffer.toString('utf8')
          const response = await handle(raw)
          if (typeof response === 'string') {
            res.writeHead(200, { 'content-type': 'application/json' })
            res.end(response)
          } else {
            res.writeHead(200, { 'content-type': 'application/octet-stream' })
            res.end(Buffer.from(response))
          }
        } catch (error) {
          res.writeHead(500, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32603, message: error instanceof Error ? error.message : 'internal error' } }))
        }
      })()
    })
  }
}

export interface HttpClientHandle {
  send: WireHandler
}

/**
 * Creates an HTTP client `send` function for `wrapMcpClient`. POSTs the request
 * envelope to `url` and returns the response envelope. Uses the global `fetch`
 * by default; inject `fetchImpl` for tests or custom agents.
 */
export function createHttpMcpClient(options: {
  url: string
  fetchImpl?: typeof fetch
  binary?: boolean
  headers?: Record<string, string>
}): HttpClientHandle {
  const doFetch = options.fetchImpl ?? fetch
  const contentType = options.binary ? 'application/octet-stream' : 'application/json'

  return {
    async send(raw: WireEnvelope): Promise<WireEnvelope> {
      const response = await doFetch(options.url, {
        method: 'POST',
        headers: { 'content-type': contentType, ...options.headers },
        body: typeof raw === 'string' ? raw : Buffer.from(raw),
      })
      if (options.binary) return new Uint8Array(await response.arrayBuffer())
      return response.text()
    },
  }
}
