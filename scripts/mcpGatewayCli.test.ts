import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { describe, expect, it } from 'vitest'

interface JsonRpcEnvelope {
  jsonrpc: '2.0'
  id: string | number | null
  result?: unknown
  error?: {
    code: number
    message: string
  }
}

function waitForLine(child: ChildProcessWithoutNullStreams, timeoutMs = 8_000): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = ''
    const timer = setTimeout(() => {
      cleanup()
      reject(new Error('Timed out waiting for gateway output'))
    }, timeoutMs)

    const onData = (chunk: Buffer) => {
      buffer += chunk.toString('utf8')
      const newlineIndex = buffer.indexOf('\n')
      if (newlineIndex >= 0) {
        const line = buffer.slice(0, newlineIndex).trim()
        cleanup()
        resolve(line)
      }
    }

    const onError = (error: Error) => {
      cleanup()
      reject(error)
    }

    const onExit = () => {
      cleanup()
      reject(new Error('Gateway process exited before producing output'))
    }

    const cleanup = () => {
      clearTimeout(timer)
      child.stdout.off('data', onData)
      child.off('error', onError)
      child.off('exit', onExit)
    }

    child.stdout.on('data', onData)
    child.on('error', onError)
    child.on('exit', onExit)
  })
}

function startGateway(extraEnv: Record<string, string> = {}): ChildProcessWithoutNullStreams {
  const child = spawn('npm', ['run', '-s', 'aip:mcp:gateway'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      ...extraEnv,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })

  child.stderr.on('data', () => {
    // suppress stderr accumulation in test output
  })

  return child
}

async function stopGateway(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.killed) return
  child.kill('SIGTERM')
  await new Promise<void>((resolve) => {
    child.once('exit', () => resolve())
    setTimeout(() => resolve(), 2_000)
  })
}

describe('AIP MCP gateway CLI', () => {
  it('returns JSON-RPC result for allowed method', async () => {
    const child = startGateway()
    try {
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'tools/call', params: { name: 'planner' } })}\n`,
      )
      const line = await waitForLine(child)
      const response = JSON.parse(line) as JsonRpcEnvelope

      expect(response.jsonrpc).toBe('2.0')
      expect(response.id).toBe(99)
      expect(response.error).toBeUndefined()
      expect(response.result).toBeTruthy()
    } finally {
      await stopGateway(child)
    }
  })

  it('returns method-not-found for disallowed method from env policy', async () => {
    const child = startGateway({ AIP_ALLOWED_METHODS: 'tools/call' })
    try {
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: '2.0', id: 'abc', method: 'resources/read', params: { uri: 'file://x' } })}\n`,
      )
      const line = await waitForLine(child)
      const response = JSON.parse(line) as JsonRpcEnvelope

      expect(response.id).toBe('abc')
      expect(response.result).toBeUndefined()
      expect(response.error?.code).toBe(-32601)
    } finally {
      await stopGateway(child)
    }
  })
})
