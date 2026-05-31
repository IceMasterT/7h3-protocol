import readline from 'node:readline'
import { createAipMcpGatewayRuntime } from '../src'

function parseAllowedMethodsFromEnv(): string[] {
  const value = process.env.AIP_ALLOWED_METHODS
  if (!value) return ['tools/call', 'resources/read', 'prompts/get']

  return value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
}

async function run(): Promise<void> {
  const sharedSecret = process.env.AIP_SHARED_SECRET ?? 'mcp-gateway-secret'
  const runtime = createAipMcpGatewayRuntime({
    sharedSecret,
    allowedMethods: parseAllowedMethodsFromEnv(),
  })

  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
    terminal: false,
  })

  for await (const line of rl) {
    const responseLine = await runtime.handleLine(line)
    if (responseLine === null) continue
    process.stdout.write(`${responseLine}\n`)
  }
}

run().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
