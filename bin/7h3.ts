#!/usr/bin/env node
import { parseArgs } from 'node:util'
import { createServer } from 'node:http'
import { writeFileSync, readFileSync } from 'node:fs'

const USAGE = `
7h3 — Protocol CLI (wire version 7h3/0.1)

Usage:
  7h3 keygen [--output <file>]
  7h3 sign   --private-key <key> --sender <id> [--recipient <id>] [--payload <str>] [--ttl <ms>]
             (or --private-key-file <path>, or env P7H3_PRIVATE_KEY)
  7h3 verify --public-key <key> --envelope <json>
  7h3 inspect --envelope <json>
  7h3 gateway --upstream <url> [--port <n>] [--public-key <key>] [--require ed25519|none]
              [--sign-responses] [--private-key <key>] [--sender <id>] [--metrics-port <n>]
              [--allow-unverified]
              (private key: --private-key-file <path>, or env GATEWAY_PRIVATE_KEY)
  7h3 keys serve [--public-key <key>] [--key-id <id>] [--port <n>]
  7h3 add --framework <name> [--sender <id>] [--output <dir>]
  7h3 help

Secrets:
  --private-key on 'sign'/'gateway' is visible in shell history and process
  listings. Prefer --private-key-file <path> or the P7H3_PRIVATE_KEY /
  GATEWAY_PRIVATE_KEY environment variables.

Commands:
  keygen     Generate an Ed25519 keypair (PKCS8/SPKI, base64url-encoded)
  sign       Create and sign a 7h3 envelope
  verify     Verify a 7h3 envelope signature
  inspect    Pretty-print a 7h3 envelope fields
  gateway    Run a verifying HTTP proxy gateway
  keys serve Serve a /.well-known/7h3-keys endpoint
  add        Scaffold 7h3 integration into a project (see --framework options)
  help       Show this usage table
`

function die(msg: string): never {
  process.stderr.write(`Error: ${msg}\n`)
  process.exit(1)
}

// A private key passed as a bare CLI argument lands in shell history and is
// visible to any other local user via `ps`/`/proc` for the life of the
// process — resolveSecretArg() prefers a file (never touches argv or the
// environment table other tools can dump) or an env var, and only falls
// back to the raw flag with an explicit warning so the risk is visible
// rather than silent.
function resolveSecretArg(
  flagName: string,
  flagValue: string | undefined,
  fileValue: string | undefined,
  envVarName: string,
): string | undefined {
  if (fileValue) {
    try {
      return readFileSync(fileValue, 'utf8').trim()
    } catch (err) {
      die(`failed to read --${flagName}-file ${fileValue}: ${String(err)}`)
    }
  }
  if (flagValue) {
    process.stderr.write(
      `[7h3] Warning: --${flagName} is visible in shell history and process listings. ` +
        `Prefer --${flagName}-file <path> or the ${envVarName} environment variable.\n`,
    )
    return flagValue
  }
  return process.env[envVarName] || undefined
}

async function cmdKeygen(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      output: { type: 'string', short: 'o' },
    },
    strict: false,
  })

  const { generateEd25519KeypairBase64Url } = await import('@7h3/protocol')
  const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()

  const result = {
    algorithm: 'Ed25519',
    wireVersion: '7h3/0.1',
    publicKey,
    privateKey,
    createdAt: new Date().toISOString(),
    warning: 'Keep privateKey secret — it grants signing authority over your agent identity.',
  }

  const json = JSON.stringify(result, null, 2)

  if (values.output) {
    writeFileSync(values.output as string, json, 'utf8')
    process.stdout.write(`Keypair written to ${values.output}\n`)
    process.stdout.write(`  algorithm : Ed25519\n`)
    process.stdout.write(`  publicKey : ${publicKey}\n`)
    process.stdout.write(`  createdAt : ${result.createdAt}\n`)
  } else {
    process.stdout.write(json + '\n')
  }
}

async function cmdSign(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      'private-key': { type: 'string' },
      'private-key-file': { type: 'string' },
      sender: { type: 'string' },
      recipient: { type: 'string' },
      payload: { type: 'string' },
      ttl: { type: 'string' },
    },
    strict: false,
  })

  const privateKey = resolveSecretArg(
    'private-key',
    values['private-key'] as string | undefined,
    values['private-key-file'] as string | undefined,
    'P7H3_PRIVATE_KEY',
  )
  const sender = values['sender'] as string | undefined

  if (!privateKey) die('--private-key (or --private-key-file / P7H3_PRIVATE_KEY) is required')
  if (!sender) die('--sender is required')

  const { createEnvelope, signEnvelopeEd25519 } = await import('@7h3/protocol')

  const envelope = createEnvelope({
    sender: sender!,
    recipient: values['recipient'] as string | undefined,
    intent: 'PING',
    content: (values['payload'] as string | undefined) ?? '',
    ttlMs: values['ttl'] ? parseInt(values['ttl'] as string, 10) : 60_000,
  })

  const signed = await signEnvelopeEd25519(envelope, privateKey!)
  process.stdout.write(JSON.stringify(signed) + '\n')
}

async function cmdVerify(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      'public-key': { type: 'string' },
      envelope: { type: 'string' },
    },
    strict: false,
  })

  const publicKey = values['public-key'] as string | undefined
  const envelopeJson = values['envelope'] as string | undefined

  if (!publicKey) die('--public-key is required')
  if (!envelopeJson) die('--envelope is required')

  const { validateEnvelope, verifyEnvelopeEd25519 } = await import('@7h3/protocol')

  let envelope: ReturnType<typeof JSON.parse>
  try {
    envelope = JSON.parse(envelopeJson!)
  } catch {
    die('--envelope is not valid JSON')
  }

  const diagnostics = validateEnvelope(envelope)
  const errors = diagnostics.filter(d => d.level === 'error')
  const warnings = diagnostics.filter(d => d.level === 'warning')

  if (errors.length > 0) {
    process.stdout.write('INVALID — envelope validation errors:\n')
    for (const e of errors) process.stdout.write(`  [error] ${e.message}\n`)
    for (const w of warnings) process.stdout.write(`  [warning] ${w.message}\n`)
    process.exit(1)
  }

  const valid = await verifyEnvelopeEd25519(envelope, publicKey!)

  if (valid) {
    process.stdout.write('Signature valid\n')
    if (warnings.length > 0) {
      for (const w of warnings) process.stdout.write(`  [warning] ${w.message}\n`)
    }
  } else {
    process.stdout.write('INVALID — signature verification failed\n')
    process.stdout.write(`  alg   : ${envelope.signature?.alg ?? 'none'}\n`)
    process.stdout.write(`  keyId : ${envelope.signature?.keyId ?? 'none'}\n`)
    process.exit(1)
  }
}

async function cmdInspect(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      envelope: { type: 'string' },
    },
    strict: false,
  })

  const envelopeJson = values['envelope'] as string | undefined
  if (!envelopeJson) die('--envelope is required')

  let envelope: ReturnType<typeof JSON.parse>
  try {
    envelope = JSON.parse(envelopeJson!)
  } catch {
    die('--envelope is not valid JSON')
  }

  const h = envelope.header ?? {}
  const b = envelope.body ?? {}
  const s = envelope.signature

  const nowMs = Date.now()
  const expiresMs = (h.timestampMs ?? 0) + (h.ttlMs ?? 0)
  const expired = expiresMs < nowMs
  const expiresStatus = expired
    ? `EXPIRED (${new Date(expiresMs).toISOString()})`
    : `OK — expires ${new Date(expiresMs).toISOString()}`

  const content: string = typeof b.content === 'string' ? b.content : ''
  const contentPreview = content.length > 80 ? content.slice(0, 77) + '...' : content

  process.stdout.write(`Wire Version : ${h.version ?? '(none)'}\n`)
  process.stdout.write(`Message ID   : ${h.messageId ?? '(none)'}\n`)
  process.stdout.write(`Sender       : ${h.sender ?? '(none)'}\n`)
  process.stdout.write(`Recipient    : ${h.recipient ?? '(none)'}\n`)
  process.stdout.write(`Timestamp    : ${h.timestampMs ? new Date(h.timestampMs).toISOString() : '(none)'}\n`)
  process.stdout.write(`TTL          : ${h.ttlMs ?? '(none)'} ms\n`)
  process.stdout.write(`Expires      : ${expiresStatus}\n`)
  process.stdout.write(`Intent       : ${b.intent ?? '(none)'}\n`)
  process.stdout.write(`Content      : ${contentPreview || '(empty)'}\n`)
  if (s) {
    process.stdout.write(`Sig alg      : ${s.alg}\n`)
    process.stdout.write(`Sig keyId    : ${s.keyId}\n`)
  } else {
    process.stdout.write(`Signature    : (none)\n`)
  }
}

async function cmdGateway(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      upstream: { type: 'string' },
      port: { type: 'string' },
      'public-key': { type: 'string' },
      require: { type: 'string' },
      'sign-responses': { type: 'boolean' },
      'private-key': { type: 'string' },
      'private-key-file': { type: 'string' },
      sender: { type: 'string' },
      'metrics-port': { type: 'string' },
      'allow-unverified': { type: 'boolean' },
    },
    strict: false,
  })

  const upstream = values['upstream'] as string | undefined
  if (!upstream) die('--upstream is required')

  const port = parseInt((values['port'] as string | undefined) ?? '8080', 10)
  const publicKey = values['public-key'] as string | undefined
  const requireMode = (values['require'] as string | undefined) ?? (publicKey ? 'ed25519' : 'none')
  const signResponses = !!(values['sign-responses'])
  const privateKey = resolveSecretArg(
    'private-key',
    values['private-key'] as string | undefined,
    values['private-key-file'] as string | undefined,
    'GATEWAY_PRIVATE_KEY',
  )
  const sender = values['sender'] as string | undefined
  const metricsPortRaw = values['metrics-port'] as string | undefined
  const metricsPort = metricsPortRaw ? parseInt(metricsPortRaw, 10) : undefined

  // `7h3 gateway --upstream <url>` with no other flags used to silently start
  // a fully unverified passthrough proxy — the exact opposite of what the
  // command's own usage text ("a verifying HTTP proxy gateway") promises.
  // Require an explicit, positive choice: either real verification material
  // or an explicit acknowledgment that this instance is intentionally open.
  if (requireMode === 'none' && !values['allow-unverified']) {
    die(
      'refusing to start an unverified passthrough gateway. Pass --public-key/--require to ' +
        'verify requests, or --allow-unverified to explicitly run without verification.',
    )
  }

  const { createGateway } = await import('@7h3/protocol/gateway')
  const { createStaticKeyRegistry } = await import('@7h3/protocol/key-registry')

  const keys: Record<string, string> = {}
  if (publicKey && sender) keys[sender] = publicKey
  const keyRegistry = createStaticKeyRegistry(keys)

  // No --replay-store flag exists (there's no CLI-friendly way to configure
  // a shared backing store), but shipping with no replay protection at all
  // when signatures ARE required silently drops one of the two guarantees
  // this whole command exists to provide. A minimal in-memory ReplayStore is
  // still only good for this single process — it won't survive a restart or
  // a second instance — which is why this only applies to the local
  // single-process CLI gateway, never the library default.
  class InMemoryCliReplayStore {
    private readonly seen = new Map<string, number>()
    async check(key: string, ttlMs: number): Promise<boolean> {
      const nowMs = Date.now()
      for (const [k, expiresAt] of this.seen) {
        if (expiresAt <= nowMs) this.seen.delete(k)
      }
      const existing = this.seen.get(key)
      if (existing !== undefined && existing > nowMs) return true // replay
      this.seen.set(key, nowMs + ttlMs)
      return false
    }
  }

  let replayStore: import('@7h3/protocol/gateway').GatewayConfig['replayStore']
  if (requireMode !== 'none') {
    replayStore = new InMemoryCliReplayStore()
    process.stderr.write(
      '[7h3] Replay protection is in-memory for this process only — it will not survive a ' +
        'restart or a second instance. For production, use the library directly with a shared replayStore.\n',
    )
  }

  const gateway = createGateway({
    upstream: upstream!,
    keyRegistry,
    signResponses: signResponses && !!privateKey,
    privateKey,
    sender,
    defaultPolicy: requireMode === 'none' ? 'allow' : 'deny',
    replayStore,
  })

  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', async () => {
      const body = Buffer.concat(chunks)

      // Flatten headers: string | string[] => string
      const headers: Record<string, string> = {}
      for (const [k, v] of Object.entries(req.headers)) {
        if (v === undefined) continue
        headers[k] = Array.isArray(v) ? v.join(', ') : v
      }

      try {
        const result = await gateway.handle({
          method: req.method ?? 'GET',
          path: req.url ?? '/',
          headers,
          body: body.length > 0 ? body.toString('utf8') : undefined,
        })
        res.writeHead(result.status, result.headers)
        res.end(result.body)
      } catch (err) {
        res.writeHead(502, { 'content-type': 'text/plain' })
        res.end(`Gateway error: ${String(err)}`)
      }
    })
  })

  // Without this, a plain EADDRINUSE (an easy real-world mistake — the port
  // is already in use) throws as an uncaught exception: a raw Node stack
  // trace instead of this CLI's own clean `Error: ...` convention.
  server.on('error', (err) => die(`gateway server: ${String(err)}`))

  server.listen(port, () => {
    process.stderr.write(`7h3 gateway listening on port ${port}\n`)
    process.stderr.write(`  upstream      : ${upstream}\n`)
    process.stderr.write(`  verify mode   : ${requireMode}\n`)
    process.stderr.write(`  sign-responses: ${signResponses && !!privateKey}\n`)
    if (sender) process.stderr.write(`  sender        : ${sender}\n`)
  })

  // Optional: dedicated metrics server
  if (metricsPort !== undefined) {
    const { metrics: globalMetrics, renderPrometheusText } = await import('@7h3/protocol/telemetry')
    const metricsServer = createServer((req, res) => {
      if (req.url === '/metrics' && req.method === 'GET') {
        const body = renderPrometheusText(globalMetrics)
        res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' })
        res.end(body)
      } else {
        res.writeHead(404, { 'content-type': 'text/plain' })
        res.end('Not Found')
      }
    })
    metricsServer.on('error', (err) => die(`metrics server: ${String(err)}`))
    metricsServer.listen(metricsPort, () => {
      process.stderr.write(`7h3 metrics listening on :${metricsPort}/metrics\n`)
    })
  }
}

async function cmdKeysServe(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      'public-key': { type: 'string' },
      'key-id': { type: 'string' },
      port: { type: 'string' },
    },
    strict: false,
  })

  const publicKey = values['public-key'] as string | undefined
  const keyId = (values['key-id'] as string | undefined) ?? 'default'
  const port = parseInt((values['port'] as string | undefined) ?? '8081', 10)

  const { serveWellKnownKeys } = await import('@7h3/protocol/keys')

  const doc = {
    version: '7h3/0.1' as const,
    updated: Date.now(),
    keys: publicKey
      ? [
          {
            id: keyId,
            algorithm: 'Ed25519' as const,
            publicKey,
            created: Date.now(),
          },
        ]
      : [],
  }

  const body = serveWellKnownKeys(doc)

  const server = createServer((req, res) => {
    if (req.url === '/.well-known/7h3-keys') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(body)
    } else {
      res.writeHead(404, { 'content-type': 'text/plain' })
      res.end('Not Found')
    }
  })

  server.on('error', (err) => die(`key server: ${String(err)}`))
  server.listen(port, () => {
    process.stderr.write(`7h3 key server listening on port ${port}\n`)
    process.stderr.write(`  GET /.well-known/7h3-keys\n`)
    if (publicKey) process.stderr.write(`  key-id: ${keyId}\n`)
    else process.stderr.write(`  (no keys configured — empty document)\n`)
  })
}

// ─── 7h3 add ───────────────────────────────────────────────────────────────────

const ADD_FRAMEWORKS = ['webmcp', 'cloudflare-worker', 'nextjs', 'express', 'hono', 'fastify', 'claude-code', 'opencode', 'codex', 'grok'] as const
type Framework = typeof ADD_FRAMEWORKS[number]

const FRAMEWORK_SNIPPETS: Record<Framework, (sender: string) => string> = {
  webmcp: (sender) => `// 7h3 — signed, capability-scoped WebMCP tools
// Install: npm install @7h3/protocol-webmcp @7h3/protocol
//
// WebMCP requires a secure context (HTTPS) and tools must be registered in the
// TOP-LEVEL page — tools inside an iframe are not discoverable by agents.

import { guard, isWebMcpSupported } from '@7h3/protocol-webmcp'
import { generateEd25519KeypairBase64Url } from '@7h3/protocol'

if (isWebMcpSupported()) {
  // Per-session key: fine for signing this visitor's grants and receipts. The
  // manifest is signed separately, at deploy time, by a key the browser never sees.
  const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()

  const g = guard({
    origin: ${JSON.stringify(sender)},
    privateKey,
    publicKey,
    onConfirm: async (tool, input) =>
      window.confirm(\`Allow \${tool.name}?\\n\\n\${JSON.stringify(input, null, 2)}\`),
  })

  // An unguarded read: no scope, so no grant is required.
  await g.registerTool({
    name: 'search_items',
    description: 'Search the catalog',
    inputSchema: {
      type: 'object',
      properties: { query: { type: 'string' } },
      required: ['query'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
    execute: async ({ query }) => searchItems(String(query)),
  })

  // A guarded write. \`scope\` gates it behind a capability; \`limit\` is a ceiling
  // this site will never exceed, whatever a grant says.
  await g.registerTool({
    name: 'place_order',
    description: 'Place an order for the current cart',
    inputSchema: {
      type: 'object',
      properties: { cartId: { type: 'string' }, amountCents: { type: 'number' } },
      required: ['cartId', 'amountCents'],
      additionalProperties: false,
    },
    annotations: { destructiveHint: true },
    scope: 'orders/place',
    limit: { field: 'amountCents', max: 500_00 },
    confirm: true,
    execute: async ({ cartId }) => placeOrder(String(cartId)),
  })

  // Wire this to a consent control in your own UI — never grant automatically.
  // The token is held page-side, so it never passes through the agent.
  document.querySelector('#allow-agent')?.addEventListener('click', async () => {
    await g.grant({
      subject: 'browser-agent',
      scopes: ['orders/place'],
      caps: { amountCents: 100_00 },  // bound inside the signed token
      ttlMs: 10 * 60_000,             // authority lapses on its own
    })
  })

  // Every call — allowed and refused — lands on a hash-chained signed log.
  g.on((event) => {
    if (event.type === 'call') {
      console.log(event.receipt.outcome, event.receipt.tool, event.receipt.reason ?? '')
    }
  })
}
`,
  'cloudflare-worker': (sender) => `// cloudflare/src/worker.ts — 7h3 Gateway Worker
// Install: npm install @7h3/protocol
// See: cloudflare/DEPLOY.md for full setup

import { createGateway } from '@7h3/protocol/gateway'
import { KvKeyRegistry } from './kv-key-registry'
import { KvReplayStore } from './kv-replay-store'

interface Env {
  KEY_REGISTRY: KVNamespace
  REPLAY_STORE: KVNamespace
  UPSTREAM_URL: string
  GATEWAY_PRIVATE_KEY?: string
  GATEWAY_SENDER?: string
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const gateway = createGateway({
      upstream: env.UPSTREAM_URL,
      keyRegistry: new KvKeyRegistry(env.KEY_REGISTRY),
      replayStore: new KvReplayStore(env.REPLAY_STORE),
      defaultPolicy: 'deny',
      privateKey: env.GATEWAY_PRIVATE_KEY,
      sender: env.GATEWAY_SENDER ?? '${sender}',
    })
    const url = new URL(request.url)
    const headers: Record<string, string> = {}
    request.headers.forEach((v, k) => { headers[k] = v })
    const result = await gateway.verify({ method: request.method, path: url.pathname, headers })
    if (!result.ok) return new Response(result.reason, { status: result.status })
    return fetch(env.UPSTREAM_URL + url.pathname + url.search, { method: request.method, headers })
  }
}
`,

  'nextjs': (sender) => `// middleware.ts — add to your Next.js project root
// Install: npm install @7h3/protocol
import { NextRequest, NextResponse } from 'next/server'
import { verifyHttpEnvelope } from '@7h3/protocol/http'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'

// Load trusted peer public keys from env vars
const PEER_KEYS = Object.fromEntries(
  (process.env.P7H3_TRUSTED_KEYS ?? '').split(',').filter(Boolean)
    .map(pair => pair.split('=') as [string, string])
)

const registry = createStaticKeyRegistry(PEER_KEYS)

export async function middleware(req: NextRequest) {
  const headers = Object.fromEntries(req.headers)
  const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
  if (!result.ok) {
    return NextResponse.json({ error: result.reason }, { status: 401 })
  }
  const response = NextResponse.next()
  response.headers.set('x-7h3-sender', (result as any).envelope?.header?.sender ?? '')
  return response
}

export const config = { matcher: '/api/:path*' }

// Usage: set env var P7H3_TRUSTED_KEYS="agent@example.com=<base64url-pubkey>,..."
// Generate keypair: npx 7h3 keygen
// Self-identity: ${sender}
`,

  'express': (sender) => `// middleware/7h3-auth.ts — add to your Express project
// Install: npm install @7h3/protocol
import type { Request, Response, NextFunction } from 'express'
import { verifyHttpEnvelope } from '@7h3/protocol/http'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'

const registry = createStaticKeyRegistry({
  'peer-agent@example.com': process.env.PEER_PUBLIC_KEY ?? '',
})

export async function verify7h3(req: Request, res: Response, next: NextFunction) {
  const result = await verifyHttpEnvelope(
    req.headers as Record<string, string>,
    { keyRegistry: registry },
  )
  if (!result.ok) return res.status(401).json({ error: result.reason })
  ;(req as any).sender7h3 = (result as any).envelope?.header?.sender
  next()
}

// Mount in app.ts:
//   import { verify7h3 } from './middleware/7h3-auth'
//   app.use('/api', verify7h3)
//
// Self-identity: ${sender}
`,

  'hono': (sender) => `// middleware/7h3-auth.ts — add to your Hono project
// Install: npm install @7h3/protocol hono
import { createMiddleware } from 'hono/factory'
import { verifyHttpEnvelope } from '@7h3/protocol/http'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'

const registry = createStaticKeyRegistry({
  'peer-agent@example.com': process.env.PEER_PUBLIC_KEY ?? '',
})

export const auth7h3 = createMiddleware(async (c, next) => {
  const headers = Object.fromEntries(c.req.raw.headers)
  const result = await verifyHttpEnvelope(headers, { keyRegistry: registry })
  if (!result.ok) return c.json({ error: result.reason }, 401)
  c.set('sender7h3', (result as any).envelope?.header?.sender ?? '')
  await next()
})

// Mount in your Hono app:
//   import { auth7h3 } from './middleware/7h3-auth'
//   app.use('/api/*', auth7h3)
//
// Self-identity: ${sender}
`,

  'fastify': (sender) => `// plugins/7h3-auth.ts — add to your Fastify project
// Install: npm install @7h3/protocol fastify
import fp from 'fastify-plugin'
import { verifyHttpEnvelope } from '@7h3/protocol/http'
import { createStaticKeyRegistry } from '@7h3/protocol/key-registry'

const registry = createStaticKeyRegistry({
  'peer-agent@example.com': process.env.PEER_PUBLIC_KEY ?? '',
})

export default fp(async (fastify) => {
  fastify.addHook('preHandler', async (request, reply) => {
    const result = await verifyHttpEnvelope(
      request.headers as Record<string, string>,
      { keyRegistry: registry },
    )
    if (!result.ok) {
      return reply.code(401).send({ error: result.reason })
    }
    request.sender7h3 = (result as any).envelope?.header?.sender ?? ''
  })
})

// In your main file: fastify.register(import('./plugins/7h3-auth'))
// Self-identity: ${sender}
`,

  'claude-code': (_sender) => `# Install 7h3 Protocol MCP server in Claude Code

## Option 1 — one command (recommended)

\`\`\`bash
claude mcp add 7h3-protocol -- npx -y @7h3/protocol-mcp
\`\`\`

## Option 2 — project .claude/settings.json

Copy .claude/settings.example.json to .claude/settings.json:

\`\`\`json
{
  "mcpServers": {
    "7h3-protocol": {
      "command": "npx",
      "args": ["-y", "@7h3/protocol-mcp"]
    }
  }
}
\`\`\`

## Available tools after install

- 7h3_generate_keypair   — Ed25519 keypair
- 7h3_generate_secret    — HMAC secret
- 7h3_sign               — sign a test envelope
- 7h3_verify             — verify an envelope
- 7h3_scaffold           — generate framework integration code
- 7h3_mcp_config         — get config for other editors
- 7h3_wrap_mcp_server    — wrap an MCP handler with 7h3 signing
`,

  'opencode': (_sender) => `# Install 7h3 Protocol MCP server in Opencode

Add to your opencode config (~/.config/opencode/config.json or opencode.json):

\`\`\`json
{
  "mcp": {
    "7h3-protocol": {
      "command": "npx",
      "args": ["-y", "@7h3/protocol-mcp"],
      "type": "stdio"
    }
  }
}
\`\`\`

Or one command:
\`\`\`bash
opencode mcp add 7h3-protocol npx -y @7h3/protocol-mcp
\`\`\`

After install, ask: "scaffold 7h3 for my hono project" and the AI will call 7h3_scaffold automatically.
`,

  'codex': (_sender) => `# 7h3 Protocol — GPT Codex integration

Codex reads AGENTS.md automatically. This repo has AGENTS.md with:
- Installation instructions for all SDKs
- Framework integration snippets (CF Worker, Next.js, Express, Hono, Fastify)
- All advanced feature examples
- CLI reference

No extra setup needed — just ensure AGENTS.md is in your repo root.

## Add to your project's AGENTS.md

\`\`\`markdown
## Security — 7h3 Protocol

All inter-agent HTTP calls must include a signed 7h3 envelope.

Install: npm install @7h3/protocol
Docs: see https://github.com/IceMasterT/7h3-protocol-aip

Verify incoming requests with verifyHttpEnvelope() from @7h3/protocol/http.
Sign outgoing requests with signEnvelopeEd25519() from @7h3/protocol.
\`\`\`
`,

  'grok': (_sender) => `# 7h3 Protocol — Grok Builder integration

Grok Builder reads AGENTS.md. This repo's AGENTS.md includes all integration patterns.

## Add to your project's AGENTS.md

\`\`\`markdown
## Security — 7h3 Protocol signing

All AI agent messages must use 7h3 Protocol (npm: @7h3/protocol).

Key rules:
- Outgoing: createEnvelope() + signEnvelopeEd25519() → x-7h3-envelope header
- Incoming: verifyHttpEnvelope() from @7h3/protocol/http
- Wire version is ALWAYS "7h3/0.1" — never change
- Generate keys: npx 7h3 keygen
\`\`\`

## MCP config for Grok (if MCP supported)

\`\`\`json
{
  "mcp": {
    "7h3-protocol": {
      "command": "npx",
      "args": ["-y", "@7h3/protocol-mcp"]
    }
  }
}
\`\`\`
`,
}

async function cmdAdd(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      framework: { type: 'string', short: 'f' },
      sender: { type: 'string', short: 's' },
      output: { type: 'string', short: 'o' },
    },
    strict: false,
  })

  const framework = (values.framework as string | undefined) ?? ''
  const sender = (values.sender as string | undefined) ?? 'agent@example.com'

  if (!framework || !ADD_FRAMEWORKS.includes(framework as Framework)) {
    process.stdout.write(`Available frameworks:\n`)
    ADD_FRAMEWORKS.forEach(f => process.stdout.write(`  ${f}\n`))
    process.stdout.write(`\nUsage: 7h3 add --framework <name> [--sender <id>]\n`)
    return
  }

  const snippet = FRAMEWORK_SNIPPETS[framework as Framework](sender)
  const out = values.output as string | undefined

  if (out) {
    const { writeFileSync } = await import('node:fs')
    writeFileSync(out, snippet, 'utf8')
    process.stdout.write(`Written to ${out}\n`)
  } else {
    process.stdout.write(snippet)
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2)
  const command = args[0] ?? 'help'
  const rest = args.slice(1)

  switch (command) {
    case 'keygen':
      await cmdKeygen(rest)
      break

    case 'sign':
      await cmdSign(rest)
      break

    case 'verify':
      await cmdVerify(rest)
      break

    case 'inspect':
      await cmdInspect(rest)
      break

    case 'gateway':
      await cmdGateway(rest)
      break

    case 'keys': {
      const sub = rest[0]
      if (sub === 'serve') {
        await cmdKeysServe(rest.slice(1))
      } else {
        die(`Unknown subcommand 'keys ${sub ?? ''}'. Did you mean 'keys serve'?`)
      }
      break
    }

    case 'add':
      await cmdAdd(rest)
      break

    case 'help':
    case '--help':
    case '-h':
      process.stdout.write(USAGE)
      break

    default:
      process.stderr.write(`Unknown command: ${command}\n`)
      process.stdout.write(USAGE)
      process.exit(1)
  }
}

main().catch(err => {
  process.stderr.write(`Fatal: ${String(err)}\n`)
  process.exit(1)
})
