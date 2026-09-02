/**
 * Scaffold generation for `7h3_scaffold`.
 *
 * Split out of index.ts so it can be tested: index.ts connects a
 * StdioServerTransport at module load, so importing it from a test would hang.
 */

import { MCP_PACKAGE_SPEC } from './version.js'

// ── scaffold generator ────────────────────────────────────────────────────────

// Safely embed a runtime string as a JS/TS string-literal expression inside
// generated source. JSON.stringify escapes quotes, backslashes, and newlines
// into their two-character escape sequences, so the value can never break out
// of the literal it's embedded in (or, when embedded inside a `//` comment,
// can never introduce an actual newline that would end the comment early).
function jsStr(value: string): string {
  return JSON.stringify(value)
}

export function buildScaffold(
  framework: 'webmcp' | 'cloudflare-worker' | 'nextjs' | 'express' | 'hono' | 'fastify' | 'claude-code' | 'raw',
  signingMethod: 'ed25519' | 'hmac',
  sender: string,
  upstream?: string,
): string {
  const envBlock = signingMethod === 'hmac'
    ? `const SECRET = process.env.P7H3_SECRET ?? 'REPLACE_ME'`
    : `const PUBLIC_KEY = process.env.P7H3_PUBLIC_KEY ?? 'REPLACE_ME'`

  const verifyCall = signingMethod === 'hmac'
    ? `await verifyHttpEnvelope(request, { secretResolver: async () => SECRET })`
    : `await verifyHttpEnvelope(request, { publicKey: PUBLIC_KEY })`

  switch (framework) {
    case 'webmcp': {
      return `// 7h3 Protocol — signed, capability-scoped WebMCP tools
// Install: npm install @7h3/protocol-webmcp @7h3/protocol
// Generated for origin: ${jsStr(sender)}
//
// WebMCP requires a secure context (HTTPS) and tools must be registered in the
// TOP-LEVEL page — tools registered inside an iframe are not discoverable.

import { guard, isWebMcpSupported } from '@7h3/protocol-webmcp'
import { generateEd25519KeypairBase64Url } from '@7h3/protocol'

if (isWebMcpSupported()) {
  // In production, sign with a key your server controls and serve the public
  // half at /.well-known/7h3-keys.json. This per-session key is fine for a
  // page that only needs to sign its own grants and receipts.
  const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()

  const g = guard({
    origin: ${jsStr(sender)},
    privateKey,
    publicKey,
    // Called for any tool declaring confirm: true. Show your own UI here.
    onConfirm: async (tool, input) => window.confirm(\`Allow \${tool.name}?\n\n\${JSON.stringify(input, null, 2)}\`),
  })

  // An unguarded read: no scope, so no grant is required.
  await g.registerTool({
    name: 'search_products',
    description: 'Search the product catalog',
    inputSchema: {
      type: 'object',
      properties: { query: { type: 'string' } },
      required: ['query'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
    execute: async ({ query }) => searchProducts(String(query)),
  })

  // A guarded write. scope gates it behind a capability; limit is a ceiling
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
    if (event.type === 'call') console.log(event.receipt.outcome, event.receipt.tool, event.receipt.reason ?? '')
  })
}

// ── What a refused call returns to the agent ───────────────────────────────
//
// { ok: false, refused: true, reason: 'limit-exceeded',
//   detail: 'amountCents=185000 exceeds the authorized ceiling of 10000',
//   receiptId: 'rcpt-3-a91f...' }
//
// Refusals are structured rather than thrown, so an agent can read why and ask
// the user for authority instead of silently failing.
`
    }

    case 'cloudflare-worker': {
      const upstreamUrl = upstream ?? 'https://your-upstream.example.com'
      return `// 7h3 Protocol Gateway — Cloudflare Worker
// Install: npm install @7h3/protocol
// Generated for sender: ${jsStr(sender)}

import { createGateway } from '@7h3/protocol/gateway'
import { KvKeyRegistry, KvReplayStore } from './kv-replay-store'

export interface Env {
  P7H3_KV: KVNamespace
${signingMethod === 'hmac' ? '  P7H3_SECRET: string' : '  P7H3_PUBLIC_KEY: string'}
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const registry = new KvKeyRegistry(env.P7H3_KV)
    const replayStore = new KvReplayStore(env.P7H3_KV)

    const gateway = createGateway({
      upstream: ${jsStr(upstreamUrl)},
      signingMethod: '${signingMethod}',
${signingMethod === 'hmac'
  ? '      secretResolver: async () => env.P7H3_SECRET,'
  : '      publicKeyResolver: async () => env.P7H3_PUBLIC_KEY,'}
      keyRegistry: registry,
      replayStore,
    })

    return gateway.fetch(request, ctx)
  },
}

// ── wrangler.toml snippet ──────────────────────────────────────────────────
//
// [vars]
// # add secret via: wrangler secret put P7H3_${signingMethod === 'hmac' ? 'SECRET' : 'PUBLIC_KEY'}
//
// [[kv_namespaces]]
// binding = "P7H3_KV"
// id = "YOUR_KV_NAMESPACE_ID"
`
    }

    case 'nextjs': {
      return `// 7h3 Protocol — Next.js Middleware
// File: middleware.ts (project root)
// Install: npm install @7h3/protocol
// Generated for sender: ${jsStr(sender)}

import { NextRequest, NextResponse } from 'next/server'
import { verifyHttpEnvelope } from '@7h3/protocol'

${envBlock}

export async function middleware(request: NextRequest): Promise<NextResponse> {
  // Only enforce 7h3 verification on API routes
  if (request.nextUrl.pathname.startsWith('/api/')) {
    const envelope = request.headers.get('x-7h3-envelope')
    if (!envelope) {
      return NextResponse.json({ error: 'Missing x-7h3-envelope header' }, { status: 401 })
    }

    try {
      const valid = ${verifyCall}
      if (!valid) {
        return NextResponse.json({ error: 'Invalid 7h3 envelope signature' }, { status: 401 })
      }
    } catch (err) {
      return NextResponse.json(
        { error: \`7h3 verification failed: \${err instanceof Error ? err.message : String(err)}\` },
        { status: 401 },
      )
    }
  }

  return NextResponse.next()
}

export const config = {
  matcher: '/api/:path*',
}
`
    }

    case 'express': {
      return `// 7h3 Protocol — Express Middleware
// Install: npm install @7h3/protocol express
// Generated for sender: ${jsStr(sender)}

import express, { Request, Response, NextFunction } from 'express'
import { verifyHttpEnvelope } from '@7h3/protocol'

${envBlock}

async function verify7h3(req: Request, res: Response, next: NextFunction): Promise<void> {
  const envelope = req.headers['x-7h3-envelope']
  if (!envelope || typeof envelope !== 'string') {
    res.status(401).json({ error: 'Missing x-7h3-envelope header' })
    return
  }

  try {
    const valid = ${verifyCall}
    if (!valid) {
      res.status(401).json({ error: 'Invalid 7h3 envelope signature' })
      return
    }
    next()
  } catch (err) {
    res.status(401).json({ error: \`7h3 verification failed: \${err instanceof Error ? err.message : String(err)}\` })
  }
}

// Usage:
const app = express()
app.use(express.json())

// Apply globally
app.use(verify7h3)

// Or per-route
// app.post('/webhook', verify7h3, (req, res) => { ... })

app.listen(3000, () => console.log('Server running on :3000'))
`
    }

    case 'hono': {
      return `// 7h3 Protocol — Hono Middleware
// Install: npm install @7h3/protocol hono
// Generated for sender: ${jsStr(sender)}

import { Hono } from 'hono'
import { createMiddleware } from 'hono/factory'
import { verifyHttpEnvelope } from '@7h3/protocol'

${envBlock}

const verify7h3 = createMiddleware(async (c, next) => {
  const envelope = c.req.header('x-7h3-envelope')
  if (!envelope) {
    return c.json({ error: 'Missing x-7h3-envelope header' }, 401)
  }

  try {
    const valid = ${verifyCall}
    if (!valid) {
      return c.json({ error: 'Invalid 7h3 envelope signature' }, 401)
    }
  } catch (err) {
    return c.json(
      { error: \`7h3 verification failed: \${err instanceof Error ? err.message : String(err)}\` },
      401,
    )
  }

  await next()
})

const app = new Hono()

// Apply globally
app.use('*', verify7h3)

// Or per-route
// app.post('/webhook', verify7h3, (c) => c.json({ ok: true }))

app.get('/', (c) => c.json({ ok: true }))

export default app
`
    }

    case 'fastify': {
      return `// 7h3 Protocol — Fastify Hook
// Install: npm install @7h3/protocol fastify
// Generated for sender: ${jsStr(sender)}

import Fastify, { FastifyRequest, FastifyReply } from 'fastify'
import { verifyHttpEnvelope } from '@7h3/protocol'

${envBlock}

const fastify = Fastify({ logger: true })

// Add preHandler hook globally for 7h3 verification
fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
  const envelope = request.headers['x-7h3-envelope']
  if (!envelope || typeof envelope !== 'string') {
    reply.status(401).send({ error: 'Missing x-7h3-envelope header' })
    return
  }

  try {
    const valid = ${verifyCall}
    if (!valid) {
      reply.status(401).send({ error: 'Invalid 7h3 envelope signature' })
      return
    }
  } catch (err) {
    reply.status(401).send({
      error: \`7h3 verification failed: \${err instanceof Error ? err.message : String(err)}\`,
    })
  }
})

fastify.get('/', async () => ({ ok: true }))

fastify.listen({ port: 3000 }, (err) => {
  if (err) {
    fastify.log.error(err)
    process.exit(1)
  }
})
`
    }

    case 'claude-code': {
      return `// 7h3 Protocol — Claude Code MCP installation
// Paste the following into .claude/settings.json

{
  "mcpServers": {
    "7h3-protocol": {
      "command": "npx",
      "args": ["-y", ${JSON.stringify(MCP_PACKAGE_SPEC)}]
    }
  }
}

// After saving, restart Claude Code. The following tools become available:
//   7h3_generate_secret    — generate HMAC secret
//   7h3_generate_keypair   — generate Ed25519 keypair
//   7h3_wrap_mcp_server    — wrap an MCP server with 7h3 signing
//   7h3_sign               — sign a test envelope
//   7h3_verify             — verify an envelope
//   7h3_scaffold           — generate integration code for a framework
//   7h3_mcp_config         — show install config for all editors
//
// Sender identity configured for this scaffold: ${jsStr(sender)}
// Signing method: ${signingMethod}
`
    }

    case 'raw': {
      return `// 7h3 Protocol — Minimal Node.js HTTP Server
// Install: npm install @7h3/protocol
// Generated for sender: ${jsStr(sender)}

import http from 'node:http'
import { verifyHttpEnvelope } from '@7h3/protocol'

${envBlock}

const server = http.createServer(async (req, res) => {
  // Verify 7h3 envelope on every incoming request
  const envelope = req.headers['x-7h3-envelope']
  if (!envelope || typeof envelope !== 'string') {
    res.writeHead(401, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'Missing x-7h3-envelope header' }))
    return
  }

  try {
    const valid = ${verifyCall}
    if (!valid) {
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Invalid 7h3 envelope signature' }))
      return
    }
  } catch (err) {
    res.writeHead(401, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      error: \`7h3 verification failed: \${err instanceof Error ? err.message : String(err)}\`,
    }))
    return
  }

  // Request is verified — handle it
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ ok: true, sender: ${jsStr(sender)} }))
})

server.listen(3000, () => {
  console.log('7h3-verified server listening on http://localhost:3000')
})
`
    }
  }
}
