#!/usr/bin/env node
import { parseArgs } from 'node:util'
import { createServer } from 'node:http'
import { writeFileSync } from 'node:fs'

const USAGE = `
7h3 — Aurelion Interaction Protocol CLI (wire version 7h3/0.1)

Usage:
  7h3 keygen [--output <file>]
  7h3 sign   --private-key <key> --sender <id> [--recipient <id>] [--payload <str>] [--ttl <ms>]
  7h3 verify --public-key <key> --envelope <json>
  7h3 inspect --envelope <json>
  7h3 gateway --upstream <url> [--port <n>] [--public-key <key>] [--require ed25519|none]
              [--sign-responses] [--private-key <key>] [--sender <id>] [--metrics-port <n>]
  7h3 keys serve [--public-key <key>] [--key-id <id>] [--port <n>]
  7h3 help

Commands:
  keygen     Generate an Ed25519 keypair (PKCS8/SPKI, base64url-encoded)
  sign       Create and sign an AIP envelope
  verify     Verify an AIP envelope signature
  inspect    Pretty-print an AIP envelope fields
  gateway    Run a verifying HTTP proxy gateway
  keys serve Serve a /.well-known/7h3-keys endpoint
  help       Show this usage table
`

function die(msg: string): never {
  process.stderr.write(`Error: ${msg}\n`)
  process.exit(1)
}

async function cmdKeygen(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      output: { type: 'string', short: 'o' },
    },
    strict: false,
  })

  const { generateEd25519KeypairBase64Url } = await import('../src/protocol.js')
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
      sender: { type: 'string' },
      recipient: { type: 'string' },
      payload: { type: 'string' },
      ttl: { type: 'string' },
    },
    strict: false,
  })

  const privateKey = values['private-key'] as string | undefined
  const sender = values['sender'] as string | undefined

  if (!privateKey) die('--private-key is required')
  if (!sender) die('--sender is required')

  const { createEnvelope, signEnvelopeEd25519 } = await import('../src/protocol.js')

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

  const { validateEnvelope, verifyEnvelopeEd25519 } = await import('../src/protocol.js')

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
      sender: { type: 'string' },
      'metrics-port': { type: 'string' },
    },
    strict: false,
  })

  const upstream = values['upstream'] as string | undefined
  if (!upstream) die('--upstream is required')

  const port = parseInt((values['port'] as string | undefined) ?? '8080', 10)
  const publicKey = values['public-key'] as string | undefined
  const requireMode = (values['require'] as string | undefined) ?? (publicKey ? 'ed25519' : 'none')
  const signResponses = !!(values['sign-responses'])
  const privateKey = values['private-key'] as string | undefined
  const sender = values['sender'] as string | undefined
  const metricsPortRaw = values['metrics-port'] as string | undefined
  const metricsPort = metricsPortRaw ? parseInt(metricsPortRaw, 10) : undefined

  const { createGateway } = await import('../src/gateway.js')
  const { createStaticKeyRegistry } = await import('../src/keyRegistry.js')

  const keys: Record<string, string> = {}
  if (publicKey && sender) keys[sender] = publicKey
  const keyRegistry = createStaticKeyRegistry(keys)

  const gateway = createGateway({
    upstream: upstream!,
    keyRegistry,
    signResponses: signResponses && !!privateKey,
    privateKey,
    sender,
    defaultPolicy: requireMode === 'none' ? 'allow' : 'deny',
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

  server.listen(port, () => {
    process.stderr.write(`7h3 gateway listening on port ${port}\n`)
    process.stderr.write(`  upstream      : ${upstream}\n`)
    process.stderr.write(`  verify mode   : ${requireMode}\n`)
    process.stderr.write(`  sign-responses: ${signResponses && !!privateKey}\n`)
    if (sender) process.stderr.write(`  sender        : ${sender}\n`)
  })

  // Optional: dedicated metrics server
  if (metricsPort !== undefined) {
    const { metrics: globalMetrics, renderPrometheusText } = await import('../src/telemetry.js')
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

  const { serveWellKnownKeys } = await import('../src/keyInfra.js')

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

  server.listen(port, () => {
    process.stderr.write(`7h3 key server listening on port ${port}\n`)
    process.stderr.write(`  GET /.well-known/7h3-keys\n`)
    if (publicKey) process.stderr.write(`  key-id: ${keyId}\n`)
    else process.stderr.write(`  (no keys configured — empty document)\n`)
  })
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
