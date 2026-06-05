#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import {
  generateEd25519KeypairBase64Url,
  createEnvelope,
  signEnvelopeHmac,
  signEnvelopeEd25519,
  verifyEnvelopeHmac,
  verifyEnvelopeEd25519,
  validateEnvelope,
} from '@7h3/protocol'
import { randomBytes } from 'node:crypto'

const server = new McpServer({ name: '@7h3/protocol-mcp', version: '0.1.0' })

// ── aip_generate_secret ───────────────────────────────────────────────────────

server.registerTool(
  'aip_generate_secret',
  {
    description: 'Generate a cryptographically random 32-byte HMAC secret for AIP message signing. Returns the value to store as AIP_SECRET.',
  },
  async () => {
    const secret = randomBytes(32).toString('base64url')
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          secret,
          envVar: 'AIP_SECRET',
          warning: 'Never commit this value. Add to .env and .gitignore.',
        }, null, 2),
      }],
    }
  },
)

// ── aip_generate_keypair ──────────────────────────────────────────────────────

server.registerTool(
  'aip_generate_keypair',
  {
    description: 'Generate an Ed25519 keypair for AIP message signing. Returns publicKey (safe to share) and privateKey (keep secret).',
  },
  async () => {
    const keypair = await generateEd25519KeypairBase64Url()
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          publicKey: keypair.publicKey,
          privateKey: keypair.privateKey,
          envVars: { privateKey: 'AIP_PRIVATE_KEY', publicKey: 'AIP_PUBLIC_KEY' },
          warning: 'Never commit privateKey. Share publicKey with peers who need to verify your messages.',
        }, null, 2),
      }],
    }
  },
)

// ── aip_wrap_mcp_server ───────────────────────────────────────────────────────

server.registerTool(
  'aip_wrap_mcp_server',
  {
    description: 'Generate ready-to-paste TypeScript boilerplate to wrap an existing MCP server handler with AIP signing and replay protection. Zero changes to your handler required.',
    inputSchema: {
      serverAgentId: z.string().describe('Unique ID for this server agent, e.g. "my-tool-server"'),
      clientAgentId: z.string().optional().describe('Expected client agent ID for sender binding. Omit to accept any signed client.'),
      transport: z.enum(['stdio', 'http']).optional().describe('Transport type. Default: stdio'),
      signingMethod: z.enum(['hmac', 'ed25519']).optional().describe('Signing algorithm. hmac = shared secret, ed25519 = keypair. Default: hmac'),
    },
  },
  async ({ serverAgentId, clientAgentId, transport = 'stdio', signingMethod = 'hmac' }) => {
    return {
      content: [{ type: 'text', text: buildBoilerplate(serverAgentId, clientAgentId, transport, signingMethod) }],
    }
  },
)

// ── aip_sign ──────────────────────────────────────────────────────────────────

server.registerTool(
  'aip_sign',
  {
    description: 'Sign a test AIP envelope. Useful for debugging or generating test fixtures.',
    inputSchema: {
      senderAgentId: z.string(),
      content: z.string().describe('Message content — plain text or JSON string'),
      signingMethod: z.enum(['hmac', 'ed25519']),
      secret: z.string().optional().describe('HMAC secret — required when signingMethod=hmac'),
      privateKey: z.string().optional().describe('Ed25519 private key base64url — required when signingMethod=ed25519'),
      recipientAgentId: z.string().optional(),
      keyId: z.string().optional().describe('Key identifier label. Default: k1'),
    },
  },
  async ({ senderAgentId, content, signingMethod, secret, privateKey, recipientAgentId, keyId = 'k1' }) => {
    try {
      const envelope = createEnvelope({ sender: senderAgentId, recipient: recipientAgentId, intent: 'TASK', content })
      let signed
      if (signingMethod === 'hmac') {
        if (!secret) throw new Error('secret is required for hmac signing')
        signed = await signEnvelopeHmac(envelope, secret, keyId)
      } else {
        if (!privateKey) throw new Error('privateKey is required for ed25519 signing')
        signed = await signEnvelopeEd25519(envelope, privateKey, keyId)
      }
      return { content: [{ type: 'text', text: JSON.stringify(signed, null, 2) }] }
    } catch (err) {
      return { content: [{ type: 'text', text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true }
    }
  },
)

// ── aip_verify ────────────────────────────────────────────────────────────────

server.registerTool(
  'aip_verify',
  {
    description: 'Verify an AIP envelope signature and validate its shape, TTL, and version.',
    inputSchema: {
      envelopeJson: z.string().describe('JSON string of the AIP envelope to verify'),
      signingMethod: z.enum(['hmac', 'ed25519']),
      secret: z.string().optional().describe('HMAC secret — required when signingMethod=hmac'),
      publicKey: z.string().optional().describe('Ed25519 public key base64url — required when signingMethod=ed25519'),
    },
  },
  async ({ envelopeJson, signingMethod, secret, publicKey }) => {
    try {
      let envelope: unknown
      try {
        envelope = JSON.parse(envelopeJson)
      } catch {
        throw new Error('envelopeJson is not valid JSON')
      }

      const validationErrors = validateEnvelope(envelope as Parameters<typeof validateEnvelope>[0])
      let sigValid = false

      if (signingMethod === 'hmac') {
        if (!secret) throw new Error('secret is required for hmac verification')
        sigValid = await verifyEnvelopeHmac(envelope as Parameters<typeof verifyEnvelopeHmac>[0], secret)
      } else {
        if (!publicKey) throw new Error('publicKey is required for ed25519 verification')
        sigValid = await verifyEnvelopeEd25519(envelope as Parameters<typeof verifyEnvelopeEd25519>[0], publicKey)
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            signatureValid: sigValid,
            validationErrors,
            result: sigValid && validationErrors.length === 0 ? 'PASS' : 'FAIL',
          }, null, 2),
        }],
      }
    } catch (err) {
      return { content: [{ type: 'text', text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true }
    }
  },
)

// ── boilerplate generator ─────────────────────────────────────────────────────

function buildBoilerplate(
  serverAgentId: string,
  clientAgentId: string | undefined,
  transport: 'stdio' | 'http',
  signingMethod: 'hmac' | 'ed25519',
): string {
  const imports = signingMethod === 'hmac'
    ? `import { wrapMcpServer, serveMcpOverStdio, signEnvelopeHmac } from '@7h3/protocol'`
    : `import { wrapMcpServer, serveMcpOverStdio, signEnvelopeEd25519 } from '@7h3/protocol'`

  const envBlock = signingMethod === 'hmac'
    ? `const SECRET = process.env.AIP_SECRET ?? 'REPLACE_ME'`
    : `const PRIVATE_KEY = process.env.AIP_PRIVATE_KEY ?? 'REPLACE_ME'
const CLIENT_PUBLIC_KEY = process.env.AIP_CLIENT_PUBLIC_KEY ?? 'REPLACE_ME'`

  const signFn = signingMethod === 'hmac'
    ? `(e) => signEnvelopeHmac(e, SECRET, 'k1')`
    : `(e) => signEnvelopeEd25519(e, PRIVATE_KEY, 'k1')`

  const receiveBlock = signingMethod === 'hmac'
    ? `receive: { secretResolver: async () => SECRET }`
    : `receive: {
      signatureResolver: async (sig) =>
        sig.alg === 'ED25519' ? { alg: 'ED25519' as const, publicKey: CLIENT_PUBLIC_KEY } : undefined,
    }`

  const peerLine = clientAgentId ? `\n    peerAgentId: '${clientAgentId}',` : ''

  const wrapCall = `wrapMcpServer(myHandler, {
    selfAgentId: '${serverAgentId}',${peerLine}
    sign: ${signFn},
    ${receiveBlock},
  })`

  const transportBlock = transport === 'stdio'
    ? `serveMcpOverStdio(${wrapCall})`
    : `import { createHttpMcpHandler } from '@7h3/protocol'
import http from 'node:http'

const handler = createHttpMcpHandler(${wrapCall})

http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/mcp') return handler(req, res)
  res.writeHead(404).end()
}).listen(3000)`

  return `// AIP-hardened MCP server — generated by @7h3/protocol-mcp
// Install: npm install @7h3/protocol
${imports}

${envBlock}

// Your existing JSON-RPC handler — zero changes needed here
async function myHandler(request: unknown): Promise<unknown> {
  throw new Error('Replace with your handler logic')
}

${transportBlock}
`
}

// ── start ─────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport()
await server.connect(transport)
