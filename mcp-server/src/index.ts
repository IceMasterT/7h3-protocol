#!/usr/bin/env node
import { buildScaffold } from './scaffold'
import { MCP_PACKAGE_SPEC, MCP_VERSION } from './version'
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

const server = new McpServer({ name: '@7h3/protocol-mcp', version: MCP_VERSION })

// Agent identifiers get embedded into generated source code (buildScaffold,
// buildBoilerplate) that this tool tells callers is "ready-to-paste" with
// "zero changes." A value containing a quote, backtick, or newline could
// break out of the string literal (or `//` comment) it's embedded in and
// inject arbitrary code into a file the caller then runs — restricting the
// charset up front means there's no injection-shaped value to embed in the
// first place, on top of the JSON.stringify() escaping at each embed site.
const agentIdSchema = z.string().min(1).max(256).regex(
  /^[A-Za-z0-9._@:-]+$/,
  'must contain only letters, digits, and . _ @ : -',
)

// ── 7h3_generate_secret ───────────────────────────────────────────────────────

server.registerTool(
  '7h3_generate_secret',
  {
    description: 'Generate a cryptographically random 32-byte HMAC secret for 7h3 Protocol message signing. Returns the value to store as P7H3_SECRET.',
  },
  async () => {
    const secret = randomBytes(32).toString('base64url')
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          secret,
          envVar: 'P7H3_SECRET',
          warning: 'Never commit this value. Add to .env and .gitignore.',
        }, null, 2),
      }],
    }
  },
)

// ── 7h3_generate_keypair ──────────────────────────────────────────────────────

server.registerTool(
  '7h3_generate_keypair',
  {
    description: 'Generate an Ed25519 keypair for 7h3 Protocol message signing. Returns publicKey (safe to share) and privateKey (keep secret).',
  },
  async () => {
    const keypair = await generateEd25519KeypairBase64Url()
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          publicKey: keypair.publicKey,
          privateKey: keypair.privateKey,
          envVars: { privateKey: 'P7H3_PRIVATE_KEY', publicKey: 'P7H3_PUBLIC_KEY' },
          warning: 'Never commit privateKey. Share publicKey with peers who need to verify your messages.',
        }, null, 2),
      }],
    }
  },
)

// ── 7h3_wrap_mcp_server ───────────────────────────────────────────────────────

server.registerTool(
  '7h3_wrap_mcp_server',
  {
    description: 'Generate ready-to-paste TypeScript boilerplate to wrap an existing MCP server handler with 7h3 Protocol signing and replay protection. Zero changes to your handler required.',
    inputSchema: {
      serverAgentId: agentIdSchema.describe('Unique ID for this server agent, e.g. "my-tool-server"'),
      clientAgentId: agentIdSchema.optional().describe('Expected client agent ID for sender binding. Omit to accept any signed client.'),
      transport: z.enum(['stdio', 'http']).optional().describe('Transport type. Default: stdio'),
      signingMethod: z.enum(['hmac', 'ed25519']).optional().describe('Signing algorithm. hmac = shared secret (dev/trusted infra), ed25519 = keypair (recommended for production). Default: hmac'),
    },
  },
  async ({ serverAgentId, clientAgentId, transport = 'stdio', signingMethod = 'hmac' }) => {
    return {
      content: [{ type: 'text', text: buildBoilerplate(serverAgentId, clientAgentId, transport, signingMethod) }],
    }
  },
)

// ── 7h3_sign ──────────────────────────────────────────────────────────────────

server.registerTool(
  '7h3_sign',
  {
    description: 'Sign a test 7h3 Protocol envelope. Useful for debugging or generating test fixtures.',
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

// ── 7h3_verify ────────────────────────────────────────────────────────────────

server.registerTool(
  '7h3_verify',
  {
    description: 'Verify a 7h3 Protocol envelope signature and validate its shape, TTL, and version.',
    inputSchema: {
      envelopeJson: z.string().describe('JSON string of the 7h3 Protocol envelope to verify'),
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

// ── 7h3_scaffold ──────────────────────────────────────────────────────────────

server.registerTool(
  '7h3_scaffold',
  {
    description:
      'Generate ready-to-paste integration code that adds 7h3 Protocol verification to a target framework or runtime. ' +
      "Use framework='webmcp' to put signed, capability-scoped, receipted WebMCP tools (document.modelContext) on a web page.",
    inputSchema: {
      framework: z.enum(['webmcp', 'cloudflare-worker', 'nextjs', 'express', 'hono', 'fastify', 'claude-code', 'raw']).describe(
        'Target framework or runtime to generate scaffold code for.',
      ),
      signingMethod: z.enum(['ed25519', 'hmac']).describe(
        'Signing algorithm. ed25519 = keypair (recommended for production), hmac = shared secret (dev/trusted infra).',
      ),
      sender: agentIdSchema.describe('Agent identity of the sender, e.g. "my-agent@example.com".'),
      upstream: z.string().url().max(2048).optional().describe('Upstream URL to proxy to — used for cloudflare-worker gateway pattern.'),
    },
  },
  async ({ framework, signingMethod, sender, upstream }) => {
    const code = buildScaffold(framework, signingMethod, sender, upstream)
    return {
      content: [{ type: 'text', text: code }],
    }
  },
)

// ── 7h3_mcp_config ────────────────────────────────────────────────────────────

server.registerTool(
  '7h3_mcp_config',
  {
    description: 'Output the exact configuration JSON/command to install the @7h3/protocol MCP server into Claude Code, Cursor, Opencode, or via npx.',
  },
  async () => {
    const config = {
      claudeCode: {
        description: 'Paste into .claude/settings.json under mcpServers',
        settings: {
          mcpServers: {
            '7h3-protocol': {
              command: 'npx',
              args: ['-y', MCP_PACKAGE_SPEC],
            },
          },
        },
      },
      cursor: {
        description: 'Paste into Cursor MCP settings (Settings → MCP → Add Server)',
        settings: {
          mcpServers: {
            '7h3-protocol': {
              command: 'npx',
              args: ['-y', MCP_PACKAGE_SPEC],
            },
          },
        },
      },
      opencode: {
        description: 'Paste into opencode config (~/.config/opencode/config.json)',
        config: {
          mcp: {
            '7h3-protocol': {
              type: 'local',
              command: ['npx', '-y', MCP_PACKAGE_SPEC],
            },
          },
        },
      },
      npx: {
        description: 'Run directly without installing',
        command: `npx -y ${MCP_PACKAGE_SPEC}`,
      },
    }

    return {
      content: [{
        type: 'text',
        text: [
          '# @7h3/protocol MCP Server — Installation Config',
          '',
          '## Claude Code (.claude/settings.json)',
          '```json',
          JSON.stringify(config.claudeCode.settings, null, 2),
          '```',
          '',
          '## Cursor (Settings → MCP → Add Server)',
          '```json',
          JSON.stringify(config.cursor.settings, null, 2),
          '```',
          '',
          '## Opencode (~/.config/opencode/config.json)',
          '```json',
          JSON.stringify(config.opencode.config, null, 2),
          '```',
          '',
          '## npx (run without installing)',
          '```sh',
          config.npx.command,
          '```',
        ].join('\n'),
      }],
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
    ? `const SECRET = process.env.P7H3_SECRET ?? 'REPLACE_ME'`
    : `const PRIVATE_KEY = process.env.P7H3_PRIVATE_KEY ?? 'REPLACE_ME'
const CLIENT_PUBLIC_KEY = process.env.P7H3_CLIENT_PUBLIC_KEY ?? 'REPLACE_ME'`

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

  const productionNote = signingMethod === 'hmac'
    ? `// For production, use Ed25519 (run 7h3_generate_keypair and regenerate with signingMethod='ed25519')\n`
    : ''

  return `// 7h3 Protocol-hardened MCP server — generated by @7h3/protocol-mcp
// Install: npm install @7h3/protocol
${imports}

${productionNote}${envBlock}

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
