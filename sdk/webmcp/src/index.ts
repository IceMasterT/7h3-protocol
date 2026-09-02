/**
 * @7h3/protocol-webmcp — signed, capability-scoped, receipted WebMCP tools.
 *
 * WebMCP gives agents hands. This gives those hands a signature, a scope,
 * and a receipt.
 *
 * @example
 * ```ts
 * import { guard } from '@7h3/protocol-webmcp'
 *
 * const g = guard({ origin: 'ledger.example', privateKey, publicKey })
 *
 * await g.registerTool({
 *   name: 'pay_invoice',
 *   description: 'Pay an outstanding invoice',
 *   inputSchema: { type: 'object', properties: { id: { type: 'string' }, amountCents: { type: 'number' } } },
 *   annotations: { destructiveHint: true },
 *   scope: 'money/pay_invoice',
 *   limit: { field: 'amountCents', max: 100_00 },
 *   execute: async ({ id }) => payInvoice(id as string),
 * })
 *
 * // Human consents, in the page, to a scoped and expiring grant:
 * await g.grant({ subject: 'chatgpt-agent', scopes: ['money/*'], caps: { amountCents: 50_00 }, ttlMs: 600_000 })
 * ```
 */

export {
  guard,
  ToolGuard,
  InMemoryReplayChecker,
  MIN_REPLAY_RETENTION_MS,
  isWebMcpSupported,
  parseCaps,
  GRANT_FIELD,
  NONCE_FIELD,
  CAPS_PREFIX,
  type GuardOptions,
  type GrantRequest,
  type ReplayChecker,
} from './guard.js'

export {
  ReceiptLog,
  verifyChain,
  receiptHash,
  canonicalReceiptPayload,
  GENESIS_HASH,
  type AppendReceiptInput,
} from './receipts.js'

export {
  signManifest,
  verifyManifest,
  diffAgainstManifest,
  manifestEntry,
  surfaceDigest,
  toolDigest,
  toolMethod,
  canonicalManifestPayload,
  type ManifestVerification,
} from './manifest.js'

export { sha256Hex, canonicalJson } from './crypto.js'

export type {
  ChainVerification,
  GuardDecision,
  GuardEvent,
  GuardEventListener,
  GuardedTool,
  ManifestEntry,
  ModelContextLike,
  ModelContextTool,
  Receipt,
  RefusalReason,
  RegisterToolOptions,
  SignedManifest,
  ToolAnnotations,
  ToolSurface,
} from './types.js'
