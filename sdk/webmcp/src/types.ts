/**
 * Core types for @7h3/webmcp.
 *
 * The vocabulary here deliberately mirrors the WebMCP specification
 * (https://webmachinelearning.github.io/webmcp/) so that a guarded tool is
 * shape-compatible with an unguarded one: anything you can pass to
 * `document.modelContext.registerTool` you can pass to `guard().registerTool`.
 */

import type { CapabilityToken } from '@7h3/protocol'

/**
 * The subset of the WebMCP `ModelContextTool` dictionary we depend on.
 *
 * Mirrors the spec IDL rather than importing it: the DOM lib does not yet ship
 * `document.modelContext` types, and pinning our own copy keeps the package
 * buildable on any TypeScript version.
 */
export interface ModelContextTool {
  name: string
  title?: string
  description: string
  inputSchema?: object
  annotations?: ToolAnnotations
  execute: (input: Record<string, unknown>, options?: unknown) => Promise<unknown>
}

/** WebMCP tool annotations. `readOnlyHint` drives our READ/WRITE classification. */
export interface ToolAnnotations {
  readOnlyHint?: boolean
  destructiveHint?: boolean
  idempotentHint?: boolean
  openWorldHint?: boolean
  [k: string]: unknown
}

/** Options bag accepted by `registerTool`, per the spec (AbortSignal-based teardown). */
export interface RegisterToolOptions {
  signal?: AbortSignal
}

/**
 * The slice of `document.modelContext` we call. Injectable so the guard can be
 * unit-tested headlessly and so a page can register into a mock during dev.
 */
export interface ModelContextLike {
  registerTool(tool: ModelContextTool, options?: RegisterToolOptions): Promise<void>
}

// ---------------------------------------------------------------------------
// Guarded tools
// ---------------------------------------------------------------------------

/**
 * A WebMCP tool plus the authorization metadata 7h3 needs.
 *
 * Everything beyond `scope`, `limit` and `confirm` is passed through to
 * `document.modelContext.registerTool` untouched.
 */
export interface GuardedTool extends ModelContextTool {
  /**
   * Path-shaped capability scope this tool sits behind, e.g. `money/pay_invoice`.
   *
   * Omit to publish the tool unguarded — appropriate for genuinely public reads.
   * An omitted scope is recorded in the signed manifest as `public`, so an
   * auditor can see exactly which tools carry no authorization requirement
   * rather than having to infer it.
   */
  scope?: string
  /**
   * Numeric ceiling enforced before `execute` runs. `field` names the input
   * property to read (in minor units, e.g. cents) and `max` is the inclusive
   * limit. A grant may tighten this further but never loosen it.
   */
  limit?: { field: string; max: number }
  /** Marks the tool as requiring explicit human confirmation for each call. */
  confirm?: boolean
}

/**
 * The agent-visible surface of a tool: everything a manifest covers.
 *
 * `execute` is excluded deliberately. A manifest describes what an agent can
 * see and decide from, so it can be built and signed at deploy time from a
 * declarative tool table, with no handlers — and therefore no application code —
 * in scope.
 */
export type ToolSurface = Omit<GuardedTool, 'execute'>

/** Why a call was refused. Stable string ids — they end up in signed receipts. */
export type RefusalReason =
  | 'no-active-grant'
  | 'grant-expired'
  | 'grant-invalid-signature'
  | 'grant-revoked'
  | 'scope-not-covered'
  | 'limit-exceeded'
  | 'replayed-call'
  | 'confirmation-denied'
  | 'unknown-tool'

export type GuardDecision =
  | { allowed: true; grantId: string | null }
  | { allowed: false; reason: RefusalReason; detail: string }

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

/**
 * One link in the hash-chained receipt log.
 *
 * `prevHash` binds each entry to its predecessor, so removing or editing any
 * historical entry invalidates every entry after it. `signature` is an Ed25519
 * signature over the canonical form of every other field.
 */
export interface Receipt {
  seq: number
  id: string
  timestampMs: number
  tool: string
  scope: string
  method: 'READ' | 'WRITE'
  outcome: 'allowed' | 'refused'
  reason?: RefusalReason
  detail?: string
  grantId: string | null
  /** SHA-256 of the canonical input, so inputs are provable without being disclosed. */
  inputHash: string
  prevHash: string
  signature: string
  keyId: string
}

export interface ChainVerification {
  ok: boolean
  length: number
  /** Index of the first entry that failed, or null when the whole chain verifies. */
  brokenAt: number | null
  reason?: string
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/** A single tool as published in the signed manifest. */
export interface ManifestEntry {
  name: string
  description: string
  scope: string
  method: 'READ' | 'WRITE'
  /** SHA-256 over name + description + inputSchema + annotations. */
  digest: string
}

/**
 * The page's signed declaration of its own tool surface.
 *
 * OpenAI's WebMCP guidance is explicit that "a tool's name or claim that it only
 * reads data isn't proof of what it does". A manifest signed by the origin's key
 * turns that claim into something checkable: an injected or swapped tool changes
 * the digest, and the signature stops verifying.
 */
export interface SignedManifest {
  version: '7h3-webmcp-manifest/1'
  origin: string
  issuedAt: number
  tools: ManifestEntry[]
  /** SHA-256 over the concatenated per-tool digests, in registration order. */
  surfaceDigest: string
  signature: string
  keyId: string
}

// ---------------------------------------------------------------------------
// Events (for live UI)
// ---------------------------------------------------------------------------

export type GuardEvent =
  | { type: 'tool-registered'; tool: string; scope: string; method: 'READ' | 'WRITE' }
  | { type: 'grant-issued'; grant: CapabilityToken }
  | { type: 'grant-revoked'; grantId: string }
  | { type: 'call'; receipt: Receipt }

export type GuardEventListener = (event: GuardEvent) => void
