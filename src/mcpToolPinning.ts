/**
 * MCP tool pinning: detect a server changing what a tool says or does after you
 * approved it ("rug pull"), and refuse tools whose text hides instructions in
 * invisible characters ("tool poisoning" via ASCII smuggling).
 *
 * The threat. An MCP client shows a model — and usually a human — each tool's
 * `description` and `inputSchema`. Those strings are instructions to the model. A
 * server can (a) ship benign text, get approved, then change it; or (b) put
 * instructions in the description that a human reviewer cannot see. Message
 * signing does not help: the malicious text arrives correctly signed by the
 * server you chose to trust.
 *
 * The defense here is deliberately narrow and deterministic:
 *
 *   1. PIN. Each approved tool is recorded as a SHA-256 digest of everything a
 *      model can read about it (name, title, description, input/output schema,
 *      annotations). Any later difference — one word, one schema default — is a
 *      changed tool.
 *   2. SCAN. Tool text containing invisible or direction-overriding characters is
 *      refused outright. That is a mechanical property, not a judgement.
 *   3. ENFORCE. {@link guardMcpClient} filters `tools/list` results and refuses
 *      `tools/call` for anything that is not currently pinned and verified.
 *
 * What it does NOT do: judge whether visible text is malicious. A poisoned
 * description written in plain sight is caught only if it differs from the pin a
 * human approved, which is why approval of the pin set is the trust decision.
 */

import { sha256Hex, stableStringify } from './actionBinding'
import { signCanonicalPayloadEd25519, verifyCanonicalPayloadEd25519 } from './protocol'
import type { JsonRpcRequest, JsonRpcResponse } from './mcpWrapper'

export interface McpTool {
  name: string
  title?: string
  description?: string
  inputSchema?: unknown
  outputSchema?: unknown
  annotations?: Record<string, unknown>
  // Anything else (e.g. `_meta`, icons) is not part of what the model reads and is ignored by the digest.
  [extra: string]: unknown
}

/** The fields a model reads. Only these participate in the digest. */
const DIGEST_FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations'] as const

export async function toolDigest(tool: McpTool): Promise<string> {
  const picked: Record<string, unknown> = {}
  for (const f of DIGEST_FIELDS) {
    if (tool[f] !== undefined) picked[f] = tool[f]
  }
  return sha256Hex(stableStringify(picked))
}

// ---------------------------------------------------------------------------
// Scanning for hidden text
// ---------------------------------------------------------------------------

export type ToolFindingKind = 'invisible-character' | 'bidi-control' | 'tag-character' | 'control-character' | 'oversized-text'

export interface ToolFinding {
  kind: ToolFindingKind
  /** JSON path of the offending string within the tool, e.g. `inputSchema.properties.q.description`. */
  path: string
  /** Code point, e.g. `U+200B`, when applicable. */
  codePoint?: string
}

export const MAX_TOOL_TEXT_LENGTH = 8_000
const MAX_SCAN_DEPTH = 32
const MAX_SCAN_STRINGS = 5_000

function classify(cp: number): ToolFindingKind | null {
  if (cp >= 0xe0000 && cp <= 0xe007f) return 'tag-character' // Unicode "tag" block: renders as nothing, carries ASCII
  if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) return 'bidi-control'
  if (
    (cp >= 0x200b && cp <= 0x200f) || // zero-width space/joiners, LRM/RLM
    (cp >= 0x2060 && cp <= 0x2064) || // word joiner, invisible operators
    cp === 0xfeff ||
    cp === 0x00ad || // soft hyphen
    cp === 0x034f || // combining grapheme joiner
    cp === 0x061c || // Arabic letter mark
    (cp >= 0xfe00 && cp <= 0xfe0f) || // variation selectors
    (cp >= 0xe0100 && cp <= 0xe01ef) || // variation selectors supplement
    cp === 0x115f ||
    cp === 0x1160 ||
    cp === 0x3164 ||
    cp === 0xffa0 // hangul fillers
  ) {
    return 'invisible-character'
  }
  if ((cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) || (cp >= 0x7f && cp <= 0x9f)) return 'control-character'
  return null
}

/** Find hidden or direction-overriding characters anywhere in a tool's readable text. */
export function scanTool(tool: McpTool): ToolFinding[] {
  const findings: ToolFinding[] = []
  let visited = 0
  const seen = new Set<string>()

  const scanString = (s: string, path: string): void => {
    if (s.length > MAX_TOOL_TEXT_LENGTH) findings.push({ kind: 'oversized-text', path })
    for (const ch of s) {
      const cp = ch.codePointAt(0)!
      const kind = classify(cp)
      if (!kind) continue
      const key = `${kind}:${path}:${cp}`
      if (seen.has(key)) continue
      seen.add(key)
      findings.push({ kind, path, codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, '0')}` })
    }
  }

  const walk = (value: unknown, path: string, depth: number): void => {
    if (visited++ > MAX_SCAN_STRINGS) return
    if (typeof value === 'string') return scanString(value, path)
    if (depth >= MAX_SCAN_DEPTH || typeof value !== 'object' || value === null) return
    if (Array.isArray(value)) {
      value.forEach((v, i) => walk(v, `${path}[${i}]`, depth + 1))
      return
    }
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      scanString(k, `${path}{key}`) // property names are model-visible too
      walk(v, path ? `${path}.${k}` : k, depth + 1)
    }
  }
  for (const f of DIGEST_FIELDS) {
    if (tool[f] !== undefined) walk(tool[f], f, 0)
  }
  return findings
}

// ---------------------------------------------------------------------------
// Pin sets
// ---------------------------------------------------------------------------

export const TOOL_PINS_VERSION = '7h3-toolpins/1'

export interface ToolPin {
  name: string
  digest: string
}

export interface ToolPinSet {
  version: typeof TOOL_PINS_VERSION
  /** The server identity these pins are for. Pins never transfer between servers. */
  server: string
  pins: ToolPin[]
  approvedAt: number
  approvedBy?: string
}

export interface SignedToolPinSet extends ToolPinSet {
  keyId: string
  signature: string
}

export async function pinTools(server: string, tools: readonly McpTool[], opts: { approvedBy?: string; now?: number } = {}): Promise<ToolPinSet> {
  const names = new Set<string>()
  const pins: ToolPin[] = []
  for (const t of tools) {
    if (typeof t.name !== 'string' || t.name.length === 0) throw new Error('pinTools: every tool needs a name')
    if (names.has(t.name)) throw new Error(`pinTools: duplicate tool name '${t.name}'`)
    names.add(t.name)
    const findings = scanTool(t)
    if (findings.length > 0) throw new Error(`pinTools: refusing to pin '${t.name}': ${findings[0].kind} at ${findings[0].path}`)
    pins.push({ name: t.name, digest: await toolDigest(t) })
  }
  pins.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
  return { version: TOOL_PINS_VERSION, server, pins, approvedAt: opts.now ?? Date.now(), ...(opts.approvedBy ? { approvedBy: opts.approvedBy } : {}) }
}

function canonicalPins(p: ToolPinSet & { keyId?: string }): string {
  return stableStringify({
    version: p.version,
    server: p.server,
    pins: p.pins.map((x) => ({ name: x.name, digest: x.digest })),
    approvedAt: p.approvedAt,
    approvedBy: p.approvedBy ?? null,
    keyId: p.keyId ?? null,
  })
}

/** Sign a pin set so it can be distributed (e.g. by an org's security team) and trusted by clients. */
export async function signToolPins(set: ToolPinSet, opts: { privateKey: string; keyId: string }): Promise<SignedToolPinSet> {
  const withKey = { ...set, keyId: opts.keyId }
  return { ...withKey, signature: await signCanonicalPayloadEd25519(canonicalPins(withKey), opts.privateKey) }
}

export type ToolPinVerifyResult = { ok: true; set: ToolPinSet } | { ok: false; reason: 'wrong-server' | 'unsupported-version' | 'invalid-signature' | 'malformed' }

export async function verifyToolPins(signed: SignedToolPinSet, opts: { publicKey: string; expectedServer: string }): Promise<ToolPinVerifyResult> {
  if (!signed || signed.version !== TOOL_PINS_VERSION) return { ok: false, reason: 'unsupported-version' }
  if (!Array.isArray(signed.pins) || typeof signed.signature !== 'string' || typeof signed.keyId !== 'string') return { ok: false, reason: 'malformed' }
  if (signed.server !== opts.expectedServer) return { ok: false, reason: 'wrong-server' }
  let valid: boolean
  try {
    valid = await verifyCanonicalPayloadEd25519(canonicalPins(signed), signed.signature, opts.publicKey)
  } catch {
    return { ok: false, reason: 'malformed' }
  }
  if (!valid) return { ok: false, reason: 'invalid-signature' }
  return {
    ok: true,
    set: {
      version: signed.version,
      server: signed.server,
      pins: signed.pins.map((p) => ({ name: p.name, digest: p.digest })),
      approvedAt: signed.approvedAt,
      ...(signed.approvedBy ? { approvedBy: signed.approvedBy } : {}),
    },
  }
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

export type ToolStatus = 'ok' | 'unpinned' | 'changed' | 'suspicious' | 'duplicate'

export interface ToolVerdict {
  name: string
  status: ToolStatus
  blocked: boolean
  currentDigest?: string
  pinnedDigest?: string
  findings?: ToolFinding[]
}

export interface ListInspection {
  verdicts: ToolVerdict[]
  /** Tools safe to expose: pinned, unchanged, clean (and unpinned ones when `allowUnpinned`). */
  allowed: McpTool[]
  /** Pinned tools the server no longer lists. Informational: removal cannot harm a client. */
  missing: string[]
}

export interface ToolGuardOptions {
  /**
   * Trust-on-first-use for tools that were never pinned. Default false: a tool you
   * did not approve is not exposed. When true, unpinned tools are still scanned
   * and are pinned as they first appear.
   */
  allowUnpinned?: boolean
}

export class ToolGuard {
  private readonly pinned = new Map<string, string>()
  readonly server: string
  private readonly allowUnpinned: boolean

  constructor(pins: ToolPinSet, options: ToolGuardOptions = {}) {
    if (pins.version !== TOOL_PINS_VERSION) throw new Error('ToolGuard: unsupported pin set version')
    this.server = pins.server
    for (const p of pins.pins) this.pinned.set(p.name, p.digest)
    this.allowUnpinned = options.allowUnpinned ?? false
  }

  get pinCount(): number {
    return this.pinned.size
  }

  async inspect(tools: readonly McpTool[]): Promise<ListInspection> {
    const counts = new Map<string, number>()
    for (const t of tools) counts.set(t.name, (counts.get(t.name) ?? 0) + 1)

    const verdicts: ToolVerdict[] = []
    const allowed: McpTool[] = []
    const seen = new Set<string>()
    for (const tool of tools) {
      const name = typeof tool.name === 'string' ? tool.name : ''
      if (!name) {
        verdicts.push({ name: '', status: 'suspicious', blocked: true })
        continue
      }
      // Two tools with one name is how a hostile server shadows a trusted tool.
      if ((counts.get(name) ?? 0) > 1) {
        if (!seen.has(name)) verdicts.push({ name, status: 'duplicate', blocked: true })
        seen.add(name)
        continue
      }
      const findings = scanTool(tool)
      const currentDigest = await toolDigest(tool)
      const pinnedDigest = this.pinned.get(name)
      let v: ToolVerdict
      if (findings.length > 0) v = { name, status: 'suspicious', blocked: true, currentDigest, pinnedDigest, findings }
      else if (pinnedDigest === undefined) {
        v = { name, status: 'unpinned', blocked: !this.allowUnpinned, currentDigest }
        if (this.allowUnpinned) this.pinned.set(name, currentDigest)
      } else if (pinnedDigest !== currentDigest) v = { name, status: 'changed', blocked: true, currentDigest, pinnedDigest }
      else v = { name, status: 'ok', blocked: false, currentDigest, pinnedDigest }
      verdicts.push(v)
      if (!v.blocked) allowed.push(tool)
    }
    const listed = new Set(tools.map((t) => t.name))
    const missing = [...this.pinned.keys()].filter((n) => !listed.has(n))
    return { verdicts, allowed, missing }
  }

  /** Whether a tool name has a pin (or was trust-on-first-use pinned). */
  isPinned(name: string): boolean {
    return this.pinned.has(name)
  }
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

export const TOOL_BLOCKED_CODE = -32001

export interface GuardMcpClientOptions {
  /** How long a verified tool list is trusted before `tools/call` re-verifies it (default 30 s). */
  maxListAgeMs?: number
  /** Pages fetched when re-verifying (default 20). */
  maxPages?: number
  /** Called for every blocked tool, for logging or alerts. */
  onBlocked?: (verdict: ToolVerdict) => void
  now?: () => number
}

function blockedResponse(id: JsonRpcRequest['id'], reason: string): JsonRpcResponse {
  return { jsonrpc: '2.0', id, error: { code: TOOL_BLOCKED_CODE, message: `tool-blocked: ${reason}` } }
}

function isToolArray(value: unknown): value is McpTool[] {
  return Array.isArray(value) && value.every((t) => typeof t === 'object' && t !== null)
}

/**
 * Wrap an MCP client call function so the model only ever sees, and can only ever
 * call, tools that are pinned and unchanged.
 *
 *   - `tools/list` responses are filtered: changed, suspicious, duplicate and
 *     (by default) unpinned tools are removed before the caller sees them.
 *   - `tools/call` for a tool that is not currently verified is refused. If the
 *     last verification is older than `maxListAgeMs`, the guard re-lists and
 *     re-verifies first — closing the gap between "listed benign" and "called
 *     after the description changed".
 *
 * Call {@link ToolGuardHandle.invalidate} when the server sends
 * `notifications/tools/list_changed` so the next call re-verifies immediately.
 */
export interface ToolGuardHandle {
  call: (request: JsonRpcRequest) => Promise<JsonRpcResponse>
  invalidate: () => void
}

export function guardMcpClient(
  call: (request: JsonRpcRequest) => Promise<JsonRpcResponse>,
  guard: ToolGuard,
  options: GuardMcpClientOptions = {},
): ToolGuardHandle {
  const now = options.now ?? Date.now
  const maxAge = options.maxListAgeMs ?? 30_000
  const maxPages = options.maxPages ?? 20
  let verified = new Map<string, ToolVerdict>()
  let verifiedAt = -Infinity
  let nextId = 0

  const record = (inspection: ListInspection): void => {
    for (const v of inspection.verdicts) {
      if (v.blocked) options.onBlocked?.(v)
    }
  }

  async function refresh(): Promise<boolean> {
    const fresh = new Map<string, ToolVerdict>()
    let cursor: string | undefined
    for (let page = 0; page < maxPages; page++) {
      const res = await call({ jsonrpc: '2.0', id: `7h3-guard-${nextId++}`, method: 'tools/list', ...(cursor ? { params: { cursor } } : {}) })
      const tools = (res.result as { tools?: unknown } | undefined)?.tools
      if (res.error || !isToolArray(tools)) return false
      const inspection = await guard.inspect(tools)
      record(inspection)
      for (const v of inspection.verdicts) fresh.set(v.name, v)
      const next = (res.result as { nextCursor?: unknown }).nextCursor
      if (typeof next !== 'string' || next.length === 0) {
        verified = fresh
        verifiedAt = now()
        return true
      }
      cursor = next
    }
    return false // never finished paging: do not trust a partial list
  }

  return {
    invalidate: () => {
      verifiedAt = -Infinity
    },
    call: async (request) => {
      if (request.method === 'tools/list') {
        const res = await call(request)
        const tools = (res.result as { tools?: unknown } | undefined)?.tools
        if (res.error || !isToolArray(tools)) return res
        const inspection = await guard.inspect(tools)
        record(inspection)
        for (const v of inspection.verdicts) verified.set(v.name, v)
        // A list response that has not been verified as a full sweep does not refresh the clock:
        // only a complete `refresh()` does.
        return { ...res, result: { ...(res.result as object), tools: inspection.allowed } }
      }

      if (request.method === 'tools/call') {
        const name = (request.params as { name?: unknown } | undefined)?.name
        if (typeof name !== 'string') return call(request)
        if (now() - verifiedAt >= maxAge && !(await refresh())) {
          return blockedResponse(request.id, 'could not verify the server\'s tool list')
        }
        const v = verified.get(name)
        if (!v) return blockedResponse(request.id, `'${name}' is not a known tool`)
        if (v.blocked) return blockedResponse(request.id, `'${name}' is ${v.status}`)
        return call(request)
      }
      return call(request)
    },
  }
}
