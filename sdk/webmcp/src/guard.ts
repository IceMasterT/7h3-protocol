/**
 * `guard()` — capability-scoped, replay-protected, receipted WebMCP tools.
 *
 * WebMCP hands agents real hands on a live, signed-in page. Chrome's agent
 * security guidance is entirely probabilistic (prompt-injection classifiers,
 * spotlighting, critic LLMs) and OpenAI's guidance tells sites to "use your
 * application's existing authentication, authorization, and input validation" —
 * but sites have no existing authorization model for *delegated agent* action.
 *
 * This is that model, and it is deterministic. A refusal here is a failed
 * signature or an uncovered scope, not a judgement call, so no amount of
 * prompt injection talks its way past it.
 */

import {
  issueCapabilityToken,
  parseCapabilityChain,
  tokenMatchesScope,
  verifyCapabilityChain,
  verifyCapabilityToken,
  type CapabilityScope,
  type CapabilityToken,
} from '@7h3/protocol'
import { canonicalJson, sha256Hex } from './crypto'
import { manifestEntry, signManifest, toolMethod } from './manifest'
import { ReceiptLog } from './receipts'
import type {
  GuardDecision,
  GuardEvent,
  GuardEventListener,
  GuardedTool,
  ModelContextLike,
  ModelContextTool,
  RegisterToolOptions,
  SignedManifest,
} from './types'

/** Reserved input field carrying an explicit bearer grant chain (cross-agent delegation). */
export const GRANT_FIELD = '__7h3_grant'
/** Reserved input field carrying a single-use call nonce. */
export const NONCE_FIELD = '__7h3_nonce'
/** Reserved capability scope prefix encoding a numeric ceiling: `caps/<field>/<max>`. */
export const CAPS_PREFIX = 'caps/'

/** Minimal replay-store surface: returns true when the key has been seen before. */
export interface ReplayChecker {
  check(key: string, ttlMs: number): Promise<boolean>
}

/** Zero-dependency replay store. Adequate for a page session; swap for Redis/KV server-side. */
export class InMemoryReplayChecker implements ReplayChecker {
  private seen = new Map<string, number>()
  constructor(private readonly now: () => number = () => Date.now()) {}
  async check(key: string, ttlMs: number): Promise<boolean> {
    const now = this.now()
    for (const [k, expiry] of this.seen) if (expiry <= now) this.seen.delete(k)
    if (this.seen.has(key)) return true
    this.seen.set(key, now + ttlMs)
    return false
  }
}

export interface GuardOptions {
  /** Logical origin id, e.g. `ledger.7h3.dev`. Appears in manifests and grants. */
  origin: string
  /** Ed25519 PKCS8 private key (base64url) used to sign grants, receipts and the manifest. */
  privateKey: string
  /** Matching SPKI public key (base64url). Used to verify grants this origin issued. */
  publicKey: string
  keyId?: string
  /** Defaults to `document.modelContext`. Injectable for tests and headless use. */
  modelContext?: ModelContextLike
  replay?: ReplayChecker
  now?: () => number
  /** Called when a tool declares `confirm: true`. Returning false refuses the call. */
  onConfirm?: (tool: GuardedTool, input: Record<string, unknown>) => Promise<boolean>
  /** Additional issuer public keys, for verifying bearer chains from other origins. */
  peerKeys?: Record<string, string>
}

export interface GrantRequest {
  /** Who the grant is for, e.g. `chatgpt-agent`. Recorded in every receipt. */
  subject: string
  /** Capability scopes, path-shaped and glob-matched: `invoices/*`, `money/**`. */
  scopes: string[]
  ttlMs: number
  /** Numeric ceilings bound *inside* the signed token, e.g. `{ amountCents: 5000 }`. */
  caps?: Record<string, number>
  /** How many further delegations are permitted. Defaults to 0 (no re-delegation). */
  maxDelegations?: number
}

/** Parse reserved `caps/<field>/<max>` scopes out of a verified token. */
export function parseCaps(token: CapabilityToken): Record<string, number> {
  const caps: Record<string, number> = {}
  for (const scope of token.scopes) {
    if (!scope.pathGlob.startsWith(CAPS_PREFIX)) continue
    const [, field, raw] = scope.pathGlob.split('/')
    const value = Number(raw)
    if (field && Number.isFinite(value)) caps[field] = value
  }
  return caps
}

export class ToolGuard {
  readonly receipts: ReceiptLog
  private readonly opts: GuardOptions
  private readonly keyId: string
  private readonly now: () => number
  private readonly replay: ReplayChecker
  private readonly tools = new Map<string, GuardedTool>()
  private readonly wrapped = new Map<string, ModelContextTool>()
  private readonly grants = new Map<string, CapabilityToken>()
  private readonly revoked = new Set<string>()
  private readonly listeners = new Set<GuardEventListener>()
  private mc: ModelContextLike | undefined

  constructor(opts: GuardOptions) {
    this.opts = opts
    this.keyId = opts.keyId ?? `${opts.origin}-k1`
    this.now = opts.now ?? (() => Date.now())
    this.replay = opts.replay ?? new InMemoryReplayChecker(this.now)
    this.receipts = new ReceiptLog({ privateKey: opts.privateKey, keyId: this.keyId, now: this.now })
    this.mc = opts.modelContext
  }

  // -- events ---------------------------------------------------------------

  on(listener: GuardEventListener): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private emit(event: GuardEvent): void {
    for (const l of this.listeners) l(event)
  }

  // -- registration ---------------------------------------------------------

  /**
   * Register a tool with the same signature as
   * `document.modelContext.registerTool`, wrapping `execute` in the guard.
   *
   * The wrapper always runs: a refused call never reaches your handler, and both
   * outcomes are appended to the signed receipt chain before returning.
   */
  async registerTool(tool: GuardedTool, options?: RegisterToolOptions): Promise<void> {
    this.tools.set(tool.name, tool)

    const wrapped = {
      name: tool.name,
      title: tool.title,
      description: tool.description,
      inputSchema: tool.inputSchema,
      annotations: tool.annotations,
      execute: async (input: Record<string, unknown> = {}, execOptions?: unknown) => {
        const decision = await this.decide(tool, input)
        const inputHash = await sha256Hex(canonicalJson(stripReserved(input)))
        const method = toolMethod(tool)

        if (!decision.allowed) {
          const receipt = await this.receipts.append({
            tool: tool.name,
            scope: tool.scope ?? 'public',
            method,
            outcome: 'refused',
            reason: decision.reason,
            detail: decision.detail,
            grantId: null,
            inputHash,
          })
          this.emit({ type: 'call', receipt })
          // Surfaced to the agent as a structured refusal rather than a throw:
          // the agent should be able to read *why* and ask the human for a grant.
          return {
            ok: false,
            refused: true,
            reason: decision.reason,
            detail: decision.detail,
            receiptId: receipt.id,
          }
        }

        const result = await tool.execute(stripReserved(input), execOptions)
        const receipt = await this.receipts.append({
          tool: tool.name,
          scope: tool.scope ?? 'public',
          method,
          outcome: 'allowed',
          grantId: decision.grantId,
          inputHash,
        })
        this.emit({ type: 'call', receipt })
        return { ok: true, result, receiptId: receipt.id }
      },
    }

    this.wrapped.set(tool.name, wrapped)

    const mc = this.mc ?? resolveModelContext()
    if (mc) await mc.registerTool(wrapped, options)

    this.emit({
      type: 'tool-registered',
      tool: tool.name,
      scope: tool.scope ?? 'public',
      method: toolMethod(tool),
    })
  }

  // -- authorization --------------------------------------------------------

  /**
   * Decide whether a call may proceed. Pure with respect to application state,
   * so a UI can preview a decision without executing anything.
   */
  async decide(tool: GuardedTool, input: Record<string, unknown>): Promise<GuardDecision> {
    // A tool with no declared scope is published unguarded, by explicit choice.
    if (!tool.scope) return { allowed: true, grantId: null }

    const method = toolMethod(tool)
    const bearer = input[GRANT_FIELD]
    const candidates: CapabilityToken[] = []

    if (typeof bearer === 'string' && bearer.length > 0) {
      const chainResult = await this.verifyBearer(bearer, tool.scope, method)
      if (!chainResult.ok) return chainResult.decision
      candidates.push(chainResult.token)
    } else {
      candidates.push(...this.grants.values())
    }

    if (candidates.length === 0) {
      return { allowed: false, reason: 'no-active-grant', detail: `no grant covers ${tool.scope}` }
    }

    let sawExpired = false
    let sawRevoked = false

    for (const token of candidates) {
      if (this.revoked.has(token.id)) { sawRevoked = true; continue }
      if (this.now() >= token.expiresAt) { sawExpired = true; continue }
      if (!(await verifyCapabilityToken(token, this.opts.publicKey, { now: this.now() }))) {
        return { allowed: false, reason: 'grant-invalid-signature', detail: `grant ${token.id} failed signature verification` }
      }
      if (!tokenMatchesScope(token, tool.scope, method)) continue

      const limitCheck = checkLimit(tool, input, parseCaps(token))
      if (limitCheck) return limitCheck

      const replayCheck = await this.checkReplay(tool, input, token)
      if (replayCheck) return replayCheck

      if (tool.confirm) {
        const confirmed = this.opts.onConfirm ? await this.opts.onConfirm(tool, input) : false
        if (!confirmed) {
          return { allowed: false, reason: 'confirmation-denied', detail: `${tool.name} requires human confirmation` }
        }
      }

      return { allowed: true, grantId: token.id }
    }

    if (sawRevoked) return { allowed: false, reason: 'grant-revoked', detail: 'the grant covering this tool was revoked' }
    if (sawExpired) return { allowed: false, reason: 'grant-expired', detail: 'the grant covering this tool has expired' }
    return { allowed: false, reason: 'scope-not-covered', detail: `no active grant covers ${tool.scope} (${method})` }
  }

  private async verifyBearer(
    serialized: string,
    scope: string,
    method: 'READ' | 'WRITE',
  ): Promise<{ ok: true; token: CapabilityToken } | { ok: false; decision: GuardDecision }> {
    let chain: CapabilityToken[]
    try {
      chain = parseCapabilityChain(serialized)
    } catch {
      return { ok: false, decision: { allowed: false, reason: 'grant-invalid-signature', detail: 'grant chain is not parseable' } }
    }

    const registry = {
      getPublicKey: async (id: string): Promise<string | null> =>
        id === this.keyId ? this.opts.publicKey : (this.opts.peerKeys?.[id] ?? null),
    }

    const result = await verifyCapabilityChain(chain, registry, {
      requiredPathGlob: scope,
      requiredMethod: method,
      now: this.now(),
    })
    if (!result.ok) {
      const expired = result.reason.includes('expired')
      return {
        ok: false,
        decision: {
          allowed: false,
          reason: expired ? 'grant-expired' : 'grant-invalid-signature',
          detail: result.reason,
        },
      }
    }
    if (this.revoked.has(result.token.id)) {
      return { ok: false, decision: { allowed: false, reason: 'grant-revoked', detail: `grant ${result.token.id} was revoked` } }
    }
    return { ok: true, token: result.token }
  }

  private async checkReplay(
    tool: GuardedTool,
    input: Record<string, unknown>,
    token: CapabilityToken,
  ): Promise<GuardDecision | null> {
    const nonce = input[NONCE_FIELD]
    if (typeof nonce !== 'string' || nonce.length === 0) return null
    const key = `${token.id}:${tool.name}:${nonce}`
    const ttlMs = Math.max(0, token.expiresAt - this.now())
    const isReplay = await this.replay.check(key, ttlMs)
    return isReplay
      ? { allowed: false, reason: 'replayed-call', detail: `nonce ${nonce} already used for ${tool.name}` }
      : null
  }

  // -- grants ---------------------------------------------------------------

  /**
   * Issue a scoped, expiring grant. Held page-side by default: the token never
   * passes through the agent, so it cannot be exfiltrated by a prompt-injected
   * one. Serialize it only when deliberately delegating to another agent.
   */
  async grant(req: GrantRequest): Promise<CapabilityToken> {
    const scopes: CapabilityScope[] = req.scopes.map((pathGlob) => ({ pathGlob }))
    for (const [field, max] of Object.entries(req.caps ?? {})) {
      scopes.push({ pathGlob: `${CAPS_PREFIX}${field}/${max}` })
    }

    const token = await issueCapabilityToken({
      issuerPrivateKey: this.opts.privateKey,
      issuerId: this.opts.origin,
      subject: req.subject,
      scopes,
      ttlMs: req.ttlMs,
      maxDelegations: req.maxDelegations ?? 0,
      keyId: this.keyId,
    })

    this.grants.set(token.id, token)
    this.emit({ type: 'grant-issued', grant: token })
    return token
  }

  /**
   * Revoke a grant immediately. Takes effect on the very next call.
   *
   * The token is retained rather than dropped so a later call can be refused
   * with `grant-revoked` — telling the agent (and the receipt chain) that
   * authorization was withdrawn, which `no-active-grant` would not. `activeGrants()`
   * excludes it either way.
   */
  revoke(grantId: string): void {
    this.revoked.add(grantId)
    this.emit({ type: 'grant-revoked', grantId })
  }

  /** Grants that are currently issued, unexpired and unrevoked. */
  activeGrants(): CapabilityToken[] {
    const now = this.now()
    return [...this.grants.values()].filter((t) => !this.revoked.has(t.id) && now < t.expiresAt)
  }

  // -- manifest -------------------------------------------------------------

  registeredTools(): GuardedTool[] {
    return [...this.tools.values()]
  }

  /**
   * Invoke a registered tool through the guard directly.
   *
   * Runs the exact wrapper `document.modelContext` would call — same
   * authorization, same receipt — so it is useful for tests, and for exercising
   * a tool surface in a browser that has no WebMCP agent attached. It is not a
   * bypass: there is no path here that skips `decide`.
   */
  async invoke(name: string, input: Record<string, unknown> = {}): Promise<unknown> {
    const tool = this.wrapped.get(name)
    if (!tool) {
      const receipt = await this.receipts.append({
        tool: name,
        scope: 'unknown',
        method: 'WRITE',
        outcome: 'refused',
        reason: 'unknown-tool',
        detail: `no tool registered as ${name}`,
        grantId: null,
        inputHash: await sha256Hex('{}'),
      })
      this.emit({ type: 'call', receipt })
      return { ok: false, refused: true, reason: 'unknown-tool', detail: `no tool registered as ${name}`, receiptId: receipt.id }
    }
    return tool.execute(input)
  }

  /** Sign the current tool surface. Serve this at a well-known path for auditors. */
  async manifest(): Promise<SignedManifest> {
    const entries = await Promise.all(this.registeredTools().map(manifestEntry))
    return signManifest({
      origin: this.opts.origin,
      entries,
      privateKey: this.opts.privateKey,
      keyId: this.keyId,
      now: this.now(),
    })
  }
}

/** Remove reserved 7h3 fields so application handlers see only their own inputs. */
function stripReserved(input: Record<string, unknown>): Record<string, unknown> {
  const { [GRANT_FIELD]: _g, [NONCE_FIELD]: _n, ...rest } = input
  return rest
}

/** Enforce the tool's ceiling, tightened by any cap bound inside the grant. */
function checkLimit(
  tool: GuardedTool,
  input: Record<string, unknown>,
  caps: Record<string, number>,
): GuardDecision | null {
  if (!tool.limit) return null
  const raw = input[tool.limit.field]
  if (raw === undefined) return null

  const value = Number(raw)
  if (!Number.isFinite(value)) {
    return { allowed: false, reason: 'limit-exceeded', detail: `${tool.limit.field} is not a finite number` }
  }

  const ceiling = Math.min(tool.limit.max, caps[tool.limit.field] ?? Number.POSITIVE_INFINITY)
  return value > ceiling
    ? { allowed: false, reason: 'limit-exceeded', detail: `${tool.limit.field}=${value} exceeds the authorized ceiling of ${ceiling}` }
    : null
}

/** Resolve `document.modelContext` when present; undefined in tests and old browsers. */
function resolveModelContext(): ModelContextLike | undefined {
  const doc = (globalThis as { document?: { modelContext?: ModelContextLike } }).document
  return typeof doc?.modelContext?.registerTool === 'function' ? doc.modelContext : undefined
}

/** True when the current browser exposes the WebMCP imperative API. */
export function isWebMcpSupported(): boolean {
  return resolveModelContext() !== undefined
}

export function guard(opts: GuardOptions): ToolGuard {
  return new ToolGuard(opts)
}
