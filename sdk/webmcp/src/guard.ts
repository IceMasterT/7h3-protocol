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

/**
 * Shortest time an accepted nonce is remembered, whatever TTL the caller passes.
 *
 * A nonce we let through must be remembered, or it is not replay protection at
 * all: with `ttlMs <= 0` the entry would expire the instant it was written, so
 * the very next identical call would read as fresh. `decide()` never passes a
 * non-positive TTL — the expiry check runs first — but this class is exported,
 * and a replay store that silently fails open is the wrong kind of surprise.
 */
export const MIN_REPLAY_RETENTION_MS = 60_000

/** Zero-dependency replay store. Adequate for a page session; swap for Redis/KV server-side. */
export class InMemoryReplayChecker implements ReplayChecker {
  private seen = new Map<string, number>()
  constructor(private readonly now: () => number = () => Date.now()) {}
  async check(key: string, ttlMs: number): Promise<boolean> {
    const now = this.now()
    for (const [k, expiry] of this.seen) if (expiry <= now) this.seen.delete(k)
    if (this.seen.has(key)) return true
    this.seen.set(key, now + Math.max(ttlMs, MIN_REPLAY_RETENTION_MS))
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

/**
 * Effective ceilings for a whole delegation chain: the minimum of every cap
 * bound anywhere along it.
 *
 * Delegation may only ever narrow authority. Reading caps from the leaf token
 * alone let a sub-agent re-delegate itself a larger ceiling than its parent
 * held — a privilege escalation whenever the root grant carried a broad enough
 * glob (`**`) for the containment check to accept the new `caps/` scope. Taking
 * the minimum makes a child's larger number a no-op, and a smaller one binding.
 */
export function effectiveCaps(chain: CapabilityToken[]): Record<string, number> {
  const caps: Record<string, number> = {}
  for (const token of chain) {
    for (const [field, max] of Object.entries(parseCaps(token))) {
      caps[field] = caps[field] === undefined ? max : Math.min(caps[field], max)
    }
  }
  return caps
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
    // `caps/` is reserved for ceilings bound inside grants. A tool sitting in
    // that namespace could be authorized by a ceiling declaration rather than a
    // real scope grant, so refuse it outright rather than resolve it silently.
    if (tool.scope?.startsWith(CAPS_PREFIX)) {
      throw new Error(`tool scope may not use the reserved '${CAPS_PREFIX}' namespace: ${tool.scope}`)
    }
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
   *
   * Grant selection is *permissive across grants*: a call is allowed if ANY
   * active grant authorizes it. A narrow grant that happens to be iterated
   * first must not veto a broader one that plainly covers the call, and one
   * corrupt grant must not disable the whole tool surface.
   *
   * Side effects run only after a grant has been found: human confirmation is
   * asked once, and the replay nonce is consumed last, so a call that is
   * ultimately refused never burns its nonce.
   */
  async decide(tool: GuardedTool, input: Record<string, unknown>): Promise<GuardDecision> {
    // A tool with no declared scope is published unguarded, by explicit choice.
    if (!tool.scope) return { allowed: true, grantId: null }

    const method = toolMethod(tool)
    const bearer = input[GRANT_FIELD]

    // Each candidate carries the chain it was verified as part of, so ceilings
    // can be intersected across the whole chain rather than read off the leaf.
    let candidates: { token: CapabilityToken; chain: CapabilityToken[] }[]
    // A bearer chain has already been verified end to end by verifyBearer,
    // including issuers other than this origin. Re-checking it against this
    // origin's key alone would reject every legitimately delegated chain.
    let preVerified = false

    if (typeof bearer === 'string' && bearer.length > 0) {
      const chainResult = await this.verifyBearer(bearer, tool.scope, method)
      if (!chainResult.ok) return chainResult.decision
      candidates = [{ token: chainResult.token, chain: chainResult.chain }]
      preVerified = true
    } else {
      candidates = [...this.grants.values()].map((token) => ({ token, chain: [token] }))
    }

    if (candidates.length === 0) {
      return { allowed: false, reason: 'no-active-grant', detail: `no grant covers ${tool.scope}` }
    }

    let bestLimitFailure: Extract<LimitOutcome, { ok: false }> | null = null
    let refusal: GuardDecision | null = null
    const note = (d: GuardDecision) => {
      if (!refusal || refusalRank(d) > refusalRank(refusal)) refusal = d
    }

    let authorizing: CapabilityToken | null = null

    for (const { token, chain } of candidates) {
      if (this.revoked.has(token.id)) {
        note({ allowed: false, reason: 'grant-revoked', detail: `grant ${token.id} was revoked` })
        continue
      }
      if (this.now() >= token.expiresAt) {
        note({ allowed: false, reason: 'grant-expired', detail: `grant ${token.id} has expired` })
        continue
      }
      if (!preVerified && !(await verifyCapabilityToken(token, this.opts.publicKey, { now: this.now() }))) {
        note({ allowed: false, reason: 'grant-invalid-signature', detail: `grant ${token.id} failed signature verification` })
        continue
      }
      if (!tokenMatchesScope(token, tool.scope, method)) continue

      const limit = evaluateLimit(tool, input, effectiveCaps(chain))
      if (!limit.ok) {
        // Keep the most permissive ceiling seen: if the caller holds a $50 and a
        // $1,000 grant, the constraint they are actually up against is $1,000.
        if (!bestLimitFailure || limit.ceiling > bestLimitFailure.ceiling) bestLimitFailure = limit
        continue
      }

      authorizing = token
      break
    }

    if (!authorizing) {
      if (bestLimitFailure) return limitRefusal(tool, bestLimitFailure)
      return (
        refusal ?? {
          allowed: false,
          reason: 'scope-not-covered',
          detail: `no active grant covers ${tool.scope} (${method})`,
        }
      )
    }

    if (tool.confirm) {
      const confirmed = this.opts.onConfirm ? await this.opts.onConfirm(tool, input) : false
      if (!confirmed) {
        return { allowed: false, reason: 'confirmation-denied', detail: `${tool.name} requires human confirmation` }
      }
    }

    // Consumed last: an authorized, confirmed call is the only kind that should
    // spend its nonce.
    const replayCheck = await this.checkReplay(tool, input, authorizing)
    if (replayCheck) return replayCheck

    return { allowed: true, grantId: authorizing.id }
  }

  private async verifyBearer(
    serialized: string,
    scope: string,
    method: 'READ' | 'WRITE',
  ): Promise<{ ok: true; token: CapabilityToken; chain: CapabilityToken[] } | { ok: false; decision: GuardDecision }> {
    let chain: CapabilityToken[]
    try {
      chain = parseCapabilityChain(serialized)
    } catch {
      return { ok: false, decision: { allowed: false, reason: 'grant-invalid-signature', detail: 'grant chain is not parseable' } }
    }

    // verifyCapabilityChain resolves keys by the token's *issuer*, not by keyId.
    // Accept both so a chain rooted at this origin verifies, and fall back to
    // configured peer keys for issuers other than us.
    const registry = {
      getPublicKey: async (id: string): Promise<string | null> => {
        if (id === this.opts.origin || id === this.keyId) return this.opts.publicKey
        return this.opts.peerKeys?.[id] ?? null
      },
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
    return { ok: true, token: result.token, chain: result.chain }
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

/**
 * Precedence for reporting refusals when several grants fail for different
 * reasons. The most specific and actionable reason wins: "you exceeded the
 * ceiling" tells an agent far more than "nothing covers this scope".
 */
function refusalRank(decision: GuardDecision): number {
  if (decision.allowed) return 0
  switch (decision.reason) {
    case 'limit-exceeded': return 4
    case 'grant-invalid-signature': return 3
    case 'grant-revoked':
    case 'grant-expired': return 2
    default: return 1
  }
}

/** Remove reserved 7h3 fields so application handlers see only their own inputs. */
function stripReserved(input: Record<string, unknown>): Record<string, unknown> {
  const { [GRANT_FIELD]: _g, [NONCE_FIELD]: _n, ...rest } = input
  return rest
}

export type LimitOutcome =
  | { ok: true }
  | { ok: false; reason: 'missing-field' | 'not-finite' | 'over-ceiling'; ceiling: number; value?: number }

/** Enforce the tool's ceiling, tightened by any cap bound inside the grant. */
function evaluateLimit(
  tool: GuardedTool,
  input: Record<string, unknown>,
  caps: Record<string, number>,
): LimitOutcome {
  if (!tool.limit) return { ok: true }

  const ceiling = Math.min(tool.limit.max, caps[tool.limit.field] ?? Number.POSITIVE_INFINITY)
  const raw = input[tool.limit.field]

  if (raw === undefined) {
    // Fail closed. The tool declared a ceiling on this field, so a call that
    // omits it cannot be shown to be within the ceiling — and schema `required`
    // is not a defense, since the guard must not trust the caller to honour it.
    return { ok: false, reason: 'missing-field', ceiling }
  }

  const value = Number(raw)
  if (!Number.isFinite(value)) return { ok: false, reason: 'not-finite', ceiling, value: NaN }

  return value > ceiling ? { ok: false, reason: 'over-ceiling', ceiling, value } : { ok: true }
}

/** Render a limit failure, naming the most permissive ceiling the caller holds. */
function limitRefusal(tool: GuardedTool, outcome: Extract<LimitOutcome, { ok: false }>): GuardDecision {
  const field = tool.limit!.field
  const detail =
    outcome.reason === 'missing-field'
      ? `${field} is required: this tool declares a ceiling on it`
      : outcome.reason === 'not-finite'
        ? `${field} is not a finite number`
        : `${field}=${outcome.value} exceeds the authorized ceiling of ${outcome.ceiling}`
  return { allowed: false, reason: 'limit-exceeded', detail }
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
