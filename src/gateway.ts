import { type KeyRegistry } from './keyRegistry'
import { type RoutePolicy, matchPolicy, isAllowedSender } from './routePolicy'
import { SlidingWindowRateLimiter, type RateLimitStore } from './rateLimiter'
import { verifyHttpEnvelope } from './httpBinding'
import { signResponse } from './signedResponse'
import { metrics as globalMetrics } from './telemetry'
import type { ReplayStore } from './replayStores'
import { CAP_HEADER, parseCapabilityChain, verifyCapabilityChain, tokenMatchesScope } from './capability'
import { APPROVAL_HEADER, parseApproval, verifyApproval, type ApproverKeyLookup } from './approval'
import { PROVENANCE_HEADER, effectiveTrust, parseProvenance, verifyProvenance, type TrustLevel } from './provenance'
import { bindAction } from './actionBinding'
import {
  DPOP_HEADER,
  DPOP_NONCE_HEADER,
  parseDpopAuthorization,
  verifyDpopProof,
  type DpopAlg,
  type DpopNonceIssuer,
} from './dpop'
import { verifyMessage, type HttpMessage, type SignatureParams, type VerificationKey } from './httpMessageSignatures'
import { MemoryReplayStore } from './replayStores'

export type { KeyRegistry, RoutePolicy }

export interface GatewayConfig {
  upstream: string
  keyRegistry: KeyRegistry
  policies?: RoutePolicy[]
  privateKey?: string
  sender?: string
  signResponses?: boolean // default true when privateKey set
  defaultPolicy?: 'allow' | 'deny' // default 'allow'
  headerName?: string
  metricsPath?: string
  /** Optional distributed replay store — prevents nonce reuse across gateway instances. */
  replayStore?: ReplayStore
  /**
   * Optional persistent rate-limit store — required for correct rate limiting
   * whenever the gateway is rebuilt per-request (e.g. inside a Workers/Lambda
   * fetch handler). Without it, rate limiting falls back to the in-memory
   * SlidingWindowRateLimiter, which only works if this Gateway instance
   * persists across the requests it's limiting.
   */
  rateLimitStore?: RateLimitStore
  /** Optional capability token registry for capability-based auth. */
  capabilityRegistry?: { getPublicKey(id: string): Promise<string | null> }
  /**
   * Public keys of approvers. Required when any policy sets `approval`. Kept
   * separate from `keyRegistry` on purpose: being a registered agent must never
   * imply being allowed to approve.
   */
  approverRegistry?: ApproverKeyLookup
  /**
   * Where consumed approval grants are recorded. Defaults to `replayStore`, then
   * to a per-instance in-memory store — which does not survive restarts or span
   * instances, so give a multi-instance gateway a shared one.
   */
  approvalReplayStore?: ReplayStore
  /** Required when any policy uses `require: 'http-signature'`. */
  httpSignature?: HttpSignatureGatewayConfig
  /** Required when any policy uses `require: 'dpop'`. */
  dpop?: DpopGatewayConfig
}

/** Configuration for routes with `require: 'dpop'` (RFC 9449). */
export interface DpopGatewayConfig {
  /**
   * Resolve an access token to the identity it was issued to and the key it is bound
   * to (`cnf.jkt`). Return `null` for an unknown, expired or unbound token: a token
   * with no key binding must not be accepted on a DPoP route.
   */
  resolveToken: (token: string) => Promise<{ sender: string; jkt: string } | null> | { sender: string; jkt: string } | null
  /** Issue and require server nonces. Recommended: bounds how long a pre-minted proof stays usable. */
  nonce?: { issuer: DpopNonceIssuer; required?: boolean }
  /** Maximum proof age in ms (default 60 s). */
  maxAgeMs?: number
  allowedAlgs?: readonly DpopAlg[]
  /** Scheme the client used to reach this gateway (default `https`). */
  scheme?: 'http' | 'https'
  /** Take the authority from `x-forwarded-host` instead of `host`. Only behind a proxy you control. */
  trustForwardedHost?: boolean
  /** Single-use `jti` store. Defaults to `replayStore`, then in-memory. */
  replayStore?: ReplayStore
}

/** Configuration for routes with `require: 'http-signature'` (RFC 9421, e.g. Web Bot Auth). */
export interface HttpSignatureGatewayConfig {
  /**
   * Map a signature's `keyid` to verification material AND the identity it stands
   * for. The identity becomes the request's authenticated sender, so it is what
   * `allowedSenders`, rate limits and approvals key on. Return `null` to refuse.
   */
  resolveKey: (
    keyId: string | undefined,
    params: SignatureParams,
  ) => Promise<{ key: VerificationKey; sender: string } | null> | { key: VerificationKey; sender: string } | null
  /** Only signatures carrying this `tag` are considered (recommended; e.g. `web-bot-auth`). */
  tag?: string
  /** Components every signature must cover. Default `@method`, `@authority`, `@path` (plus `@query` when the request has a query string). */
  requiredComponents?: string[]
  /** Maximum signature age in ms (default 5 minutes). */
  maxAgeMs?: number
  /** Refuse signatures that carry no `expires`. */
  requireExpires?: boolean
  /**
   * Require `content-digest` to be covered (and to match) whenever a request has a
   * body. Default true: a signature that ignores the body authenticates the
   * envelope of a request, not what it does.
   */
  requireBodyBinding?: boolean
  /** Scheme the client used to reach this gateway (default `https`). */
  scheme?: 'http' | 'https'
  /** Take the authority from `x-forwarded-host` instead of `host`. Only behind a proxy you control. */
  trustForwardedHost?: boolean
  /** Single-use nonce store. Defaults to `replayStore`, then in-memory. */
  nonceStore?: ReplayStore
  label?: string
}

export interface GatewayRequest {
  method: string
  path: string
  headers: Record<string, string | string[]>
  body?: string
  url?: string
}

export interface GatewayResponse {
  status: number
  headers: Record<string, string>
  body: string
}

export type GatewayVerifyOutcome =
  | { ok: true; sender: string; envelopeId?: string; approvedBy?: string; trust?: TrustLevel }
  | { ok: false; status: 400 | 401 | 403 | 429; reason: string; detail?: Record<string, unknown>; headers?: Record<string, string> }

/** Case-insensitive single-value header lookup (Node lower-cases; other runtimes may not). */
function getHeader(headers: Record<string, string | string[]>, name: string): string | undefined {
  const lower = name.toLowerCase()
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return Array.isArray(v) ? v[0] : v
  }
  return undefined
}

/**
 * Headers the gateway alone may set. Anything a client sends under these names is
 * dropped before forwarding: an upstream that trusts `x-7h3-verified` or
 * `x-7h3-approved-by` must never be able to be told so by the caller.
 */
const GATEWAY_OWNED_HEADERS = new Set([
  'x-7h3-sender',
  'x-7h3-verified',
  'x-7h3-approved-by',
  'x-7h3-trust',
  APPROVAL_HEADER, // single-use secret between approver and gateway; upstream has no need of it
  DPOP_HEADER, // single-use proof; the upstream authenticates the gateway, not the client's key
])

/**
 * Normalize a request path before it's used for both policy matching and
 * upstream forwarding. Without this, a path like `/public/../admin/secret`
 * matches a permissive `/public/**` policy (or no policy at all, under
 * `defaultPolicy: 'allow'`) as a literal string, is forwarded unverified,
 * and then gets collapsed by the URL parser inside `fetch()` on the way out
 * — landing on `/admin/secret` at the upstream with zero verification ever
 * having been performed against the path that's actually reached. Matching
 * and forwarding must both operate on the same fully-normalized path so
 * there's no gap between what was checked and what was sent.
 *
 * Returns null for anything that isn't a clean absolute path — including a
 * `..` that would escape above the root, or percent-encoding that doesn't
 * settle after a bounded number of decode passes (double-encoding is a
 * classic way to smuggle a traversal past a single decode).
 */
export function normalizeGatewayPath(rawPath: string): string | null {
  if (!rawPath.startsWith('/')) return null

  let decoded = rawPath
  for (let i = 0; i < 5; i++) {
    let next: string
    try {
      next = decodeURIComponent(decoded)
    } catch {
      return null
    }
    if (next === decoded) break
    decoded = next
  }
  if (/%[0-9a-fA-F]{2}/.test(decoded)) return null // still encoded after 5 passes
  // eslint-disable-next-line no-control-regex -- intentional: reject control chars / null bytes
  if (/[\x00-\x1f]/.test(decoded)) return null

  const segments = decoded.split('/')
  const normalized: string[] = []
  for (const seg of segments) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      if (normalized.length === 0) return null // escapes above root
      normalized.pop()
      continue
    }
    normalized.push(seg)
  }
  return '/' + normalized.join('/')
}

class Protocol7h3Gateway {
  private config: GatewayConfig
  private rateLimiter: SlidingWindowRateLimiter
  private approvalStore: ReplayStore
  private httpSigNonceStore: ReplayStore
  private dpopStore: ReplayStore

  constructor(config: GatewayConfig) {
    this.config = config
    this.rateLimiter = new SlidingWindowRateLimiter()
    this.approvalStore = config.approvalReplayStore ?? config.replayStore ?? new MemoryReplayStore()
    this.httpSigNonceStore = config.httpSignature?.nonceStore ?? config.replayStore ?? new MemoryReplayStore()

    this.dpopStore = config.dpop?.replayStore ?? config.replayStore ?? new MemoryReplayStore()
    if ((config.policies ?? []).some((p) => p.require === 'dpop') && !config.dpop) {
      throw new Error("createGateway(): a policy uses require:'dpop' but no dpop config is provided")
    }
    if ((config.policies ?? []).some((p) => p.require === 'http-signature') && !config.httpSignature) {
      throw new Error("createGateway(): a policy uses require:'http-signature' but no httpSignature config is provided")
    }

    // An approval policy that cannot be enforced must fail at construction, not
    // quietly allow the route through (or deny it forever) at request time.
    for (const p of config.policies ?? []) {
      if (!p.approval) continue
      if (p.require === 'none') {
        throw new Error(`createGateway(): policy '${p.path}' sets approval but require:'none' authenticates nobody to approve for`)
      }
      if (!config.approverRegistry) {
        throw new Error(`createGateway(): policy '${p.path}' sets approval but no approverRegistry is configured`)
      }
      if (!Array.isArray(p.approval.approvers) || p.approval.approvers.length === 0) {
        throw new Error(`createGateway(): policy '${p.path}' approval.approvers must be a non-empty list`)
      }
      if (p.approval.require !== 'always' && p.approval.require !== 'untrusted') {
        throw new Error(`createGateway(): policy '${p.path}' approval.require must be 'always' or 'untrusted'`)
      }
    }

    // A gateway with at least one signature-requiring policy but no shared
    // replayStore verifies signatures/TTL but never dedupes nonce reuse, and
    // silently loses that protection entirely once more than one instance is
    // running (e.g. a Workers isolate rebuilding the gateway per request).
    // Warn once at construction rather than fail, since a single-instance
    // in-memory-only deployment (e.g. local dev) is a legitimate use case.
    if (
      !config.replayStore &&
      (config.policies ?? []).some((p) => p.require !== 'none')
    ) {
      console.warn(
        '[7h3-protocol] createGateway(): no replayStore configured with signature-requiring policies. ' +
          'Nonce/replay protection will not survive multiple gateway instances or restarts. ' +
          'See docs/GATEWAY.md#production-safety.',
      )
    }
  }

  // Shared by both auth paths (signature and capability-token) so neither one
  // can bypass allowedSenders/rate-limit enforcement — the capability path
  // used to return ok:true immediately on a valid chain, silently skipping
  // both checks below for any policy that specified them.
  private async checkSenderAndRateLimit(
    policy: RoutePolicy | null,
    sender: string,
    alg: string,
    req: GatewayRequest,
    startMs: number,
  ): Promise<GatewayVerifyOutcome | null> {
    if (policy && !isAllowedSender(policy, sender)) {
      const durationMs = performance.now() - startMs
      globalMetrics.verifications_total.increment({ result: 'fail', alg, transport: 'http' })
      globalMetrics.verification_duration_ms.observe(durationMs)
      globalMetrics.sender_denials_total.increment({ sender, path: req.path })
      return { ok: false, status: 403, reason: 'sender-denied' }
    }

    if (policy?.rateLimit) {
      const rl = this.config.rateLimitStore
        ? await this.config.rateLimitStore.consume(sender, policy.rateLimit)
        : this.rateLimiter.consume(sender, policy.rateLimit)
      if (!rl.allowed) {
        const durationMs = performance.now() - startMs
        globalMetrics.verifications_total.increment({ result: 'fail', alg, transport: 'http' })
        globalMetrics.verification_duration_ms.observe(durationMs)
        globalMetrics.rate_limit_hits_total.increment({ sender, path: req.path })
        return { ok: false, status: 429, reason: 'rate-limited' }
      }
    }

    return null
  }

  /**
   * Step-up approval gate. Runs only after the caller is authenticated, so
   * `sender` is a verified identity, and only for policies that opt in.
   * Returns a denial, or the approval facts to forward on success (`null` when
   * the policy does not apply / no approval was needed).
   */
  private async enforceApproval(
    policy: RoutePolicy | null,
    sender: string,
    req: GatewayRequest,
    normalizedPath: string,
    alg: string,
    startMs: number,
  ): Promise<{ denied: GatewayVerifyOutcome } | { approvedBy?: string; trust?: TrustLevel }> {
    const rule = policy?.approval
    if (!rule) return {}

    const deny = (reason: string, detail?: Record<string, unknown>): { denied: GatewayVerifyOutcome } => {
      globalMetrics.verifications_total.increment({ result: 'fail', alg, transport: 'http' })
      globalMetrics.verification_duration_ms.observe(performance.now() - startMs)
      globalMetrics.sender_denials_total.increment({ sender, path: req.path })
      return { denied: { ok: false, status: 403, reason, ...(detail ? { detail } : {}) } }
    }

    const action = await bindAction({ method: req.method, path: normalizedPath, body: req.body })

    let trust: TrustLevel = 'untrusted'
    if (rule.require === 'untrusted') {
      const rawProv = getHeader(req.headers, PROVENANCE_HEADER)
      const provenance = await verifyProvenance(parseProvenance(rawProv), {
        keyRegistry: this.config.keyRegistry,
        sender,
        action,
      })
      trust = effectiveTrust(provenance)
      // Trusted inputs: no human needed.
      if (trust === 'trusted') return { trust }
    }

    const grant = parseApproval(getHeader(req.headers, APPROVAL_HEADER))
    if (grant === null) {
      return deny('approval-required', { action, approvers: rule.approvers, trust })
    }
    const result = await verifyApproval(grant, {
      approverKeys: this.config.approverRegistry!,
      allowedApprovers: rule.approvers,
      subject: sender,
      action,
      replayStore: this.approvalStore,
    })
    if (!result.ok) {
      return deny(`approval-invalid:${result.reason}`, { action, approvers: rule.approvers, trust })
    }
    return { approvedBy: result.grant.approver, trust }
  }

  /**
   * RFC 9421 authentication for `require: 'http-signature'` routes. The signed
   * target URI is rebuilt from the Host header and the path exactly as received,
   * so the verifier and the signer derive the same signature base.
   */
  private async verifyHttpSignature(
    policy: RoutePolicy,
    req: GatewayRequest,
    normalizedPath: string,
    startMs: number,
  ): Promise<GatewayVerifyOutcome> {
    const cfg = this.config.httpSignature!
    const fail = (reason: string): GatewayVerifyOutcome => {
      globalMetrics.verifications_total.increment({ result: 'fail', alg: 'none', transport: 'http' })
      globalMetrics.verification_duration_ms.observe(performance.now() - startMs)
      return { ok: false, status: 401, reason: `http-signature:${reason}` }
    }

    const authority = getHeader(req.headers, cfg.trustForwardedHost ? 'x-forwarded-host' : 'host')
    if (!authority) return fail('missing-host')
    const message: HttpMessage = { method: req.method, url: `${cfg.scheme ?? 'https'}://${authority}${req.path}`, headers: req.headers }

    let resolved: { key: VerificationKey; sender: string } | null = null
    let result
    try {
      result = await verifyMessage(message, {
        label: cfg.label,
        tag: cfg.tag,
        // The query string is user-controlled input too: when there is one, it must be signed.
        requiredComponents: cfg.requiredComponents ?? ['@method', '@authority', '@path', ...(req.path.includes('?') ? ['@query'] : [])],
        maxAgeMs: cfg.maxAgeMs,
        requireExpires: cfg.requireExpires,
        body: req.body,
        requireBodyBinding: cfg.requireBodyBinding ?? true,
        nonceStore: this.httpSigNonceStore,
        resolveKey: async (keyId, params) => {
          resolved = await cfg.resolveKey(keyId, params)
          return resolved?.key ?? null
        },
      })
    } catch {
      // A derived component the message cannot satisfy, an invalid URL, etc. Never a 500.
      return fail('unverifiable')
    }
    if (!result.ok) return fail(result.reason)
    const { key, sender } = resolved as unknown as { key: VerificationKey; sender: string }
    const alg = key.alg === 'ed25519' ? 'ED25519' : 'HS256'

    const denied = await this.checkSenderAndRateLimit(policy, sender, alg, req, startMs)
    if (denied) return denied
    const gate = await this.enforceApproval(policy, sender, req, normalizedPath, alg, startMs)
    if ('denied' in gate) return gate.denied

    globalMetrics.verifications_total.increment({ result: 'ok', alg, transport: 'http' })
    globalMetrics.verification_duration_ms.observe(performance.now() - startMs)
    return { ok: true, sender, ...gate }
  }

  /**
   * RFC 9449 authentication for `require: 'dpop'` routes: `Authorization: DPoP <token>`
   * plus one `DPoP` proof. The token identifies the caller and names the key it is
   * bound to; the proof shows the caller holds that key, for this method and URL.
   */
  private async verifyDpop(policy: RoutePolicy, req: GatewayRequest, normalizedPath: string, startMs: number): Promise<GatewayVerifyOutcome> {
    const cfg = this.config.dpop!
    const fail = async (reason: string, extra: { challengeNonce?: boolean } = {}): Promise<GatewayVerifyOutcome> => {
      globalMetrics.verifications_total.increment({ result: 'fail', alg: 'none', transport: 'http' })
      globalMetrics.verification_duration_ms.observe(performance.now() - startMs)
      const headers: Record<string, string> = { 'www-authenticate': `DPoP error="${extra.challengeNonce ? 'use_dpop_nonce' : 'invalid_dpop_proof'}"` }
      if (extra.challengeNonce && cfg.nonce) headers[DPOP_NONCE_HEADER] = await cfg.nonce.issuer.issue()
      return { ok: false, status: 401, reason: `dpop:${reason}`, headers }
    }

    const token = parseDpopAuthorization(getHeader(req.headers, 'authorization'))
    if (token === null) return fail('missing-token')

    const bound = await cfg.resolveToken(token)
    if (!bound || !bound.jkt) return fail('invalid-token')

    const authority = getHeader(req.headers, cfg.trustForwardedHost ? 'x-forwarded-host' : 'host')
    if (!authority) return fail('missing-host')
    const pathOnly = req.path.split(/[?#]/, 1)[0]

    const proofs: string[] = []
    for (const [k, v] of Object.entries(req.headers)) {
      if (k.toLowerCase() === DPOP_HEADER && v !== undefined) proofs.push(...(Array.isArray(v) ? v : [v]))
    }

    let result
    try {
      result = await verifyDpopProof(proofs, {
        method: req.method,
        url: `${cfg.scheme ?? 'https'}://${authority}${pathOnly}`,
        accessToken: token,
        expectedJkt: bound.jkt,
        allowedAlgs: cfg.allowedAlgs,
        maxAgeMs: cfg.maxAgeMs,
        replayStore: this.dpopStore,
        nonce: cfg.nonce ? { required: cfg.nonce.required ?? true, validate: (n) => cfg.nonce!.issuer.validate(n) } : undefined,
      })
    } catch {
      return fail('unverifiable')
    }
    if (!result.ok) return fail(result.reason, { challengeNonce: result.reason === 'nonce-required' || result.reason === 'nonce-mismatch' })

    const alg = result.jwk.kty === 'EC' ? 'ES256' : 'ED25519'
    const denied = await this.checkSenderAndRateLimit(policy, bound.sender, alg, req, startMs)
    if (denied) return denied
    const gate = await this.enforceApproval(policy, bound.sender, req, normalizedPath, alg, startMs)
    if ('denied' in gate) return gate.denied

    globalMetrics.verifications_total.increment({ result: 'ok', alg, transport: 'http' })
    globalMetrics.verification_duration_ms.observe(performance.now() - startMs)
    return { ok: true, sender: bound.sender, ...gate }
  }

  async verify(req: GatewayRequest): Promise<GatewayVerifyOutcome> {
    const startMs = performance.now()
    const normalizedPath = normalizeGatewayPath(req.path)
    if (normalizedPath === null) {
      return { ok: false, status: 400, reason: 'invalid-path' }
    }
    const policy = matchPolicy(this.config.policies ?? [], normalizedPath)

    // Determine if we skip verification
    const skipVerify =
      policy?.require === 'none' ||
      (!policy && (this.config.defaultPolicy ?? 'allow') === 'allow')

    if (skipVerify) {
      const durationMs = performance.now() - startMs
      globalMetrics.verifications_total.increment({ result: 'ok', alg: 'none', transport: 'http' })
      globalMetrics.verification_duration_ms.observe(durationMs)
      return { ok: true, sender: '' }
    }

    // Capability token path — alternative auth via x-7h3-capability header
    if (this.config.capabilityRegistry) {
      const rawCap = req.headers[CAP_HEADER]
      const capHeader = Array.isArray(rawCap) ? rawCap[0] : rawCap
      if (capHeader) {
        try {
          const chain = parseCapabilityChain(capHeader)
          const result = await verifyCapabilityChain(chain, this.config.capabilityRegistry, {
            requiredPathGlob: req.path,
            requiredMethod: req.method,
          })
          if (result.ok && tokenMatchesScope(result.token, req.path, req.method)) {
            const capSender = result.token.subject
            const denied = await this.checkSenderAndRateLimit(policy, capSender, 'ED25519', req, startMs)
            if (denied) return denied
            const gate = await this.enforceApproval(policy, capSender, req, normalizedPath, 'ED25519', startMs)
            if ('denied' in gate) return gate.denied
            const durationMs = performance.now() - startMs
            globalMetrics.verifications_total.increment({ result: 'ok', alg: 'ED25519', transport: 'http' })
            globalMetrics.verification_duration_ms.observe(durationMs)
            return { ok: true, sender: capSender, ...gate }
          }
          const durationMs = performance.now() - startMs
          globalMetrics.verifications_total.increment({ result: 'fail', alg: 'none', transport: 'http' })
          globalMetrics.verification_duration_ms.observe(durationMs)
          return { ok: false, status: 401, reason: result.ok ? 'capability-scope-mismatch' : (result as { ok: false; reason: string }).reason }
        } catch {
          const durationMs = performance.now() - startMs
          globalMetrics.verifications_total.increment({ result: 'fail', alg: 'none', transport: 'http' })
          globalMetrics.verification_duration_ms.observe(durationMs)
          return { ok: false, status: 401, reason: 'invalid-capability-chain' }
        }
      }
    }

    if (policy?.require === 'dpop') {
      return this.verifyDpop(policy, req, normalizedPath, startMs)
    }

    // RFC 9421 routes authenticate with the HTTP signature only
    if (policy?.require === 'http-signature') {
      return this.verifyHttpSignature(policy, req, normalizedPath, startMs)
    }

    // deny if no policy and defaultPolicy is 'deny'
    if (!policy && (this.config.defaultPolicy ?? 'allow') === 'deny') {
      const durationMs = performance.now() - startMs
      globalMetrics.verifications_total.increment({ result: 'fail', alg: 'none', transport: 'http' })
      globalMetrics.verification_duration_ms.observe(durationMs)
      globalMetrics.sender_denials_total.increment({ sender: '', path: req.path })
      return { ok: false, status: 403, reason: 'no-matching-policy' }
    }

    // Verify the envelope
    const result = await verifyHttpEnvelope(req.headers, {
      keyRegistry: this.config.keyRegistry,
      headerName: this.config.headerName,
    })

    if (!result.ok) {
      const durationMs = performance.now() - startMs
      globalMetrics.verifications_total.increment({ result: 'fail', alg: 'none', transport: 'http' })
      globalMetrics.verification_duration_ms.observe(durationMs)
      return { ok: false, status: 401, reason: result.reason }
    }

    const envelope = result.envelope
    const sender = envelope.header.sender
    const envelopeId = envelope.header.messageId
    const alg = (envelope.signature?.alg as string | undefined) ?? 'none'

    // Check replay store — prevents nonce reuse across multiple gateway instances
    if (this.config.replayStore) {
      const replayed = await this.config.replayStore.check(
        envelope.header.nonce,
        envelope.header.ttlMs,
      )
      if (replayed) {
        return { ok: false, status: 401, reason: 'replay-detected' }
      }
    }

    // Enforce algorithm requirement when policy specifies a specific alg
    if (policy && policy.require !== 'any') {
      const actualAlg = envelope.signature?.alg
      const requiresEd25519 = policy.require === 'ed25519' && actualAlg !== 'ED25519'
      const requiresHmac = policy.require === 'hmac' && actualAlg !== 'HS256'
      if (requiresEd25519 || requiresHmac) {
        const durationMs = performance.now() - startMs
        globalMetrics.verifications_total.increment({ result: 'fail', alg, transport: 'http' })
        globalMetrics.verification_duration_ms.observe(durationMs)
        return { ok: false, status: 401, reason: 'invalid-signature' }
      }
    }

    // Check allowedSenders + rate limit (shared with the capability-token path)
    const denied = await this.checkSenderAndRateLimit(policy, sender, alg, req, startMs)
    if (denied) return denied

    const gate = await this.enforceApproval(policy, sender, req, normalizedPath, alg, startMs)
    if ('denied' in gate) return gate.denied

    const durationMs = performance.now() - startMs
    globalMetrics.verifications_total.increment({ result: 'ok', alg, transport: 'http' })
    globalMetrics.verification_duration_ms.observe(durationMs)
    return { ok: true, sender, envelopeId, ...gate }
  }

  async handle(req: GatewayRequest): Promise<GatewayResponse> {
    const outcome = await this.verify(req)

    if (!outcome.ok) {
      return {
        status: outcome.status,
        headers: { 'content-type': 'application/json', ...outcome.headers },
        body: JSON.stringify({ error: outcome.reason, ...(outcome.detail ? { detail: outcome.detail } : {}) }),
      }
    }

    // Build upstream URL from the same normalized path verify() matched
    // policies against — never the raw req.path. verify() already returned
    // ok:true, so normalization is guaranteed to succeed here too (it's a
    // pure function of req.path, which hasn't changed).
    const normalizedPath = normalizeGatewayPath(req.path)!
    const upstreamUrl = this.config.upstream.replace(/\/$/, '') + normalizedPath

    // Build forwarded headers, adding 7h3 metadata
    const forwardHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers)) {
      // Drop anything a client sent under a gateway-owned name (case-insensitively);
      // the gateway re-adds only what it actually established below.
      if (GATEWAY_OWNED_HEADERS.has(k.toLowerCase())) continue
      forwardHeaders[k] = Array.isArray(v) ? v[0] : v
    }
    // outcome.sender is only ever non-empty when a signature or capability
    // token was actually checked (the skip-verify path returns sender: '').
    // Setting x-7h3-verified: true unconditionally would tell the upstream
    // "this request was cryptographically verified" even when it was simply
    // allowed through unverified — actively misleading any upstream that
    // trusts the header as proof of verification.
    if (outcome.sender) {
      forwardHeaders['x-7h3-sender'] = outcome.sender
      forwardHeaders['x-7h3-verified'] = 'true'
    }
    if (outcome.approvedBy) forwardHeaders['x-7h3-approved-by'] = outcome.approvedBy
    if (outcome.trust) forwardHeaders['x-7h3-trust'] = outcome.trust

    // Fetch upstream
    const fetchResponse = await fetch(upstreamUrl, {
      method: req.method,
      headers: forwardHeaders,
      body: req.body,
    })

    const responseBody = await fetchResponse.text()
    const responseHeaders: Record<string, string> = {
      'content-type': fetchResponse.headers.get('content-type') ?? 'application/json',
    }

    // Sign response if configured
    const shouldSign =
      this.config.privateKey !== undefined &&
      (this.config.signResponses ?? true) &&
      this.config.sender !== undefined

    if (shouldSign) {
      const signed = await signResponse(responseBody, {
        privateKey: this.config.privateKey!,
        sender: this.config.sender!,
        recipient: outcome.sender || undefined,
      })
      Object.assign(responseHeaders, signed.headers)
    }

    return {
      status: fetchResponse.status,
      headers: responseHeaders,
      body: responseBody,
    }
  }

  getRateLimiter(): SlidingWindowRateLimiter {
    return this.rateLimiter
  }
}

export function createGateway(config: GatewayConfig): Protocol7h3Gateway {
  return new Protocol7h3Gateway(config)
}

/**
 * Hardened preset for production deployments: fails fast (rather than
 * silently falling back to permissive defaults) if `defaultPolicy` isn't
 * explicitly `'deny'` or `replayStore` isn't configured. Use this instead of
 * `createGateway()` wherever a misconfiguration should be a deploy-time error,
 * not a runtime security gap discovered later.
 */
export function createProductionGateway(config: GatewayConfig): Protocol7h3Gateway {
  if (config.defaultPolicy !== 'deny') {
    throw new Error(
      "createProductionGateway(): defaultPolicy must be explicitly 'deny'. " +
        "Unmatched routes must never be forwarded unverified in production.",
    )
  }
  if (!config.replayStore) {
    throw new Error(
      'createProductionGateway(): replayStore is required. ' +
        'Use a shared store (Redis/KV/Durable Object) so nonce replay protection ' +
        'survives multiple instances and restarts.',
    )
  }
  return new Protocol7h3Gateway(config)
}

export { Protocol7h3Gateway }
