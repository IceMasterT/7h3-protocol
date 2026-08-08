import { type KeyRegistry } from './keyRegistry'
import { type RoutePolicy, matchPolicy, isAllowedSender } from './routePolicy'
import { SlidingWindowRateLimiter, type RateLimitStore } from './rateLimiter'
import { verifyHttpEnvelope } from './httpBinding'
import { signResponse } from './signedResponse'
import { metrics as globalMetrics } from './telemetry'
import type { ReplayStore } from './replayStores'
import { CAP_HEADER, parseCapabilityChain, verifyCapabilityChain, tokenMatchesScope } from './capability'

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
  | { ok: true; sender: string; envelopeId?: string }
  | { ok: false; status: 400 | 401 | 403 | 429; reason: string }

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

  constructor(config: GatewayConfig) {
    this.config = config
    this.rateLimiter = new SlidingWindowRateLimiter()

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
            const durationMs = performance.now() - startMs
            globalMetrics.verifications_total.increment({ result: 'ok', alg: 'ED25519', transport: 'http' })
            globalMetrics.verification_duration_ms.observe(durationMs)
            return { ok: true, sender: capSender }
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

    const durationMs = performance.now() - startMs
    globalMetrics.verifications_total.increment({ result: 'ok', alg, transport: 'http' })
    globalMetrics.verification_duration_ms.observe(durationMs)
    return { ok: true, sender, envelopeId }
  }

  async handle(req: GatewayRequest): Promise<GatewayResponse> {
    const outcome = await this.verify(req)

    if (!outcome.ok) {
      return {
        status: outcome.status,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ error: outcome.reason }),
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
