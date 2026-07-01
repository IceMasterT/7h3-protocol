import { type KeyRegistry } from './keyRegistry'
import { type RoutePolicy, matchPolicy, isAllowedSender } from './routePolicy'
import { SlidingWindowRateLimiter } from './rateLimiter'
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
  | { ok: false; status: 401 | 403 | 429; reason: string }

class Protocol7h3Gateway {
  private config: GatewayConfig
  private rateLimiter: SlidingWindowRateLimiter

  constructor(config: GatewayConfig) {
    this.config = config
    this.rateLimiter = new SlidingWindowRateLimiter()
  }

  async verify(req: GatewayRequest): Promise<GatewayVerifyOutcome> {
    const startMs = performance.now()
    const policy = matchPolicy(this.config.policies ?? [], req.path)

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
            const durationMs = performance.now() - startMs
            globalMetrics.verifications_total.increment({ result: 'ok', alg: 'ED25519', transport: 'http' })
            globalMetrics.verification_duration_ms.observe(durationMs)
            return { ok: true, sender: result.token.subject }
          }
          const durationMs = performance.now() - startMs
          globalMetrics.verifications_total.increment({ result: 'fail', alg: 'none', transport: 'http' })
          globalMetrics.verification_duration_ms.observe(durationMs)
          return { ok: false, status: 401, reason: result.ok ? 'capability-scope-mismatch' : (result as { ok: false; reason: string }).reason }
        } catch (e) {
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

    // Check allowedSenders
    if (policy && !isAllowedSender(policy, sender)) {
      const durationMs = performance.now() - startMs
      globalMetrics.verifications_total.increment({ result: 'fail', alg, transport: 'http' })
      globalMetrics.verification_duration_ms.observe(durationMs)
      globalMetrics.sender_denials_total.increment({ sender, path: req.path })
      return { ok: false, status: 403, reason: 'sender-denied' }
    }

    // Check rate limit
    if (policy?.rateLimit) {
      const rl = this.rateLimiter.consume(sender, policy.rateLimit)
      if (!rl.allowed) {
        const durationMs = performance.now() - startMs
        globalMetrics.verifications_total.increment({ result: 'fail', alg, transport: 'http' })
        globalMetrics.verification_duration_ms.observe(durationMs)
        globalMetrics.rate_limit_hits_total.increment({ sender, path: req.path })
        return { ok: false, status: 429, reason: 'rate-limited' }
      }
    }

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

    // Build upstream URL
    const upstreamUrl = this.config.upstream.replace(/\/$/, '') + req.path

    // Build forwarded headers, adding 7h3 metadata
    const forwardHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers)) {
      forwardHeaders[k] = Array.isArray(v) ? v[0] : v
    }
    if (outcome.sender) {
      forwardHeaders['x-7h3-sender'] = outcome.sender
    }
    forwardHeaders['x-7h3-verified'] = 'true'

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

export { Protocol7h3Gateway }
