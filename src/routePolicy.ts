/**
 * How a route authenticates its caller.
 *   - `'ed25519'` / `'hmac'` / `'any'`: a signed 7h3 envelope (or capability token).
 *   - `'http-signature'`: an RFC 9421 HTTP Message Signature (e.g. Web Bot Auth);
 *     needs `GatewayConfig.httpSignature`.
 *   - `'dpop'`: an OAuth access token bound to a client key with a DPoP proof
 *     (RFC 9449); needs `GatewayConfig.dpop`.
 *   - `'none'`: no authentication.
 */
export type PolicyRequirement = 'ed25519' | 'hmac' | 'any' | 'http-signature' | 'dpop' | 'none'

/**
 * Step-up approval requirement for a route.
 *
 *   - `'always'`    every request needs a valid approval grant.
 *   - `'untrusted'` a grant is needed only when the request's provenance claim is
 *                   missing, invalid, or labels its inputs untrusted. A request
 *                   whose signed claim says everything came from trusted sources
 *                   passes without a human in the loop.
 */
export interface ApprovalPolicy {
  require: 'always' | 'untrusted'
  /** Identities allowed to approve on this route. Must be non-empty. */
  approvers: string[]
}

export interface RoutePolicy {
  path: string
  require: PolicyRequirement
  rateLimit?: { requests: number; windowMs: number }
  allowedSenders?: string[]
  signResponse?: boolean
  approval?: ApprovalPolicy
}

/**
 * Translate a glob pattern to a RegExp.
 * Supported:
 *   - exact: '/health'
 *   - '?'  → any single non-slash char
 *   - '*'  → any chars within a single segment (no slash)
 *   - '**' → any chars at any depth (including slashes)
 */
export function matchGlob(pattern: string, path: string): boolean {
  // Build regex from pattern, handling ** before * to avoid double-expanding
  let regexStr = '^'
  let i = 0
  while (i < pattern.length) {
    const ch = pattern[i]
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        // Double star: matches anything including /
        regexStr += '.*'
        i += 2
      } else {
        // Single star: matches any non-slash sequence
        regexStr += '[^/]*'
        i += 1
      }
    } else if (ch === '?') {
      // Single char, not slash
      regexStr += '[^/]'
      i += 1
    } else {
      // Escape regex metacharacters in literal segments
      regexStr += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&')
      i += 1
    }
  }
  regexStr += '$'

  return new RegExp(regexStr).test(path)
}

/**
 * Find the first matching policy for a given path.
 * Returns null if no policy matches.
 */
export function matchPolicy(policies: RoutePolicy[], path: string): RoutePolicy | null {
  for (const policy of policies) {
    if (matchGlob(policy.path, path)) {
      return policy
    }
  }
  return null
}

/**
 * Check whether a sender is permitted by a policy.
 * If allowedSenders is not set, all senders are allowed.
 */
export function isAllowedSender(policy: RoutePolicy, sender: string): boolean {
  if (!policy.allowedSenders || policy.allowedSenders.length === 0) {
    return true
  }
  return policy.allowedSenders.includes(sender)
}
