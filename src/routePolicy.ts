export type PolicyRequirement = 'ed25519' | 'hmac' | 'any' | 'none'

export interface RoutePolicy {
  path: string
  require: PolicyRequirement
  rateLimit?: { requests: number; windowMs: number }
  allowedSenders?: string[]
  signResponse?: boolean
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
