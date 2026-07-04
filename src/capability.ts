import {
  generateEd25519KeypairBase64Url,
  randomHex,
  signCanonicalPayloadEd25519,
  verifyCanonicalPayloadEd25519,
} from './protocol'
import { matchGlob } from './routePolicy'

// Re-export for test convenience
export { generateEd25519KeypairBase64Url }

export interface CapabilityScope {
  pathGlob: string
  methods?: string[]
  maxDelegations?: number
}

export interface CapabilityToken {
  id: string
  version: '7h3-cap/1'
  issuer: string
  subject: string
  scopes: CapabilityScope[]
  issuedAt: number
  expiresAt: number
  delegationDepth: number
  parentTokenId?: string
  /** How many more times this token can be re-delegated. undefined = unlimited, 0 = no further delegation. */
  maxDelegations: number | undefined
  signature: string
  keyId: string
}

export type CapabilityVerifyResult =
  | { ok: true; token: CapabilityToken; chain: CapabilityToken[] }
  | { ok: false; reason: string }

export const CAP_HEADER = 'x-7h3-capability'

// ---------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------

function canonicalizeScope(scope: CapabilityScope): string {
  const parts: string[] = []
  if (scope.maxDelegations !== undefined) {
    parts.push(`"maxDelegations":${scope.maxDelegations}`)
  }
  if (scope.methods !== undefined) {
    parts.push(`"methods":${JSON.stringify(scope.methods)}`)
  }
  parts.push(`"pathGlob":${JSON.stringify(scope.pathGlob)}`)
  return `{${parts.join(',')}}`
}

/**
 * Deterministic canonical form for signing: alphabetically sorted top-level fields,
 * each scope also sorted. The `signature` field is excluded.
 */
export function canonicalizeCapabilityToken(token: Omit<CapabilityToken, 'signature'>): string {
  const parts: string[] = []

  parts.push(`"delegationDepth":${token.delegationDepth}`)
  parts.push(`"expiresAt":${token.expiresAt}`)
  parts.push(`"id":${JSON.stringify(token.id)}`)
  parts.push(`"issuedAt":${token.issuedAt}`)
  parts.push(`"issuer":${JSON.stringify(token.issuer)}`)
  parts.push(`"keyId":${JSON.stringify(token.keyId)}`)

  if (token.maxDelegations !== undefined) {
    parts.push(`"maxDelegations":${token.maxDelegations}`)
  }

  if (token.parentTokenId !== undefined) {
    parts.push(`"parentTokenId":${JSON.stringify(token.parentTokenId)}`)
  }

  const scopesStr = `[${token.scopes.map(canonicalizeScope).join(',')}]`
  parts.push(`"scopes":${scopesStr}`)

  parts.push(`"subject":${JSON.stringify(token.subject)}`)
  parts.push(`"version":${JSON.stringify(token.version)}`)

  return `{${parts.join(',')}}`
}

// ---------------------------------------------------------------------------
// Issue
// ---------------------------------------------------------------------------

export async function issueCapabilityToken(opts: {
  issuerPrivateKey: string
  issuerId: string
  subject: string
  scopes: CapabilityScope[]
  ttlMs: number
  maxDelegations?: number
  keyId?: string
}): Promise<CapabilityToken> {
  const now = Date.now()
  const id = `cap-${now}-${randomHex(6)}`
  const keyId = opts.keyId ?? `${opts.issuerId}-key`
  const maxDelegations = opts.maxDelegations ?? 0

  const unsigned: Omit<CapabilityToken, 'signature'> = {
    id,
    version: '7h3-cap/1',
    issuer: opts.issuerId,
    subject: opts.subject,
    scopes: opts.scopes,
    issuedAt: now,
    expiresAt: now + opts.ttlMs,
    delegationDepth: 0,
    maxDelegations,
    keyId,
  }

  const payload = canonicalizeCapabilityToken(unsigned)
  const signature = await signCanonicalPayloadEd25519(payload, opts.issuerPrivateKey)

  return { ...unsigned, signature }
}

// ---------------------------------------------------------------------------
// Delegate
// ---------------------------------------------------------------------------

/**
 * Check whether childScope is a subset of parentScope.
 * - pathGlob: the parent must matchGlob the child's pathGlob literal (or the child's glob must be
 *   at least as restrictive). We check that every path that matches child also matches parent by
 *   testing the child pathGlob against the parent pathGlob pattern.
 * - methods: parent undefined = any (child is allowed anything); child undefined = any =
 *   broader than a defined parent → reject.
 */
function scopeIsSubset(child: CapabilityScope, parent: CapabilityScope): boolean {
  // Path: child path must be covered by parent path pattern
  if (!matchGlob(parent.pathGlob, child.pathGlob)) {
    // Also try: child glob should be at most as broad as parent
    // For glob subset we check that child's pathGlob matches under the parent glob pattern
    // This covers the common case of /api/payments/** under /api/**
    // We fall back: if parent.pathGlob doesn't match child.pathGlob directly,
    // test by checking child is a "narrower" glob — just use matchGlob both ways
    return false
  }

  // Methods: parent undefined = allows all; child must not exceed parent
  if (parent.methods !== undefined) {
    if (child.methods === undefined) {
      // child wants all methods, parent is restricted — not a subset
      return false
    }
    // Every child method must be in parent methods
    for (const m of child.methods) {
      if (!parent.methods.includes(m)) {
        return false
      }
    }
  }
  // parent.methods === undefined → parent allows all; child can be anything

  return true
}

function scopesAreSubset(childScopes: CapabilityScope[], parentScopes: CapabilityScope[]): boolean {
  // Every child scope must be covered by at least one parent scope
  for (const child of childScopes) {
    const covered = parentScopes.some((parent) => scopeIsSubset(child, parent))
    if (!covered) return false
  }
  return true
}

export async function delegateCapabilityToken(opts: {
  parentToken: CapabilityToken
  delegatorPrivateKey: string
  delegatorId: string
  newSubject: string
  scopes?: CapabilityScope[]
  ttlMs: number
  keyId?: string
}): Promise<CapabilityToken> {
  const { parentToken, delegatorId, newSubject } = opts

  // Validate delegator is parent token's subject
  if (delegatorId !== parentToken.subject) {
    throw new Error(`delegatorId '${delegatorId}' does not match parentToken.subject '${parentToken.subject}'`)
  }

  // Validate parent not expired
  const now = Date.now()
  if (now >= parentToken.expiresAt) {
    throw new Error('Parent token is expired')
  }

  // Validate delegation is still allowed
  if (parentToken.maxDelegations !== undefined && parentToken.maxDelegations <= 0) {
    throw new Error('Parent token does not allow further delegation (maxDelegations=0)')
  }

  // Determine new scopes
  const newScopes = opts.scopes ?? parentToken.scopes

  // Validate new scopes are a subset of parent scopes
  if (!scopesAreSubset(newScopes, parentToken.scopes)) {
    throw new Error('Delegated scopes exceed parent token scopes')
  }

  // Validate TTL does not exceed parent remaining TTL
  const parentRemainingMs = parentToken.expiresAt - now
  if (opts.ttlMs > parentRemainingMs) {
    throw new Error(
      `Delegated ttlMs (${opts.ttlMs}) exceeds parent token remaining TTL (${parentRemainingMs})`,
    )
  }

  const id = `cap-${now}-${randomHex(6)}`
  const keyId = opts.keyId ?? `${delegatorId}-key`

  // Compute new maxDelegations: decrement from parent (undefined = unlimited stays unlimited)
  const newMaxDelegations =
    parentToken.maxDelegations === undefined ? undefined : parentToken.maxDelegations - 1

  const unsigned: Omit<CapabilityToken, 'signature'> = {
    id,
    version: '7h3-cap/1',
    issuer: delegatorId,
    subject: newSubject,
    scopes: newScopes,
    issuedAt: now,
    expiresAt: now + opts.ttlMs,
    delegationDepth: parentToken.delegationDepth + 1,
    parentTokenId: parentToken.id,
    maxDelegations: newMaxDelegations,
    keyId,
  }

  const payload = canonicalizeCapabilityToken(unsigned)
  const signature = await signCanonicalPayloadEd25519(payload, opts.delegatorPrivateKey)

  return { ...unsigned, signature }
}

// ---------------------------------------------------------------------------
// Verify single token
// ---------------------------------------------------------------------------

export async function verifyCapabilityToken(
  token: CapabilityToken,
  publicKey: string,
  opts?: { now?: number },
): Promise<boolean> {
  const now = opts?.now ?? Date.now()

  // Check expiry
  if (now >= token.expiresAt) {
    return false
  }

  // Reconstruct unsigned form
  const { signature, ...unsigned } = token

  const payload = canonicalizeCapabilityToken(unsigned)
  return verifyCanonicalPayloadEd25519(payload, signature, publicKey)
}

// ---------------------------------------------------------------------------
// Verify chain
// ---------------------------------------------------------------------------

export async function verifyCapabilityChain(
  chain: CapabilityToken[],
  keyRegistry: { getPublicKey(id: string): Promise<string | null> },
  opts?: { requiredPathGlob?: string; requiredMethod?: string; now?: number },
): Promise<CapabilityVerifyResult> {
  if (chain.length === 0) {
    return { ok: false, reason: 'empty-chain' }
  }

  const now = opts?.now ?? Date.now()

  // Verify each token in the chain
  for (let i = 0; i < chain.length; i++) {
    const token = chain[i]

    // Structural check: root must have depth 0
    if (i === 0 && token.delegationDepth !== 0) {
      return { ok: false, reason: 'root-token-delegation-depth-must-be-zero' }
    }

    // Chain linkage: issuer of token[i] must be subject of token[i-1]
    if (i > 0) {
      const prev = chain[i - 1]
      if (token.issuer !== prev.subject) {
        return {
          ok: false,
          reason: `chain-broken: token[${i}].issuer '${token.issuer}' !== token[${i - 1}].subject '${prev.subject}'`,
        }
      }
      if (token.parentTokenId !== prev.id) {
        return {
          ok: false,
          reason: `chain-broken: token[${i}].parentTokenId '${token.parentTokenId}' !== token[${i - 1}].id '${prev.id}'`,
        }
      }
      if (token.delegationDepth !== prev.delegationDepth + 1) {
        return {
          ok: false,
          reason: `chain-broken: token[${i}].delegationDepth ${token.delegationDepth} !== ${prev.delegationDepth + 1}`,
        }
      }
    }

    // Expiry check
    if (now >= token.expiresAt) {
      return { ok: false, reason: `token[${i}]-expired` }
    }

    // Get public key for issuer
    const issuerPub = await keyRegistry.getPublicKey(token.issuer)
    if (!issuerPub) {
      return { ok: false, reason: `no-public-key-for-issuer:${token.issuer}` }
    }

    // Verify signature
    const { signature, ...unsigned } = token
    const payload = canonicalizeCapabilityToken(unsigned)
    const valid = await verifyCanonicalPayloadEd25519(payload, signature, issuerPub)
    if (!valid) {
      return { ok: false, reason: `invalid-signature-at-index:${i}` }
    }
  }

  const leaf = chain[chain.length - 1]

  // Check required scope
  if (opts?.requiredPathGlob !== undefined) {
    if (!tokenMatchesScope(leaf, opts.requiredPathGlob, opts.requiredMethod)) {
      return { ok: false, reason: 'leaf-token-does-not-cover-required-scope' }
    }
  }

  return { ok: true, token: leaf, chain }
}

// ---------------------------------------------------------------------------
// Scope matching
// ---------------------------------------------------------------------------

export function tokenMatchesScope(token: CapabilityToken, pathGlob: string, method?: string): boolean {
  for (const scope of token.scopes) {
    // Check path: the scope's pathGlob must match the requested path
    if (!matchGlob(scope.pathGlob, pathGlob)) {
      continue
    }

    // Check method: if scope has no methods restriction, any method is allowed
    if (scope.methods === undefined) {
      return true
    }
    if (method === undefined) {
      return true
    }
    if (scope.methods.includes(method.toUpperCase())) {
      return true
    }
  }
  return false
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

export function serializeCapabilityChain(chain: CapabilityToken[]): string {
  return JSON.stringify(chain)
}

export function parseCapabilityChain(serialized: string): CapabilityToken[] {
  return JSON.parse(serialized) as CapabilityToken[]
}
