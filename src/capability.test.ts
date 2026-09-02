import { describe, it, expect } from 'vitest'
import { matchGlob } from './routePolicy'
import {
  generateEd25519KeypairBase64Url,
  issueCapabilityToken,
  verifyCapabilityToken,
  delegateCapabilityToken,
  verifyCapabilityChain,
  tokenMatchesScope,
  serializeCapabilityChain,
  parseCapabilityChain,
  canonicalizeCapabilityToken,
  type CapabilityToken,
  type CapabilityScope,
} from './capability'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeKeypair() {
  return generateEd25519KeypairBase64Url()
}

function makeKeyRegistry(map: Record<string, string>): { getPublicKey(id: string): Promise<string | null> } {
  return {
    async getPublicKey(id: string) {
      return map[id] ?? null
    },
  }
}

const paymentScopes: CapabilityScope[] = [
  { pathGlob: '/api/payments/**', methods: ['POST', 'PUT'] },
]

const readonlyPaymentScopes: CapabilityScope[] = [
  { pathGlob: '/api/payments/**', methods: ['POST'] },
]

// ---------------------------------------------------------------------------
// Test 1: issueCapabilityToken creates token with correct fields
// ---------------------------------------------------------------------------
describe('issueCapabilityToken', () => {
  it('creates token with correct fields', async () => {
    const root = await makeKeypair()
    const now = Date.now()

    const token = await issueCapabilityToken({
      issuerPrivateKey: root.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
      maxDelegations: 2,
    })

    expect(token.version).toBe('7h3-cap/1')
    expect(token.issuer).toBe('agent-root')
    expect(token.subject).toBe('agent-b')
    expect(token.scopes).toEqual(paymentScopes)
    expect(token.delegationDepth).toBe(0)
    expect(token.maxDelegations).toBe(2)
    expect(token.parentTokenId).toBeUndefined()
    expect(token.issuedAt).toBeGreaterThanOrEqual(now)
    expect(token.expiresAt).toBeGreaterThan(token.issuedAt)
    expect(typeof token.id).toBe('string')
    expect(typeof token.signature).toBe('string')
    expect(typeof token.keyId).toBe('string')
  })

  it('defaults maxDelegations to 0 when not specified', async () => {
    const root = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: root.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
    })
    expect(token.maxDelegations).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Test 2: verifyCapabilityToken succeeds with correct key
// ---------------------------------------------------------------------------
describe('verifyCapabilityToken', () => {
  it('succeeds with correct key', async () => {
    const root = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: root.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
    })

    const valid = await verifyCapabilityToken(token, root.publicKey)
    expect(valid).toBe(true)
  })

  // Test 3: verifyCapabilityToken fails with wrong key
  it('fails with wrong key', async () => {
    const root = await makeKeypair()
    const other = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: root.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
    })

    const valid = await verifyCapabilityToken(token, other.publicKey)
    expect(valid).toBe(false)
  })

  // Test 4: verifyCapabilityToken fails on expired token
  it('fails on expired token', async () => {
    const root = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: root.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 1, // 1ms — will be expired by the time we check
    })

    // Use a future "now" to simulate expiry
    const futureNow = token.expiresAt + 1
    const valid = await verifyCapabilityToken(token, root.publicKey, { now: futureNow })
    expect(valid).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Test 5: delegateCapabilityToken creates valid delegation
// ---------------------------------------------------------------------------
describe('delegateCapabilityToken', () => {
  it('creates valid delegation', async () => {
    const rootKeys = await makeKeypair()
    const agentBKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
      maxDelegations: 2,
    })

    const delegated = await delegateCapabilityToken({
      parentToken: rootToken,
      delegatorPrivateKey: agentBKeys.privateKey,
      delegatorId: 'agent-b',
      newSubject: 'agent-c',
      scopes: readonlyPaymentScopes,
      ttlMs: 30_000,
    })

    expect(delegated.issuer).toBe('agent-b')
    expect(delegated.subject).toBe('agent-c')
    expect(delegated.delegationDepth).toBe(1)
    expect(delegated.parentTokenId).toBe(rootToken.id)
    expect(delegated.scopes).toEqual(readonlyPaymentScopes)
    // maxDelegations should be decremented
    expect(delegated.maxDelegations).toBe(1)

    const valid = await verifyCapabilityToken(delegated, agentBKeys.publicKey)
    expect(valid).toBe(true)
  })

  // Test 6: delegateCapabilityToken fails when maxDelegations=0
  it('fails when maxDelegations=0', async () => {
    const rootKeys = await makeKeypair()
    const agentBKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
      maxDelegations: 0, // no further delegation
    })

    await expect(
      delegateCapabilityToken({
        parentToken: rootToken,
        delegatorPrivateKey: agentBKeys.privateKey,
        delegatorId: 'agent-b',
        newSubject: 'agent-c',
        scopes: readonlyPaymentScopes,
        ttlMs: 30_000,
      }),
    ).rejects.toThrow(/maxDelegations/)
  })

  // Test 7: delegateCapabilityToken fails when new scopes exceed parent scopes
  it('fails when new scopes exceed parent scopes', async () => {
    const rootKeys = await makeKeypair()
    const agentBKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: [{ pathGlob: '/api/payments/**', methods: ['POST'] }],
      ttlMs: 60_000,
      maxDelegations: 2,
    })

    // Try to delegate with a method (DELETE) not in parent
    await expect(
      delegateCapabilityToken({
        parentToken: rootToken,
        delegatorPrivateKey: agentBKeys.privateKey,
        delegatorId: 'agent-b',
        newSubject: 'agent-c',
        scopes: [{ pathGlob: '/api/payments/**', methods: ['POST', 'DELETE'] }],
        ttlMs: 30_000,
      }),
    ).rejects.toThrow(/exceed|subset/i)
  })

  // matchGlob('/admin/*', '/admin/**') is true (it matches '**' as two literal
  // asterisk characters against the regex [^/]* — a coincidence of the regex
  // translation, not real glob containment), so a naive subset check that
  // just calls matchGlob(parent, child) on the pattern *strings* wrongly
  // treats a recursive '**' child as narrower than a single-segment '*'
  // parent. It's the opposite: '**' can match arbitrarily deep paths a
  // single '*' never would, so it must be rejected as broader, not narrower.
  it('fails when delegated pathGlob uses ** under a parent restricted to a single *', async () => {
    const rootKeys = await makeKeypair()
    const agentBKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: [{ pathGlob: '/api/admin/*' }],
      ttlMs: 60_000,
      maxDelegations: 2,
    })

    await expect(
      delegateCapabilityToken({
        parentToken: rootToken,
        delegatorPrivateKey: agentBKeys.privateKey,
        delegatorId: 'agent-b',
        newSubject: 'agent-c',
        scopes: [{ pathGlob: '/api/admin/**' }],
        ttlMs: 30_000,
      }),
    ).rejects.toThrow(/exceed|subset/i)
  })

  it('allows delegated pathGlob to narrow from ** to a more specific prefix', async () => {
    const rootKeys = await makeKeypair()
    const agentBKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: [{ pathGlob: '/api/**' }],
      ttlMs: 60_000,
      maxDelegations: 2,
    })

    const delegated = await delegateCapabilityToken({
      parentToken: rootToken,
      delegatorPrivateKey: agentBKeys.privateKey,
      delegatorId: 'agent-b',
      newSubject: 'agent-c',
      scopes: [{ pathGlob: '/api/payments/**' }],
      ttlMs: 30_000,
    })
    expect(delegated.scopes).toEqual([{ pathGlob: '/api/payments/**' }])
  })

  it('fails when delegatorId does not match parentToken.subject', async () => {
    const rootKeys = await makeKeypair()
    const wrongKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
      maxDelegations: 2,
    })

    await expect(
      delegateCapabilityToken({
        parentToken: rootToken,
        delegatorPrivateKey: wrongKeys.privateKey,
        delegatorId: 'agent-wrong', // not agent-b
        newSubject: 'agent-c',
        ttlMs: 30_000,
      }),
    ).rejects.toThrow(/does not match/)
  })
})

// ---------------------------------------------------------------------------
// Test 8: verifyCapabilityChain: 2-link chain (root→delegate) verifies
// ---------------------------------------------------------------------------
describe('verifyCapabilityChain', () => {
  it('2-link chain (root→delegate) verifies', async () => {
    const rootKeys = await makeKeypair()
    const agentBKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
      maxDelegations: 2,
    })

    const delegated = await delegateCapabilityToken({
      parentToken: rootToken,
      delegatorPrivateKey: agentBKeys.privateKey,
      delegatorId: 'agent-b',
      newSubject: 'agent-c',
      scopes: readonlyPaymentScopes,
      ttlMs: 30_000,
    })

    const registry = makeKeyRegistry({
      'agent-root': rootKeys.publicKey,
      'agent-b': agentBKeys.publicKey,
    })

    const result = await verifyCapabilityChain([rootToken, delegated], registry)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.token.subject).toBe('agent-c')
      expect(result.chain).toHaveLength(2)
    }
  })

  // Test 9: verifyCapabilityChain: tampered chain fails
  it('tampered chain fails', async () => {
    const rootKeys = await makeKeypair()
    const agentBKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
      maxDelegations: 2,
    })

    const delegated = await delegateCapabilityToken({
      parentToken: rootToken,
      delegatorPrivateKey: agentBKeys.privateKey,
      delegatorId: 'agent-b',
      newSubject: 'agent-c',
      scopes: readonlyPaymentScopes,
      ttlMs: 30_000,
    })

    // Tamper with the delegated token's subject
    const tampered: CapabilityToken = { ...delegated, subject: 'agent-evil' }

    const registry = makeKeyRegistry({
      'agent-root': rootKeys.publicKey,
      'agent-b': agentBKeys.publicKey,
    })

    const result = await verifyCapabilityChain([rootToken, tampered], registry)
    expect(result.ok).toBe(false)
  })

  it('rejects when issuer key not in registry', async () => {
    const rootKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
    })

    // Empty registry — no key for agent-root
    const registry = makeKeyRegistry({})
    const result = await verifyCapabilityChain([rootToken], registry)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/no-public-key/)
    }
  })

  it('rejects when required scope not covered', async () => {
    const rootKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: [{ pathGlob: '/api/payments/**' }],
      ttlMs: 60_000,
    })

    const registry = makeKeyRegistry({ 'agent-root': rootKeys.publicKey })
    const result = await verifyCapabilityChain([rootToken], registry, {
      requiredPathGlob: '/api/admin/delete',
    })
    expect(result.ok).toBe(false)
  })

  it('rejects expired token in chain', async () => {
    const rootKeys = await makeKeypair()

    const rootToken = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
    })

    const registry = makeKeyRegistry({ 'agent-root': rootKeys.publicKey })

    // Check with a future now that makes the token expired
    const result = await verifyCapabilityChain([rootToken], registry, {
      now: rootToken.expiresAt + 1,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/expired/)
    }
  })

  // A subject always controls their own signing key, so they can hand-sign
  // a next hop directly instead of calling delegateCapabilityToken() — that
  // function's own checks (scope/TTL/maxDelegations narrowing) are then
  // just advice they can ignore. verifyCapabilityChain must independently
  // enforce narrowing per hop, or a self-issued "delegation" can escalate
  // scope, extend TTL past the parent, or delegate past maxDelegations=0.
  describe('rejects forged escalation even with a structurally valid, correctly-signed chain', () => {
    it('rejects a child token with broader scope than its parent', async () => {
      const rootKeys = await makeKeypair()
      const agentBKeys = await makeKeypair()

      const rootToken = await issueCapabilityToken({
        issuerPrivateKey: rootKeys.privateKey,
        issuerId: 'agent-root',
        subject: 'agent-b',
        scopes: [{ pathGlob: '/api/payments/**', methods: ['POST'] }],
        ttlMs: 60_000,
        maxDelegations: 5,
      })

      // Hand-crafted, not via delegateCapabilityToken: scope escalated to /api/**
      const forgedUnsigned = {
        id: 'cap-forged-1',
        version: '7h3-cap/1' as const,
        issuer: 'agent-b',
        subject: 'agent-mallory',
        scopes: [{ pathGlob: '/api/**' }],
        issuedAt: Date.now(),
        expiresAt: rootToken.expiresAt,
        delegationDepth: rootToken.delegationDepth + 1,
        parentTokenId: rootToken.id,
        maxDelegations: undefined,
        keyId: 'agent-b-key',
      }
      const payload = canonicalizeCapabilityToken(forgedUnsigned)
      const { signCanonicalPayloadEd25519 } = await import('./protocol')
      const signature = await signCanonicalPayloadEd25519(payload, agentBKeys.privateKey)
      const forged: CapabilityToken = { ...forgedUnsigned, signature }

      const registry = makeKeyRegistry({
        'agent-root': rootKeys.publicKey,
        'agent-b': agentBKeys.publicKey,
      })

      const result = await verifyCapabilityChain([rootToken, forged], registry)
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.reason).toMatch(/scopes exceed/)
    })

    it('rejects a child token whose TTL extends past its parent', async () => {
      const rootKeys = await makeKeypair()
      const agentBKeys = await makeKeypair()

      const rootToken = await issueCapabilityToken({
        issuerPrivateKey: rootKeys.privateKey,
        issuerId: 'agent-root',
        subject: 'agent-b',
        scopes: paymentScopes,
        ttlMs: 60_000,
        maxDelegations: 1,
      })

      const forgedUnsigned = {
        id: 'cap-forged-2',
        version: '7h3-cap/1' as const,
        issuer: 'agent-b',
        subject: 'agent-mallory',
        scopes: paymentScopes,
        issuedAt: Date.now(),
        expiresAt: rootToken.expiresAt + 3_600_000, // 1 hour past parent expiry
        delegationDepth: rootToken.delegationDepth + 1,
        parentTokenId: rootToken.id,
        maxDelegations: undefined,
        keyId: 'agent-b-key',
      }
      const payload = canonicalizeCapabilityToken(forgedUnsigned)
      const { signCanonicalPayloadEd25519 } = await import('./protocol')
      const signature = await signCanonicalPayloadEd25519(payload, agentBKeys.privateKey)
      const forged: CapabilityToken = { ...forgedUnsigned, signature }

      const registry = makeKeyRegistry({
        'agent-root': rootKeys.publicKey,
        'agent-b': agentBKeys.publicKey,
      })

      const result = await verifyCapabilityChain([rootToken, forged], registry)
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.reason).toMatch(/expiresAt exceeds/)
    })

    it('rejects any further delegation once a token has maxDelegations=0', async () => {
      const rootKeys = await makeKeypair()
      const agentBKeys = await makeKeypair()

      const rootToken = await issueCapabilityToken({
        issuerPrivateKey: rootKeys.privateKey,
        issuerId: 'agent-root',
        subject: 'agent-b',
        scopes: paymentScopes,
        ttlMs: 60_000,
        maxDelegations: 0,
      })

      const forgedUnsigned = {
        id: 'cap-forged-3',
        version: '7h3-cap/1' as const,
        issuer: 'agent-b',
        subject: 'agent-mallory',
        scopes: paymentScopes,
        issuedAt: Date.now(),
        expiresAt: rootToken.expiresAt,
        delegationDepth: rootToken.delegationDepth + 1,
        parentTokenId: rootToken.id,
        maxDelegations: undefined,
        keyId: 'agent-b-key',
      }
      const payload = canonicalizeCapabilityToken(forgedUnsigned)
      const { signCanonicalPayloadEd25519 } = await import('./protocol')
      const signature = await signCanonicalPayloadEd25519(payload, agentBKeys.privateKey)
      const forged: CapabilityToken = { ...forgedUnsigned, signature }

      const registry = makeKeyRegistry({
        'agent-root': rootKeys.publicKey,
        'agent-b': agentBKeys.publicKey,
      })

      const result = await verifyCapabilityChain([rootToken, forged], registry)
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.reason).toMatch(/does not permit further delegation/)
    })
  })
})

// ---------------------------------------------------------------------------
// Test 10: tokenMatchesScope: glob matching works
// ---------------------------------------------------------------------------
describe('tokenMatchesScope', () => {
  it('matches exact glob pattern', async () => {
    const rootKeys = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: [{ pathGlob: '/api/payments/**', methods: ['POST', 'PUT'] }],
      ttlMs: 60_000,
    })

    expect(tokenMatchesScope(token, '/api/payments/create', 'POST')).toBe(true)
    expect(tokenMatchesScope(token, '/api/payments/update/123', 'PUT')).toBe(true)
  })

  it('rejects method not in scope', async () => {
    const rootKeys = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: [{ pathGlob: '/api/payments/**', methods: ['POST'] }],
      ttlMs: 60_000,
    })

    expect(tokenMatchesScope(token, '/api/payments/create', 'DELETE')).toBe(false)
  })

  it('matches any method when methods is undefined', async () => {
    const rootKeys = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: [{ pathGlob: '/api/**' }], // no methods restriction
      ttlMs: 60_000,
    })

    expect(tokenMatchesScope(token, '/api/anything', 'DELETE')).toBe(true)
    expect(tokenMatchesScope(token, '/api/payments/create', 'GET')).toBe(true)
  })

  it('rejects path not matching glob', async () => {
    const rootKeys = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: [{ pathGlob: '/api/payments/**' }],
      ttlMs: 60_000,
    })

    expect(tokenMatchesScope(token, '/api/admin/delete', 'POST')).toBe(false)
  })

  it('handles single-segment wildcard', async () => {
    const rootKeys = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: [{ pathGlob: '/api/*/status' }],
      ttlMs: 60_000,
    })

    expect(tokenMatchesScope(token, '/api/payments/status', 'GET')).toBe(true)
    // Multi-segment should NOT match single *
    expect(tokenMatchesScope(token, '/api/a/b/status', 'GET')).toBe(false)
  })

  it('fails closed when scope restricts methods but no method is given to check', async () => {
    const rootKeys = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: [{ pathGlob: '/api/payments/**', methods: ['POST'] }],
      ttlMs: 60_000,
    })

    // "can't confirm the method is allowed" must not be treated as "allowed"
    expect(tokenMatchesScope(token, '/api/payments/create', undefined)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Serialization round-trip
// ---------------------------------------------------------------------------
describe('serializeCapabilityChain / parseCapabilityChain', () => {
  it('round-trips a chain', async () => {
    const rootKeys = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
    })

    const serialized = serializeCapabilityChain([token])
    const parsed = parseCapabilityChain(serialized)

    expect(parsed).toHaveLength(1)
    expect(parsed[0].id).toBe(token.id)
    expect(parsed[0].signature).toBe(token.signature)
  })
})

// ---------------------------------------------------------------------------
// Canonicalization determinism
// ---------------------------------------------------------------------------
describe('canonicalizeCapabilityToken', () => {
  it('produces the same string for equivalent tokens', async () => {
    const rootKeys = await makeKeypair()
    const token = await issueCapabilityToken({
      issuerPrivateKey: rootKeys.privateKey,
      issuerId: 'agent-root',
      subject: 'agent-b',
      scopes: paymentScopes,
      ttlMs: 60_000,
    })

    const { signature, ...unsigned } = token
    const c1 = canonicalizeCapabilityToken(unsigned)
    const c2 = canonicalizeCapabilityToken(unsigned)
    expect(c1).toBe(c2)
  })
})

describe('delegation scope containment — soundness', () => {
  async function tryDelegate(childGlob: string, parentGlob: string): Promise<boolean> {
    const keys = await generateEd25519KeypairBase64Url()
    const root = await issueCapabilityToken({
      issuerPrivateKey: keys.privateKey,
      issuerId: 'origin',
      subject: 'agent-a',
      scopes: [{ pathGlob: parentGlob }],
      ttlMs: 60_000,
      maxDelegations: 2,
      keyId: 'k1',
    })
    try {
      await delegateCapabilityToken({
        parentToken: root,
        delegatorPrivateKey: keys.privateKey,
        delegatorId: 'agent-a',
        newSubject: 'agent-b',
        scopes: [{ pathGlob: childGlob }],
        ttlMs: 30_000,
      })
      return true
    } catch {
      return false
    }
  }

  it('refuses a child that ends where the parent requires a further segment', async () => {
    // `a/**` matches `a/x` but never bare `a`, so a child of `a` reaches a path
    // the parent cannot — it is not a subset, however much it looks like one.
    expect(matchGlob('a/**', 'a')).toBe(false)
    expect(matchGlob('a', 'a')).toBe(true)
    expect(await tryDelegate('a', 'a/**')).toBe(false)
    expect(await tryDelegate('money', 'money/**')).toBe(false)
  })

  it('still allows genuinely narrower children under a recursive parent', async () => {
    expect(await tryDelegate('a/*', 'a/**')).toBe(true)
    expect(await tryDelegate('a/b/c', 'a/**')).toBe(true)
    expect(await tryDelegate('a/', 'a/**')).toBe(true)
    expect(await tryDelegate('a', '**')).toBe(true)
    expect(await tryDelegate('a/**', '**')).toBe(true)
  })

  it('keeps refusing children broader than their parent', async () => {
    expect(await tryDelegate('**', '*')).toBe(false)
    expect(await tryDelegate('a/**', 'a/*')).toBe(false)
  })
})
