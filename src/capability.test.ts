import { describe, it, expect } from 'vitest'
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
