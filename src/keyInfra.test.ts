import { describe, it, expect, beforeEach } from 'vitest'
import {
  parseWellKnownKeys,
  serveWellKnownKeys,
  KeyRotationManager,
  RevocationRegistry,
} from './keyInfra'
import type { WellKnownKeysDocument, RevocationList } from './keyInfra'
import { createStaticKeyRegistry } from './keyRegistry'

// ── 1. parseWellKnownKeys: valid document parses correctly ───────────────────

describe('parseWellKnownKeys', () => {
  it('parses a valid document correctly', () => {
    const doc: WellKnownKeysDocument = {
      version: '7h3/0.1',
      updated: 1_700_000_000_000,
      keys: [
        {
          id: 'agent@example.com',
          algorithm: 'Ed25519',
          publicKey: 'MCowBQYDK2VwAyEA',
          created: 1_699_000_000_000,
        },
      ],
    }
    const json = JSON.stringify(doc)
    const parsed = parseWellKnownKeys(json)
    expect(parsed.version).toBe('7h3/0.1')
    expect(parsed.updated).toBe(1_700_000_000_000)
    expect(parsed.keys).toHaveLength(1)
    expect(parsed.keys[0].id).toBe('agent@example.com')
    expect(parsed.keys[0].algorithm).toBe('Ed25519')
    expect(parsed.keys[0].publicKey).toBe('MCowBQYDK2VwAyEA')
    expect(parsed.keys[0].created).toBe(1_699_000_000_000)
  })

  // ── 2. parseWellKnownKeys: wrong version throws ────────────────────────────

  it('throws on unsupported version', () => {
    const doc = {
      version: '7h3/0.2',
      updated: Date.now(),
      keys: [],
    }
    expect(() => parseWellKnownKeys(JSON.stringify(doc))).toThrow('unsupported version: 7h3/0.2')
  })
})

// ── 3. serveWellKnownKeys: produces valid JSON ───────────────────────────────

describe('serveWellKnownKeys', () => {
  it('produces valid JSON that round-trips through parseWellKnownKeys', () => {
    const doc: WellKnownKeysDocument = {
      version: '7h3/0.1',
      updated: 1_700_000_000_000,
      keys: [],
    }
    const json = serveWellKnownKeys(doc)
    expect(() => JSON.parse(json)).not.toThrow()
    const parsed = parseWellKnownKeys(json)
    expect(parsed.version).toBe('7h3/0.1')
    expect(parsed.updated).toBe(doc.updated)
    expect(parsed.keys).toEqual([])
  })
})

// ── KeyRotationManager tests ─────────────────────────────────────────────────

describe('KeyRotationManager', () => {
  // ── 4. addKey + getCurrentKey returns newest ─────────────────────────────

  it('addKey + getCurrentKey returns the newest key', () => {
    const mgr = new KeyRotationManager({ maxAgeMs: 60_000 })
    const now = Date.now()

    const older = {
      id: 'key-old',
      publicKey: 'pub-old',
      privateKey: 'priv-old',
      createdAt: now - 10_000,
    }
    const newer = {
      id: 'key-new',
      publicKey: 'pub-new',
      privateKey: 'priv-new',
      createdAt: now - 1_000,
    }

    mgr.addKey(older)
    mgr.addKey(newer)

    const current = mgr.getCurrentKey()
    expect(current).not.toBeNull()
    expect(current!.id).toBe('key-new')
  })

  // A KeyRegistry.getPublicKey miss must mean "identity unknown," never "use
  // whatever key happens to be current" — otherwise one managed identity's
  // valid signature verifies while claiming to be an entirely different,
  // unrelated senderId that was never actually registered.
  it('toKeyRegistry().getPublicKey returns null for an unrecognized senderId instead of the current key', async () => {
    const mgr = new KeyRotationManager({ maxAgeMs: 60_000 })
    mgr.addKey({
      id: 'key-real',
      publicKey: 'pub-real',
      privateKey: 'priv-real',
      createdAt: Date.now(),
    })

    const result = await mgr.toKeyRegistry().getPublicKey('some-other-agent-id')
    expect(result).toBeNull()
  })

  it('toKeyRegistry().getPublicKey still resolves a real managed key id', async () => {
    const mgr = new KeyRotationManager({ maxAgeMs: 60_000 })
    mgr.addKey({
      id: 'key-real',
      publicKey: 'pub-real',
      privateKey: 'priv-real',
      createdAt: Date.now(),
    })

    const result = await mgr.toKeyRegistry().getPublicKey('key-real')
    expect(result).toBe('pub-real')
  })

  // ── 5. rotateIfNeeded generates new key when current is too old ──────────

  it('rotateIfNeeded generates a new key when current key is too old', async () => {
    const mgr = new KeyRotationManager({ maxAgeMs: 1_000, overlapMs: 100 })
    const now = Date.now()

    // Add a key that is older than maxAgeMs - overlapMs = 900ms
    const oldKey = {
      id: 'key-stale',
      publicKey: 'pub-stale',
      privateKey: 'priv-stale',
      createdAt: now - 1_000,  // exactly at maxAgeMs, past the rotate threshold
    }
    mgr.addKey(oldKey)

    const rotated = await mgr.rotateIfNeeded()
    expect(rotated).not.toBeNull()
    expect(rotated!.publicKey).toBeTruthy()
    expect(rotated!.privateKey).toBeTruthy()
    expect(rotated!.id).toMatch(/^key-/)
    expect(rotated!.createdAt).toBeGreaterThanOrEqual(now)
  })

  // ── 6. rotateIfNeeded returns null when key is still fresh ───────────────

  it('rotateIfNeeded returns null when the current key is still fresh', async () => {
    const mgr = new KeyRotationManager({ maxAgeMs: 60_000, overlapMs: 6_000 })
    const now = Date.now()

    // Key created just now — well within the maxAgeMs - overlapMs window
    const freshKey = {
      id: 'key-fresh',
      publicKey: 'pub-fresh',
      privateKey: 'priv-fresh',
      createdAt: now,
    }
    mgr.addKey(freshKey)

    const result = await mgr.rotateIfNeeded()
    expect(result).toBeNull()
  })

  // ── 7. getWellKnownDocument structure ───────────────────────────────────

  it('getWellKnownDocument returns correct structure', () => {
    const mgr = new KeyRotationManager({ maxAgeMs: 60_000 })
    const now = Date.now()

    mgr.addKey({
      id: 'key-abc',
      publicKey: 'pub-abc',
      privateKey: 'priv-abc',
      createdAt: now - 5_000,
    })

    const doc = mgr.getWellKnownDocument()

    expect(doc.version).toBe('7h3/0.1')
    expect(typeof doc.updated).toBe('number')
    expect(doc.keys).toHaveLength(1)
    expect(doc.keys[0].id).toBe('key-abc')
    expect(doc.keys[0].algorithm).toBe('Ed25519')
    expect(doc.keys[0].publicKey).toBe('pub-abc')
    expect(doc.keys[0].created).toBe(now - 5_000)
  })

  it('getWellKnownDocument marks expired keys as revoked', () => {
    const mgr = new KeyRotationManager({ maxAgeMs: 60_000 })
    const pastTime = Date.now() - 10_000

    mgr.addKey({
      id: 'key-expired',
      publicKey: 'pub-exp',
      privateKey: 'priv-exp',
      createdAt: Date.now() - 30_000,
      expiresAt: pastTime,  // already expired
    })

    const doc = mgr.getWellKnownDocument()
    expect(doc.keys[0].revoked).toBe(true)
    expect(doc.keys[0].revokedAt).toBe(pastTime)
  })
})

// ── RevocationRegistry tests ─────────────────────────────────────────────────

describe('RevocationRegistry', () => {
  let registry: RevocationRegistry

  beforeEach(() => {
    registry = new RevocationRegistry()
  })

  // ── 8. revoke + isRevoked ────────────────────────────────────────────────

  it('revoke + isRevoked: marks key as revoked', () => {
    expect(registry.isRevoked('key-001')).toBe(false)
    registry.revoke('key-001', 'compromised')
    expect(registry.isRevoked('key-001')).toBe(true)
  })

  it('isRevoked returns false for unknown key', () => {
    expect(registry.isRevoked('key-unknown')).toBe(false)
  })

  // ── 9. getList structure ─────────────────────────────────────────────────

  it('getList returns correct structure', () => {
    registry.revoke('key-alpha', 'expired')
    registry.revoke('key-beta')

    const list = registry.getList()

    expect(list.version).toBe('7h3/0.1')
    expect(typeof list.updated).toBe('number')
    expect(list.revokedKeys).toHaveLength(2)

    const alpha = list.revokedKeys.find(e => e.id === 'key-alpha')
    expect(alpha).toBeDefined()
    expect(alpha!.reason).toBe('expired')
    expect(typeof alpha!.revokedAt).toBe('number')

    const beta = list.revokedKeys.find(e => e.id === 'key-beta')
    expect(beta).toBeDefined()
    expect(beta!.reason).toBeUndefined()
  })

  // ── 10. importList merges without overwrite ──────────────────────────────

  it('importList merges entries without overwriting existing ones', () => {
    // Pre-revoke key-a locally with a specific timestamp
    const originalTime = Date.now() - 5_000
    registry['revoked'].set('key-a', { id: 'key-a', revokedAt: originalTime, reason: 'local-reason' })

    const incomingList: RevocationList = {
      version: '7h3/0.1',
      updated: Date.now(),
      revokedKeys: [
        { id: 'key-a', revokedAt: Date.now(), reason: 'remote-reason' },  // should NOT overwrite
        { id: 'key-b', revokedAt: Date.now(), reason: 'new-key' },         // should be added
      ],
    }

    registry.importList(incomingList)

    // key-a should keep original local entry (no overwrite)
    const entryA = registry['revoked'].get('key-a')
    expect(entryA!.revokedAt).toBe(originalTime)
    expect(entryA!.reason).toBe('local-reason')

    // key-b should have been added
    expect(registry.isRevoked('key-b')).toBe(true)
    const entryB = registry['revoked'].get('key-b')
    expect(entryB!.reason).toBe('new-key')
  })

  // ── 11. wrapRegistry returns null for revoked sender ────────────────────

  it('wrapRegistry returns null for a revoked sender', async () => {
    const inner = createStaticKeyRegistry({
      'agent@example.com': 'pub-key-abc',
    })

    registry.revoke('agent@example.com')
    const wrapped = registry.wrapRegistry(inner)

    const result = await wrapped.getPublicKey('agent@example.com')
    expect(result).toBeNull()
  })

  it('wrapRegistry returns the public key for a non-revoked sender', async () => {
    const inner = createStaticKeyRegistry({
      'agent@example.com': 'pub-key-abc',
    })

    const wrapped = registry.wrapRegistry(inner)

    const result = await wrapped.getPublicKey('agent@example.com')
    expect(result).toBe('pub-key-abc')
  })

  it('wrapRegistry also blocks getSharedSecret (HMAC) for a revoked identity, not just getPublicKey (Ed25519)', async () => {
    const inner = {
      getPublicKey: async () => null,
      getSharedSecret: async (_keyId: string, _sender: string) => 'the-shared-secret',
    }

    registry.revoke('agent@example.com')
    const wrapped = registry.wrapRegistry(inner)

    const result = await wrapped.getSharedSecret!('k1', 'agent@example.com')
    expect(result).toBeNull()
  })

  it('wrapRegistry still returns the shared secret for a non-revoked identity', async () => {
    const inner = {
      getPublicKey: async () => null,
      getSharedSecret: async (_keyId: string, _sender: string) => 'the-shared-secret',
    }

    const wrapped = registry.wrapRegistry(inner)

    const result = await wrapped.getSharedSecret!('k1', 'agent@example.com')
    expect(result).toBe('the-shared-secret')
  })
})

describe('RevocationRegistry — sender vs keyId', () => {
  const inner = {
    getPublicKey: async (sender: string) => (sender === 'alice@a.test' ? 'PUBKEY' : null),
    getSharedSecret: async (_keyId: string, sender: string) => (sender === 'alice@a.test' ? 'SECRET' : null),
  }

  it('revoking a sender blocks both credential types', async () => {
    const r = new RevocationRegistry()
    r.revoke('alice@a.test', 'compromised')
    const w = r.wrapRegistry(inner as never)
    expect(await w.getPublicKey('alice@a.test')).toBeNull()
    expect(await w.getSharedSecret!('k1', 'alice@a.test')).toBeNull()
  })

  it('isEnvelopeRevoked enforces a keyId revocation, which a registry lookup cannot', async () => {
    const r = new RevocationRegistry()
    r.revoke('k1', 'key compromised')
    const w = r.wrapRegistry(inner as never)

    // A registry lookup is keyed by sender and never sees signature.keyId, so
    // it cannot enforce this — which is exactly why isEnvelopeRevoked exists.
    expect(await w.getPublicKey('alice@a.test')).toBe('PUBKEY')
    expect(await w.getSharedSecret!('k1', 'alice@a.test')).toBeNull()

    const envelope = { header: { sender: 'alice@a.test' }, signature: { keyId: 'k1' } }
    expect(r.isEnvelopeRevoked(envelope)).toBe(true)
  })

  it('isEnvelopeRevoked also catches a revoked sender', () => {
    const r = new RevocationRegistry()
    r.revoke('alice@a.test')
    expect(r.isEnvelopeRevoked({ header: { sender: 'alice@a.test' }, signature: { keyId: 'k9' } })).toBe(true)
    expect(r.isEnvelopeRevoked({ header: { sender: 'bob@a.test' }, signature: { keyId: 'k9' } })).toBe(false)
  })
})
