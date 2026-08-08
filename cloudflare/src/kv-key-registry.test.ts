import { describe, it, expect } from 'vitest'
import { KvKeyRegistry } from './kv-key-registry'

/** Minimal in-memory KVNamespace fake covering the get/put surface KvKeyRegistry uses. */
class FakeKV {
  private store = new Map<string, string>()

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null
  }

  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value)
  }
}

describe('KvKeyRegistry', () => {
  it('resolves a public key by sender id', async () => {
    const kv = new FakeKV()
    await kv.put('7h3:pk:agent@example.com', 'pub-key-abc')
    const registry = new KvKeyRegistry(kv as unknown as KVNamespace)

    expect(await registry.getPublicKey('agent@example.com')).toBe('pub-key-abc')
    expect(await registry.getPublicKey('unknown@example.com')).toBeNull()
  })

  it('resolves a shared secret by (keyId, sender)', async () => {
    const kv = new FakeKV()
    const registry = new KvKeyRegistry(kv as unknown as KVNamespace)
    await kv.put(`7h3:ss:${encodeURIComponent('alice')}:${encodeURIComponent('k1')}`, 'alice-secret')

    expect(await registry.getSharedSecret('k1', 'alice')).toBe('alice-secret')
  })

  // Without percent-encoding, "${sender}:${keyId}" lets a `:` inside either
  // field shift the field boundary: sender="alice:secret", keyId="xyz"
  // would produce the identical raw key as sender="alice", keyId="secret:xyz".
  // That would let a caller claiming to be "alice:secret" read a secret that
  // was actually registered for the completely different sender "alice".
  it('does not let a colon inside sender/keyId collide with a different (sender, keyId) pair', async () => {
    const kv = new FakeKV()
    const registry = new KvKeyRegistry(kv as unknown as KVNamespace)

    // Register a secret for sender="alice", keyId="secret:xyz"
    await kv.put(`7h3:ss:${encodeURIComponent('alice')}:${encodeURIComponent('secret:xyz')}`, 'alices-real-secret')

    // A lookup claiming sender="alice:secret", keyId="xyz" must NOT resolve
    // to the same value — with an unescaped join both would read the raw
    // key "7h3:ss:alice:secret:xyz".
    const collisionAttempt = await registry.getSharedSecret('xyz', 'alice:secret')
    expect(collisionAttempt).toBeNull()

    // The real (sender, keyId) pair still resolves correctly.
    const real = await registry.getSharedSecret('secret:xyz', 'alice')
    expect(real).toBe('alices-real-secret')
  })

  it('does not confuse two senders whose secrets could collide without escaping', async () => {
    const kv = new FakeKV()
    const registry = new KvKeyRegistry(kv as unknown as KVNamespace)

    await kv.put(`7h3:ss:${encodeURIComponent('bob')}:${encodeURIComponent('k1')}`, 'bobs-secret')
    await kv.put(`7h3:ss:${encodeURIComponent('bob:evil')}:${encodeURIComponent('1')}`, 'attacker-secret')

    expect(await registry.getSharedSecret('k1', 'bob')).toBe('bobs-secret')
    expect(await registry.getSharedSecret('1', 'bob:evil')).toBe('attacker-secret')
  })
})
