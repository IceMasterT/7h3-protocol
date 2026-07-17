// Core interface all bindings use to look up keys
export interface KeyRegistry {
  getPublicKey(senderId: string): Promise<string | null>  // Ed25519 SPKI base64url
  // HMAC secret (optional). `sender` MUST be checked by implementations that
  // store secrets shared by multiple senders — without binding the lookup to
  // the sender the envelope actually claims, any principal holding one valid
  // (keyId, secret) pair can forge messages as a different sender.
  getSharedSecret?(keyId: string, sender: string): Promise<string | null>
}

// Simple in-memory registry from a static map
export function createStaticKeyRegistry(keys: Record<string, string>): KeyRegistry {
  return {
    async getPublicKey(senderId) { return keys[senderId] ?? null },
  }
}

// Multi-registry: tries registries in order, returns first non-null
export function createCompositeKeyRegistry(...registries: KeyRegistry[]): KeyRegistry {
  return {
    async getPublicKey(senderId) {
      for (const r of registries) {
        const key = await r.getPublicKey(senderId)
        if (key !== null) return key
      }
      return null
    },
    async getSharedSecret(keyId, sender) {
      for (const r of registries) {
        if (!r.getSharedSecret) continue
        const secret = await r.getSharedSecret(keyId, sender)
        if (secret !== null) return secret
      }
      return null
    },
  }
}

// Caching wrapper around any KeyRegistry (avoids repeated network calls)
export function createCachingKeyRegistry(
  inner: KeyRegistry,
  opts?: { ttlMs?: number }
): KeyRegistry {
  const ttl = opts?.ttlMs ?? 60_000
  const cache = new Map<string, { value: string | null; expiresAt: number }>()
  async function get(key: string, fetch: () => Promise<string | null>): Promise<string | null> {
    const now = Date.now()
    const cached = cache.get(key)
    if (cached && cached.expiresAt > now) return cached.value
    const value = await fetch()
    cache.set(key, { value, expiresAt: now + ttl })
    return value
  }
  return {
    async getPublicKey(senderId) {
      return get(`pk:${senderId}`, () => inner.getPublicKey(senderId))
    },
    async getSharedSecret(keyId, sender) {
      if (!inner.getSharedSecret) return null
      // Cache key includes sender — a cached secret for (keyId, agent-a) must
      // never be returned for a lookup claiming (keyId, agent-b).
      return get(`ss:${sender}:${keyId}`, () => inner.getSharedSecret!(keyId, sender))
    },
  }
}
