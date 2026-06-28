import type { ProtocolEnvelope } from './protocol'

// Core interface all bindings use to look up keys
export interface KeyRegistry {
  getPublicKey(senderId: string): Promise<string | null>  // Ed25519 SPKI base64url
  getSharedSecret?(keyId: string): Promise<string | null>  // HMAC secret (optional)
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
    async getSharedSecret(keyId) {
      for (const r of registries) {
        if (!r.getSharedSecret) continue
        const secret = await r.getSharedSecret(keyId)
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
    async getSharedSecret(keyId) {
      if (!inner.getSharedSecret) return null
      return get(`ss:${keyId}`, () => inner.getSharedSecret!(keyId))
    },
  }
}
