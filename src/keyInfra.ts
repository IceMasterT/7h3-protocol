import { generateEd25519KeypairBase64Url } from './protocol'
import type { KeyRegistry } from './keyRegistry'

// ── Well-Known Document ──────────────────────────────────────────────────────

export interface KeyEntry {
  id: string
  algorithm: 'Ed25519'
  publicKey: string   // SPKI base64url
  created: number     // Unix ms
  expires?: number
  revoked?: boolean
  revokedAt?: number
}

export interface WellKnownKeysDocument {
  version: '7h3/0.1'
  updated: number
  keys: KeyEntry[]
}

export function serveWellKnownKeys(doc: WellKnownKeysDocument): string {
  return JSON.stringify(doc)
}

export function parseWellKnownKeys(json: string): WellKnownKeysDocument {
  const d = JSON.parse(json) as WellKnownKeysDocument
  if (d.version !== '7h3/0.1') throw new Error(`unsupported version: ${d.version}`)
  return d
}

// Fetch .well-known/7h3-keys from a base URL (uses global fetch)
export async function fetchWellKnownKeys(
  baseUrl: string,
  opts?: { timeout?: number }
): Promise<WellKnownKeysDocument> {
  const url = baseUrl.replace(/\/$/, '') + '/.well-known/7h3-keys'
  const controller = new AbortController()
  const timer = opts?.timeout
    ? setTimeout(() => controller.abort(), opts.timeout)
    : undefined
  try {
    const resp = await fetch(url, { signal: controller.signal })
    if (!resp.ok) throw new Error(`HTTP ${resp.status} from ${url}`)
    return parseWellKnownKeys(await resp.text())
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

// ── HTTP-backed KeyRegistry (auto-discovers from .well-known) ────────────────

export function createHttpKeyRegistry(opts?: {
  timeout?: number
  cacheMs?: number
}): KeyRegistry {
  const cache = new Map<string, { doc: WellKnownKeysDocument; expiresAt: number }>()
  const cacheMs = opts?.cacheMs ?? 60_000
  const timeout = opts?.timeout ?? 5_000

  async function getDoc(baseUrl: string): Promise<WellKnownKeysDocument> {
    const now = Date.now()
    const hit = cache.get(baseUrl)
    if (hit && hit.expiresAt > now) return hit.doc
    const doc = await fetchWellKnownKeys(baseUrl, { timeout })
    cache.set(baseUrl, { doc, expiresAt: now + cacheMs })
    return doc
  }

  return {
    async getPublicKey(senderId: string): Promise<string | null> {
      // senderId format: "service@example.com" or "agent.example.com"
      // extract domain for well-known lookup
      const domain = senderId.includes('@')
        ? senderId.split('@')[1]
        : senderId.split('.').slice(-2).join('.')
      if (!domain) return null
      try {
        const doc = await getDoc(`https://${domain}`)
        const now = Date.now()
        const entry = doc.keys.find(
          k =>
            (k.id === senderId || k.id === senderId.split('@')[0]) &&
            !k.revoked &&
            (!k.expires || k.expires > now)
        )
        return entry?.publicKey ?? null
      } catch {
        return null
      }
    },
  }
}

// ── Key Rotation Manager ─────────────────────────────────────────────────────

export interface ManagedKeyPair {
  id: string
  publicKey: string
  privateKey: string
  createdAt: number
  expiresAt?: number
}

export interface KeyRotationOptions {
  maxAgeMs: number
  overlapMs?: number
}

export class KeyRotationManager {
  private readonly maxAgeMs: number
  private readonly overlapMs: number
  private keys: ManagedKeyPair[] = []

  constructor(opts: KeyRotationOptions) {
    this.maxAgeMs = opts.maxAgeMs
    this.overlapMs = opts.overlapMs ?? Math.floor(opts.maxAgeMs * 0.1)
  }

  addKey(pair: ManagedKeyPair): void {
    this.keys.push(pair)
  }

  getCurrentKey(): ManagedKeyPair | null {
    const now = Date.now()
    const active = this.keys.filter(k => !k.expiresAt || k.expiresAt > now)
    if (active.length === 0) return null
    return active.reduce((a, b) => (a.createdAt > b.createdAt ? a : b))
  }

  async rotateIfNeeded(): Promise<ManagedKeyPair | null> {
    const now = Date.now()
    const current = this.getCurrentKey()
    if (current && now - current.createdAt < this.maxAgeMs - this.overlapMs) return null
    // Expire the current key after overlap period
    if (current && !current.expiresAt) {
      current.expiresAt = now + this.overlapMs
    }
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const newKey: ManagedKeyPair = {
      id: `key-${now}-${Math.random().toString(36).slice(2, 8)}`,
      publicKey,
      privateKey,
      createdAt: now,
    }
    this.keys.push(newKey)
    return newKey
  }

  getWellKnownDocument(): WellKnownKeysDocument {
    const now = Date.now()
    return {
      version: '7h3/0.1',
      updated: now,
      keys: this.keys.map(k => ({
        id: k.id,
        algorithm: 'Ed25519' as const,
        publicKey: k.publicKey,
        created: k.createdAt,
        ...(k.expiresAt ? { expires: k.expiresAt } : {}),
        ...(k.expiresAt && k.expiresAt < now ? { revoked: true, revokedAt: k.expiresAt } : {}),
      })),
    }
  }

  toKeyRegistry(): KeyRegistry {
    return {
      getPublicKey: async (senderId: string): Promise<string | null> => {
        const now = Date.now()
        // Find by ID or return the current active key's public key
        const byId = this.keys.find(k => k.id === senderId && (!k.expiresAt || k.expiresAt > now))
        return byId?.publicKey ?? this.getCurrentKey()?.publicKey ?? null
      },
    }
  }
}

// ── Revocation Registry ──────────────────────────────────────────────────────

export interface RevocationEntry {
  id: string
  revokedAt: number
  reason?: string
}

export interface RevocationList {
  version: '7h3/0.1'
  updated: number
  revokedKeys: RevocationEntry[]
}

export class RevocationRegistry {
  private revoked = new Map<string, RevocationEntry>()

  revoke(keyId: string, reason?: string): void {
    this.revoked.set(keyId, { id: keyId, revokedAt: Date.now(), reason })
  }

  isRevoked(keyId: string): boolean {
    return this.revoked.has(keyId)
  }

  getList(): RevocationList {
    return {
      version: '7h3/0.1',
      updated: Date.now(),
      revokedKeys: [...this.revoked.values()],
    }
  }

  importList(list: RevocationList): void {
    for (const entry of list.revokedKeys) {
      if (!this.revoked.has(entry.id)) this.revoked.set(entry.id, entry)
    }
  }

  // Returns a KeyRegistry wrapper that rejects revoked keys
  wrapRegistry(inner: KeyRegistry): KeyRegistry {
    const self = this
    return {
      async getPublicKey(senderId: string) {
        if (self.isRevoked(senderId)) return null
        return inner.getPublicKey(senderId)
      },
      getSharedSecret: inner.getSharedSecret?.bind(inner),
    }
  }
}
