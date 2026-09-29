import { generateEd25519KeypairBase64Url, randomHex } from './protocol'
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

/** Largest key document accepted, in characters. A key document is a few hundred bytes per key. */
const MAX_KEY_DOCUMENT_CHARS = 256 * 1024

// Fetch .well-known/7h3-keys from a base URL (uses global fetch).
// Redirects are refused (a redirect can move a request from the vetted host to an
// internal one) and the response size is bounded.
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
    const resp = await fetch(url, { signal: controller.signal, redirect: 'error' })
    if (!resp.ok) throw new Error(`HTTP ${resp.status} from ${url}`)
    const text = await resp.text()
    if (text.length > MAX_KEY_DOCUMENT_CHARS) throw new Error(`key document from ${url} is too large`)
    return parseWellKnownKeys(text)
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

/**
 * True if `host` is a plausible PUBLIC DNS name we are willing to fetch keys from:
 * lower-case labels only, at least two of them, no port, path, credentials or
 * brackets, not an IP address, and not a name that resolves internally by convention
 * (`localhost`, `*.local`, `*.internal`, `*.localhost`, `*.lan`, `*.home.arpa`).
 *
 * The host comes from the `sender` field of a message that has NOT been verified yet
 * (verification needs the key this lookup fetches), so it is attacker-controlled. Without
 * this check a caller could steer the verifier at `127.0.0.1`, a metadata endpoint or an
 * arbitrary internal service. DNS can still resolve a public-looking name to a private
 * address, so deployments that must be robust to that should also set `allowedDomains`.
 */
export function isFetchableKeyHost(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(host)) return false
  const labels = host.split('.')
  if (labels.every((l) => /^[0-9]+$/.test(l))) return false // dotted-quad IPv4 (and similar numeric forms)
  const tld = labels[labels.length - 1]
  if (/^[0-9]+$/.test(tld) || tld === 'localhost' || tld === 'local' || tld === 'internal' || tld === 'lan' || tld === 'home' || host.endsWith('.home.arpa')) return false
  return true
}

// ── HTTP-backed KeyRegistry (auto-discovers from .well-known) ────────────────

export function createHttpKeyRegistry(opts?: {
  timeout?: number
  cacheMs?: number
  /**
   * Only look up keys for these hosts (exact match, lower-case). Strongly recommended:
   * without it any public host named in a sender id is contacted, and any domain can
   * introduce itself as a sender.
   */
  allowedDomains?: string[]
  /** Maximum cached hosts (default 1000). */
  maxCacheEntries?: number
}): KeyRegistry {
  const cache = new Map<string, { doc: WellKnownKeysDocument; expiresAt: number }>()
  const cacheMs = opts?.cacheMs ?? 60_000
  const timeout = opts?.timeout ?? 5_000
  const maxCache = opts?.maxCacheEntries ?? 1000
  const allowed = opts?.allowedDomains ? new Set(opts.allowedDomains.map((d) => d.toLowerCase())) : null

  async function getDoc(baseUrl: string): Promise<WellKnownKeysDocument> {
    const now = Date.now()
    const hit = cache.get(baseUrl)
    if (hit && hit.expiresAt > now) return hit.doc
    const doc = await fetchWellKnownKeys(baseUrl, { timeout })
    // Bounded: sender ids are attacker-chosen, so an unbounded cache is a memory-growth vector.
    if (cache.size >= maxCache) cache.delete(cache.keys().next().value as string)
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
      if (!domain || !isFetchableKeyHost(domain)) return null
      if (allowed && !allowed.has(domain)) return null
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
      id: `key-${now}-${randomHex(4)}`,
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
        // A KeyRegistry must return null for an identity it doesn't manage —
        // falling back to "the current key" here would mean a lookup for
        // *any* unrecognized senderId resolves to whichever key happens to
        // be current, letting one identity's signature verify while claiming
        // to be a different, unrelated identity.
        const byId = this.keys.find(k => k.id === senderId && (!k.expiresAt || k.expiresAt > now))
        return byId?.publicKey ?? null
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

  /**
   * Revoke an identifier — either a sender identity or a keyId.
   *
   * Which one you pass matters, and the difference used to be silent. A
   * registry lookup is keyed by *sender*, so `wrapRegistry().getPublicKey()`
   * can only ever compare against a sender id. Revoking a bare keyId therefore
   * blocked the HMAC path (which receives both identifiers) while leaving the
   * Ed25519 path fully open — a revoked, compromised key kept authenticating.
   *
   * Use {@link isEnvelopeRevoked} on the verification path to enforce a keyId
   * revocation for Ed25519, or revoke the sender identity as well. For
   * fleet-wide `(sender, keyId)` revocation, use `RevocationStore` from
   * `./revocation` instead.
   */
  revoke(senderOrKeyId: string, reason?: string): void {
    this.revoked.set(senderOrKeyId, { id: senderOrKeyId, revokedAt: Date.now(), reason })
  }

  /**
   * True if either the envelope's sender or the keyId it was signed under has
   * been revoked.
   *
   * This is the check that actually enforces a keyId revocation for Ed25519,
   * because unlike a registry lookup it can see `signature.keyId`. Call it on
   * the verification path alongside signature checking.
   */
  isEnvelopeRevoked(envelope: {
    header?: { sender?: string }
    signature?: { keyId?: string }
  }): boolean {
    const sender = envelope?.header?.sender
    const keyId = envelope?.signature?.keyId
    return (sender !== undefined && this.isRevoked(sender)) ||
      (keyId !== undefined && this.isRevoked(keyId))
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
    return {
      // Only the sender id is available here — the KeyRegistry interface gives
      // this method nothing else — so a keyId-only revocation cannot be
      // enforced at this point. isEnvelopeRevoked() covers that case on the
      // verification path, where signature.keyId is in scope.
      getPublicKey: async (senderId: string) => {
        if (this.isRevoked(senderId)) return null
        return inner.getPublicKey(senderId)
      },
      // Forwarding inner.getSharedSecret unchanged (as a previous version of
      // this method did) enforces revocation for Ed25519 senders but lets an
      // HMAC identity keep authenticating after being revoked — the wrapper
      // only wraps one of the two credential types it claims to cover.
      // Revoked entries are keyed by whatever identifier revoke() was called
      // with; since callers have been observed passing either a keyId or a
      // sender id there, check both before delegating.
      getSharedSecret: inner.getSharedSecret
        ? async (keyId: string, sender: string) => {
            if (this.isRevoked(keyId) || this.isRevoked(sender)) return null
            return inner.getSharedSecret!(keyId, sender)
          }
        : undefined,
    }
  }
}
