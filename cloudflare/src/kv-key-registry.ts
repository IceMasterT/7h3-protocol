import type { KeyRegistry } from '@7h3/protocol/key-registry'

/**
 * Cloudflare KV-backed key registry.
 *
 * Keys are stored in KV under:
 *   7h3:pk:{senderId}                                    → Ed25519 SPKI public key (base64url)
 *   7h3:ss:{encodeURIComponent(sender)}:{encodeURIComponent(keyId)}  → HMAC shared secret
 *
 * HMAC secrets are keyed by (sender, keyId) — not keyId alone — so a
 * principal holding one valid (keyId, secret) pair cannot present it while
 * claiming to be a different sender. Both fields are percent-encoded before
 * joining specifically so a `:` inside either one can't shift the boundary
 * between them — e.g. sender="alice:secret", keyId="xyz" must never collide
 * with the entirely different pair sender="alice", keyId="secret:xyz".
 *
 * Load keys via:
 *   wrangler kv:key put --namespace-id <ID> "7h3:pk:agent@example.com" "<base64url-pubkey>"
 *   wrangler kv:key put --namespace-id <ID> "7h3:ss:$(node -e "console.log(encodeURIComponent('agent@example.com'))"):$(node -e "console.log(encodeURIComponent('k1'))")" "<secret>"
 */
export class KvKeyRegistry implements KeyRegistry {
  private readonly pkPrefix: string
  private readonly ssPrefix: string

  constructor(
    private readonly kv: KVNamespace,
    opts?: { pkPrefix?: string; ssPrefix?: string },
  ) {
    this.pkPrefix = opts?.pkPrefix ?? '7h3:pk:'
    this.ssPrefix = opts?.ssPrefix ?? '7h3:ss:'
  }

  async getPublicKey(senderId: string): Promise<string | null> {
    return this.kv.get(`${this.pkPrefix}${senderId}`)
  }

  async getSharedSecret(keyId: string, sender: string): Promise<string | null> {
    return this.kv.get(`${this.ssPrefix}${encodeURIComponent(sender)}:${encodeURIComponent(keyId)}`)
  }
}

/**
 * Composite registry: checks KV first, then falls back to a static map.
 * Useful during initial setup before all keys are loaded into KV.
 */
export function createKvKeyRegistry(
  kv: KVNamespace,
  staticFallback?: Record<string, string>,
): KeyRegistry {
  const kvRegistry = new KvKeyRegistry(kv)
  if (!staticFallback) return kvRegistry

  return {
    async getPublicKey(senderId: string) {
      const fromKv = await kvRegistry.getPublicKey(senderId)
      return fromKv ?? staticFallback[senderId] ?? null
    },
    async getSharedSecret(keyId: string, sender: string) {
      return kvRegistry.getSharedSecret(keyId, sender)
    },
  }
}
