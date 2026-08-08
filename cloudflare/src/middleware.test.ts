import { describe, it, expect } from 'vitest'
import { generateEd25519KeypairBase64Url, createEnvelope, signEnvelopeEd25519 } from '@7h3/protocol'
import { create7h3Middleware, type MiddlewareEnv } from './middleware'

/** Minimal in-memory KVNamespace fake shared by KEY_REGISTRY and REPLAY_STORE. */
class FakeKV {
  private store = new Map<string, string>()

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null
  }

  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value)
  }
}

async function makeSignedHeaders(sender: string, privateKey: string, path = '/api/test'): Promise<Record<string, string>> {
  const envelope = createEnvelope({ sender, intent: 'TASK', content: path, ttlMs: 60_000 })
  const signed = await signEnvelopeEd25519(envelope, privateKey)
  return { 'x-7h3-envelope': JSON.stringify(signed) }
}

async function makeEnv(overrides: Partial<MiddlewareEnv> = {}): Promise<{ env: MiddlewareEnv; keys: { publicKey: string; privateKey: string } }> {
  const keys = await generateEd25519KeypairBase64Url()
  const keyRegistryKv = new FakeKV()
  await keyRegistryKv.put('7h3:pk:agent-a', keys.publicKey)

  const env: MiddlewareEnv = {
    KEY_REGISTRY: keyRegistryKv as unknown as KVNamespace,
    REPLAY_STORE: new FakeKV() as unknown as KVNamespace,
    ...overrides,
  }
  return { env, keys }
}

describe('create7h3Middleware', () => {
  it('verifies a validly signed request against a matching policy', async () => {
    const { env, keys } = await makeEnv({ DEFAULT_POLICY: 'deny' })
    const mw = create7h3Middleware(env, { policies: [{ path: '/api/**', require: 'ed25519' }] })
    const headers = await makeSignedHeaders('agent-a', keys.privateKey)

    const request = new Request('https://example.com/api/test', { headers })
    const result = await mw.verify(request)

    expect(result.ok).toBe(true)
    if (result.ok) expect(result.sender).toBe('agent-a')
  })

  it('rejects an unsigned request when DEFAULT_POLICY is deny', async () => {
    const { env } = await makeEnv({ DEFAULT_POLICY: 'deny' })
    const mw = create7h3Middleware(env)

    const request = new Request('https://example.com/api/test')
    const result = await mw.verify(request)

    expect(result.ok).toBe(false)
  })

  // The MiddlewareEnv type annotation claims DEFAULT_POLICY is 'allow' | 'deny',
  // but at runtime it's a plain Worker env var string with no validation
  // behind that type. Only the exact string 'allow' may opt into forwarding
  // unmatched/unsigned requests — every other value (a typo, wrong casing, an
  // empty string from a misconfigured secret) must fail closed to 'deny'.
  it.each(['Allow', 'ALLOW', '', 'true', 'yes'])(
    'treats an unrecognized DEFAULT_POLICY value (%j) as deny, not allow',
    async (badValue) => {
      const { env } = await makeEnv({ DEFAULT_POLICY: badValue as MiddlewareEnv['DEFAULT_POLICY'] })
      const mw = create7h3Middleware(env)

      const request = new Request('https://example.com/api/test')
      const result = await mw.verify(request)

      expect(result.ok).toBe(false)
    },
  )

  it('allows an unsigned request when DEFAULT_POLICY is exactly "allow"', async () => {
    const { env } = await makeEnv({ DEFAULT_POLICY: 'allow' })
    const mw = create7h3Middleware(env)

    const request = new Request('https://example.com/api/test')
    const result = await mw.verify(request)

    expect(result.ok).toBe(true)
  })
})
