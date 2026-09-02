/**
 * Regression tests for the authorization decision path.
 *
 * Every case here is a bug that shipped in the first cut of `decide()` and was
 * caught in review. They are written as the property that must hold, so the
 * failure mode is named rather than just the fix.
 */

import { describe, expect, it } from 'vitest'
import {
  delegateCapabilityToken,
  generateEd25519KeypairBase64Url,
  serializeCapabilityChain,
} from '@7h3/protocol'
import { guard, InMemoryReplayChecker, NONCE_FIELD } from './guard'
import type { ModelContextLike, ModelContextTool } from './types'

class FakeModelContext implements ModelContextLike {
  readonly registered = new Map<string, ModelContextTool>()
  async registerTool(tool: ModelContextTool): Promise<void> {
    this.registered.set(tool.name, tool)
  }
  call(name: string, input: Record<string, unknown> = {}): Promise<unknown> {
    return this.registered.get(name)!.execute(input) as Promise<unknown>
  }
}

type Result = { ok: boolean; reason?: string; detail?: string }

async function harness() {
  const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
  const mc = new FakeModelContext()
  const calls: string[] = []
  const g = guard({ origin: 'ledger.test', privateKey, publicKey, modelContext: mc })

  await g.registerTool({
    name: 'pay',
    description: 'Pay an invoice',
    scope: 'money/pay',
    limit: { field: 'amountCents', max: 1_000_00 },
    execute: async () => { calls.push('pay'); return { paid: true } },
  })
  await g.registerTool({
    name: 'confirmed_pay',
    description: 'Pay, with human confirmation',
    scope: 'money/pay',
    confirm: true,
    execute: async () => { calls.push('confirmed_pay'); return { paid: true } },
  })

  return { g, mc, calls }
}

describe('grant selection is permissive across grants', () => {
  it('lets a broader grant authorize what a narrower one would cap', async () => {
    const { g, mc } = await harness()
    // Narrow grant issued first, so it is iterated first.
    await g.grant({ subject: 'a', scopes: ['money/pay'], caps: { amountCents: 50_00 }, ttlMs: 600_000 })
    await g.grant({ subject: 'a', scopes: ['money/**'], caps: { amountCents: 900_00 }, ttlMs: 600_000 })

    const res = (await mc.call('pay', { amountCents: 600_00 })) as Result
    expect(res.ok).toBe(true)
  })

  it('does not let one corrupt grant veto a valid one', async () => {
    const { g, mc } = await harness()
    const bad = await g.grant({ subject: 'a', scopes: ['money/pay'], ttlMs: 600_000 })
    ;(bad as { signature: string }).signature = 'A'.repeat(86)
    await g.grant({ subject: 'a', scopes: ['money/pay'], ttlMs: 600_000 })

    const res = (await mc.call('pay', { amountCents: 10 })) as Result
    expect(res.ok).toBe(true)
  })

  it('still refuses when no grant authorizes, reporting the most specific reason', async () => {
    const { g, mc } = await harness()
    await g.grant({ subject: 'a', scopes: ['money/**'], caps: { amountCents: 10_00 }, ttlMs: 600_000 })

    const res = (await mc.call('pay', { amountCents: 900_00 })) as Result
    expect(res.ok).toBe(false)
    // limit-exceeded outranks scope-not-covered: it tells the agent far more.
    expect(res.reason).toBe('limit-exceeded')
  })
})

describe('ceilings fail closed', () => {
  it('refuses when the limited field is omitted entirely', async () => {
    const { g, mc, calls } = await harness()
    await g.grant({ subject: 'a', scopes: ['money/**'], caps: { amountCents: 1 }, ttlMs: 600_000 })

    const res = (await mc.call('pay', {})) as Result
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('limit-exceeded')
    expect(calls).toEqual([])
  })
})

describe('nonces are spent only by calls that proceed', () => {
  it('does not consume a nonce on a call refused at confirmation', async () => {
    const { g, mc } = await harness()
    await g.grant({ subject: 'a', scopes: ['money/**'], ttlMs: 600_000 })

    const first = (await mc.call('confirmed_pay', { [NONCE_FIELD]: 'n1' })) as Result
    expect(first.reason).toBe('confirmation-denied')

    // The human changes their mind; the identical retry must not be a replay.
    const second = (await mc.call('confirmed_pay', { [NONCE_FIELD]: 'n1' })) as Result
    expect(second.reason).not.toBe('replayed-call')
  })

  it('still refuses a genuine replay of a call that did proceed', async () => {
    const { g, mc } = await harness()
    await g.grant({ subject: 'a', scopes: ['money/**'], ttlMs: 600_000 })

    expect(((await mc.call('pay', { amountCents: 10, [NONCE_FIELD]: 'n2' })) as Result).ok).toBe(true)
    const replay = (await mc.call('pay', { amountCents: 10, [NONCE_FIELD]: 'n2' })) as Result
    expect(replay.reason).toBe('replayed-call')
  })
})

describe('cross-agent delegation', () => {
  it('accepts a chain re-delegated by the subject under its own key', async () => {
    const origin = await generateEd25519KeypairBase64Url()
    const agentA = await generateEd25519KeypairBase64Url()
    const mc = new FakeModelContext()
    const g = guard({
      origin: 'ledger.test',
      privateKey: origin.privateKey,
      publicKey: origin.publicKey,
      modelContext: mc,
      peerKeys: { 'agent-a': agentA.publicKey },
    })
    await g.registerTool({
      name: 'pay',
      description: 'Pay an invoice',
      scope: 'money/pay',
      limit: { field: 'amountCents', max: 1_000_00 },
      execute: async () => ({ paid: true }),
    })

    const root = await g.grant({ subject: 'agent-a', scopes: ['money/**'], ttlMs: 600_000, maxDelegations: 1 })
    const child = await delegateCapabilityToken({
      parentToken: root,
      delegatorPrivateKey: agentA.privateKey,
      delegatorId: 'agent-a',
      newSubject: 'agent-b',
      scopes: [{ pathGlob: 'money/pay' }],
      ttlMs: 300_000,
    })

    const res = (await mc.call('pay', {
      amountCents: 100,
      __7h3_grant: serializeCapabilityChain([root, child]),
    })) as Result
    expect(res.ok).toBe(true)
  })

  it('refuses a delegated chain from an issuer whose key is not configured', async () => {
    const origin = await generateEd25519KeypairBase64Url()
    const agentA = await generateEd25519KeypairBase64Url()
    const mc = new FakeModelContext()
    const g = guard({ origin: 'ledger.test', privateKey: origin.privateKey, publicKey: origin.publicKey, modelContext: mc })
    await g.registerTool({
      name: 'pay', description: 'Pay', scope: 'money/pay',
      execute: async () => ({ paid: true }),
    })

    const root = await g.grant({ subject: 'agent-a', scopes: ['money/**'], ttlMs: 600_000, maxDelegations: 1 })
    const child = await delegateCapabilityToken({
      parentToken: root,
      delegatorPrivateKey: agentA.privateKey,
      delegatorId: 'agent-a',
      newSubject: 'agent-b',
      ttlMs: 300_000,
    })

    const res = (await mc.call('pay', { __7h3_grant: serializeCapabilityChain([root, child]) })) as Result
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('grant-invalid-signature')
  })
})

describe('limit refusals name the binding ceiling', () => {
  it('reports the most permissive ceiling the caller actually holds', async () => {
    const { g, mc } = await harness()
    await g.grant({ subject: 'a', scopes: ['money/pay'], caps: { amountCents: 50_00 }, ttlMs: 600_000 })
    await g.grant({ subject: 'a', scopes: ['money/**'], caps: { amountCents: 900_00 }, ttlMs: 600_000 })

    const res = (await mc.call('pay', { amountCents: 5_000_00 })) as Result
    expect(res.ok).toBe(false)
    // 90000, not the narrow grant's 5000 — the $900 grant is what they are up against.
    expect(res.detail).toContain('90000')
    expect(res.detail).not.toContain('of 5000')
  })

  it('still refuses a non-finite amount rather than coercing it', async () => {
    const { g, mc } = await harness()
    await g.grant({ subject: 'a', scopes: ['money/**'], ttlMs: 600_000 })
    const res = (await mc.call('pay', { amountCents: 'not-a-number' })) as Result
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('limit-exceeded')
  })
})

describe('delegation may only narrow authority', () => {
  async function chainHarness() {
    const origin = await generateEd25519KeypairBase64Url()
    const agentA = await generateEd25519KeypairBase64Url()
    const mc = new FakeModelContext()
    const g = guard({
      origin: 'ledger.test',
      privateKey: origin.privateKey,
      publicKey: origin.publicKey,
      modelContext: mc,
      peerKeys: { 'agent-a': agentA.publicKey },
    })
    await g.registerTool({
      name: 'pay',
      description: 'Pay an invoice',
      scope: 'money/pay',
      limit: { field: 'amountCents', max: 2_000_00 },
      execute: async () => ({ paid: true }),
    })
    return { g, mc, agentA }
  }

  it('refuses a child that re-delegates itself a larger ceiling than its parent', async () => {
    const { g, mc, agentA } = await chainHarness()
    // A broad root glob is what makes the escalation reachable: '**' contains
    // the reserved caps/ scope, so containment alone would accept a bigger cap.
    const root = await g.grant({
      subject: 'agent-a', scopes: ['**'], caps: { amountCents: 50_00 },
      ttlMs: 600_000, maxDelegations: 1,
    })
    const child = await delegateCapabilityToken({
      parentToken: root,
      delegatorPrivateKey: agentA.privateKey,
      delegatorId: 'agent-a',
      newSubject: 'agent-b',
      scopes: [{ pathGlob: 'money/pay' }, { pathGlob: 'caps/amountCents/199900' }],
      ttlMs: 300_000,
    })

    const res = (await mc.call('pay', {
      amountCents: 1_500_00,
      __7h3_grant: serializeCapabilityChain([root, child]),
    })) as Result
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('limit-exceeded')
    // The parent's $50 is what binds, not the child's claim.
    expect(res.detail).toContain('5000')
  })

  it('lets a child tighten the ceiling below its parent', async () => {
    const { g, mc, agentA } = await chainHarness()
    const root = await g.grant({
      subject: 'agent-a', scopes: ['**'], caps: { amountCents: 500_00 },
      ttlMs: 600_000, maxDelegations: 1,
    })
    const child = await delegateCapabilityToken({
      parentToken: root,
      delegatorPrivateKey: agentA.privateKey,
      delegatorId: 'agent-a',
      newSubject: 'agent-b',
      scopes: [{ pathGlob: 'money/pay' }, { pathGlob: 'caps/amountCents/1000' }],
      ttlMs: 300_000,
    })
    const chain = serializeCapabilityChain([root, child])

    expect(((await mc.call('pay', { amountCents: 5_00, __7h3_grant: chain })) as Result).ok).toBe(true)
    const over = (await mc.call('pay', { amountCents: 100_00, __7h3_grant: chain })) as Result
    expect(over.ok).toBe(false)
    expect(over.detail).toContain('1000')
  })
})

describe('reserved namespace', () => {
  it('refuses to register a tool inside the caps/ namespace', async () => {
    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const g = guard({ origin: 'o', privateKey, publicKey, modelContext: new FakeModelContext() })
    await expect(
      g.registerTool({
        name: 'sneaky', description: 'x', scope: 'caps/amountCents/999999',
        execute: async () => ({}),
      }),
    ).rejects.toThrow(/reserved/)
  })
})

describe('replay store retention', () => {
  it('remembers an accepted nonce even when handed a non-positive TTL', async () => {
    const clock = 1_000_000
    for (const ttl of [0, -5]) {
      const store = new InMemoryReplayChecker(() => clock)
      expect(await store.check('n', ttl)).toBe(false)
      // Without a retention floor the entry expires the instant it is written,
      // so the identical call reads as fresh and replay protection vanishes.
      expect(await store.check('n', ttl)).toBe(true)
    }
  })

  it('releases a nonce once its retention window has genuinely elapsed', async () => {
    let clock = 1_000_000
    const store = new InMemoryReplayChecker(() => clock)
    expect(await store.check('n', 5 * 60_000)).toBe(false)
    clock += 4 * 60_000
    expect(await store.check('n', 5 * 60_000)).toBe(true)
    clock += 2 * 60_000
    expect(await store.check('n', 5 * 60_000)).toBe(false)
  })
})
