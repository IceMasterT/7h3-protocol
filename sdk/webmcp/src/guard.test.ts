import { describe, expect, it } from 'vitest'
import { generateEd25519KeypairBase64Url } from '@7h3/protocol'
import { guard, GRANT_FIELD, NONCE_FIELD, parseCaps, type ToolGuard } from './guard'
import { verifyChain } from './receipts'
import type { GuardedTool, ModelContextLike, ModelContextTool } from './types'

/** Captures registered tools so tests can invoke exactly what an agent would call. */
class FakeModelContext implements ModelContextLike {
  readonly registered = new Map<string, ModelContextTool>()
  async registerTool(tool: ModelContextTool): Promise<void> {
    this.registered.set(tool.name, tool)
  }
  call(name: string, input: Record<string, unknown> = {}): Promise<unknown> {
    const tool = this.registered.get(name)
    if (!tool) throw new Error(`tool not registered: ${name}`)
    return tool.execute(input) as Promise<unknown>
  }
}

interface Harness {
  g: ToolGuard
  mc: FakeModelContext
  publicKey: string
  privateKey: string
  setNow: (ms: number) => void
  calls: string[]
}

async function harness(opts: { onConfirm?: GuardedTool extends never ? never : (t: GuardedTool, i: Record<string, unknown>) => Promise<boolean> } = {}): Promise<Harness> {
  const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
  const mc = new FakeModelContext()
  let clock = Date.now()
  const calls: string[] = []

  const g = guard({
    origin: 'ledger.test',
    privateKey,
    publicKey,
    modelContext: mc,
    now: () => clock,
    onConfirm: opts.onConfirm,
  })

  // A representative surface: one public read, one scoped write, one with a ceiling.
  await g.registerTool({
    name: 'list_invoices',
    description: 'List invoices',
    annotations: { readOnlyHint: true },
    execute: async () => { calls.push('list_invoices'); return [{ id: 'inv-1' }] },
  })
  await g.registerTool({
    name: 'delete_invoice',
    description: 'Permanently delete an invoice',
    annotations: { destructiveHint: true },
    scope: 'invoices/delete_invoice',
    execute: async () => { calls.push('delete_invoice'); return { deleted: true } },
  })
  await g.registerTool({
    name: 'pay_invoice',
    description: 'Pay an outstanding invoice',
    annotations: { destructiveHint: true },
    scope: 'money/pay_invoice',
    limit: { field: 'amountCents', max: 100_00 },
    execute: async () => { calls.push('pay_invoice'); return { paid: true } },
  })

  return { g, mc, publicKey, privateKey, setNow: (ms) => { clock = ms }, calls }
}

describe('guard — unguarded tools', () => {
  it('runs a tool with no declared scope without any grant', async () => {
    const { mc, calls } = await harness()
    const res = (await mc.call('list_invoices')) as { ok: boolean }
    expect(res.ok).toBe(true)
    expect(calls).toEqual(['list_invoices'])
  })
})

describe('guard — refusal without a grant', () => {
  it('refuses a scoped tool when no grant is active', async () => {
    const { mc } = await harness()
    const res = (await mc.call('delete_invoice', { id: 'inv-1' })) as { ok: boolean; reason: string }
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('no-active-grant')
  })

  it('never invokes the application handler on refusal', async () => {
    const { mc, calls } = await harness()
    await mc.call('delete_invoice', { id: 'inv-1' })
    expect(calls).toEqual([])
  })
})

describe('guard — grants', () => {
  it('allows a scoped tool once a covering grant is issued', async () => {
    const { g, mc, calls } = await harness()
    await g.grant({ subject: 'agent', scopes: ['invoices/*'], ttlMs: 600_000 })
    const res = (await mc.call('delete_invoice', { id: 'inv-1' })) as { ok: boolean }
    expect(res.ok).toBe(true)
    expect(calls).toEqual(['delete_invoice'])
  })

  it('refuses a tool the grant does not cover', async () => {
    const { g, mc } = await harness()
    await g.grant({ subject: 'agent', scopes: ['invoices/*'], ttlMs: 600_000 })
    const res = (await mc.call('pay_invoice', { amountCents: 100 })) as { ok: boolean; reason: string }
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('scope-not-covered')
  })

  it('refuses once the grant has expired', async () => {
    const { g, mc, setNow } = await harness()
    await g.grant({ subject: 'agent', scopes: ['invoices/*'], ttlMs: 1_000 })
    setNow(Date.now() + 60_000)
    const res = (await mc.call('delete_invoice', { id: 'inv-1' })) as { ok: boolean; reason: string }
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('grant-expired')
  })

  it('refuses immediately after revocation', async () => {
    const { g, mc } = await harness()
    const token = await g.grant({ subject: 'agent', scopes: ['invoices/*'], ttlMs: 600_000 })
    expect(((await mc.call('delete_invoice', { id: 'a' })) as { ok: boolean }).ok).toBe(true)

    g.revoke(token.id)

    const res = (await mc.call('delete_invoice', { id: 'b' })) as { ok: boolean; reason: string }
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('grant-revoked')
  })

  it('omits expired and revoked grants from activeGrants()', async () => {
    const { g, setNow } = await harness()
    const keep = await g.grant({ subject: 'agent', scopes: ['invoices/*'], ttlMs: 600_000 })
    const kill = await g.grant({ subject: 'agent', scopes: ['money/*'], ttlMs: 600_000 })
    g.revoke(kill.id)
    expect(g.activeGrants().map((t) => t.id)).toEqual([keep.id])

    setNow(Date.now() + 700_000)
    expect(g.activeGrants()).toEqual([])
  })
})

describe('guard — spend ceilings', () => {
  it("enforces the tool's own ceiling", async () => {
    const { g, mc } = await harness()
    await g.grant({ subject: 'agent', scopes: ['money/*'], ttlMs: 600_000 })
    const res = (await mc.call('pay_invoice', { amountCents: 500_00 })) as { ok: boolean; reason: string; detail: string }
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('limit-exceeded')
    expect(res.detail).toContain('10000')
  })

  it('lets a cap bound inside the grant tighten the tool ceiling', async () => {
    const { g, mc, calls } = await harness()
    await g.grant({ subject: 'agent', scopes: ['money/*'], caps: { amountCents: 50_00 }, ttlMs: 600_000 })

    const under = (await mc.call('pay_invoice', { amountCents: 40_00 })) as { ok: boolean }
    expect(under.ok).toBe(true)

    const over = (await mc.call('pay_invoice', { amountCents: 60_00 })) as { ok: boolean; reason: string; detail: string }
    expect(over.ok).toBe(false)
    expect(over.reason).toBe('limit-exceeded')
    expect(over.detail).toContain('5000')
    expect(calls).toEqual(['pay_invoice'])
  })

  it('binds the cap inside the signed token rather than page state', async () => {
    const { g } = await harness()
    const token = await g.grant({ subject: 'agent', scopes: ['money/*'], caps: { amountCents: 50_00 }, ttlMs: 600_000 })
    expect(parseCaps(token)).toEqual({ amountCents: 5000 })
    expect(token.scopes.some((s) => s.pathGlob === 'caps/amountCents/5000')).toBe(true)
  })

  it('refuses a non-finite amount rather than coercing it', async () => {
    const { g, mc } = await harness()
    await g.grant({ subject: 'agent', scopes: ['money/*'], ttlMs: 600_000 })
    const res = (await mc.call('pay_invoice', { amountCents: 'not-a-number' })) as { ok: boolean; reason: string }
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('limit-exceeded')
  })
})

describe('guard — replay protection', () => {
  it('accepts a nonce once and refuses the identical call', async () => {
    const { g, mc } = await harness()
    await g.grant({ subject: 'agent', scopes: ['money/*'], ttlMs: 600_000 })

    const first = (await mc.call('pay_invoice', { amountCents: 100, [NONCE_FIELD]: 'n-1' })) as { ok: boolean }
    expect(first.ok).toBe(true)

    const second = (await mc.call('pay_invoice', { amountCents: 100, [NONCE_FIELD]: 'n-1' })) as { ok: boolean; reason: string }
    expect(second.ok).toBe(false)
    expect(second.reason).toBe('replayed-call')
  })

  it('allows repeated calls that carry no nonce', async () => {
    const { g, mc, calls } = await harness()
    await g.grant({ subject: 'agent', scopes: ['money/*'], ttlMs: 600_000 })
    await mc.call('pay_invoice', { amountCents: 100 })
    await mc.call('pay_invoice', { amountCents: 100 })
    expect(calls).toEqual(['pay_invoice', 'pay_invoice'])
  })
})

describe('guard — human confirmation', () => {
  it('refuses when the confirmation handler declines', async () => {
    const { g, mc } = await harness()
    await g.registerTool({
      name: 'wire_funds',
      description: 'Wire funds externally',
      scope: 'money/wire_funds',
      confirm: true,
      execute: async () => ({ sent: true }),
    })
    await g.grant({ subject: 'agent', scopes: ['money/*'], ttlMs: 600_000 })
    const res = (await mc.call('wire_funds', {})) as { ok: boolean; reason: string }
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('confirmation-denied')
  })

  it('refuses a confirm-required tool when no handler is configured', async () => {
    const { g, mc } = await harness()
    await g.registerTool({
      name: 'wire_funds2',
      description: 'Wire funds externally',
      scope: 'money/wire_funds2',
      confirm: true,
      execute: async () => ({ sent: true }),
    })
    await g.grant({ subject: 'agent', scopes: ['money/*'], ttlMs: 600_000 })
    const res = (await mc.call('wire_funds2', {})) as { ok: boolean; reason: string }
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('confirmation-denied')
  })
})

describe('guard — input handling', () => {
  it('strips reserved 7h3 fields before the application handler sees the input', async () => {
    const { g, mc } = await harness()
    let seen: Record<string, unknown> | undefined
    await g.registerTool({
      name: 'echo',
      description: 'Echo input',
      scope: 'debug/echo',
      execute: async (input) => { seen = input; return input },
    })
    await g.grant({ subject: 'agent', scopes: ['debug/*'], ttlMs: 600_000 })

    await mc.call('echo', { real: 'value', [NONCE_FIELD]: 'n-9', [GRANT_FIELD]: '' })
    expect(seen).toEqual({ real: 'value' })
  })
})

describe('guard — receipts', () => {
  it('records both allowed and refused calls in one verifiable chain', async () => {
    const { g, mc, publicKey } = await harness()
    await mc.call('delete_invoice', { id: 'inv-1' })          // refused
    await g.grant({ subject: 'agent', scopes: ['invoices/*'], ttlMs: 600_000 })
    await mc.call('delete_invoice', { id: 'inv-1' })          // allowed

    const receipts = g.receipts.all()
    expect(receipts.map((r) => r.outcome)).toEqual(['refused', 'allowed'])
    expect(receipts[0].reason).toBe('no-active-grant')

    const verification = await verifyChain(receipts, publicKey)
    expect(verification.ok).toBe(true)
    expect(verification.length).toBe(2)
  })

  it('attributes an allowed call to the grant that authorized it', async () => {
    const { g, mc } = await harness()
    const token = await g.grant({ subject: 'agent', scopes: ['invoices/*'], ttlMs: 600_000 })
    await mc.call('delete_invoice', { id: 'inv-1' })
    expect(g.receipts.all()[0].grantId).toBe(token.id)
  })

  it('hashes inputs rather than storing them', async () => {
    const { g, mc } = await harness()
    await g.grant({ subject: 'agent', scopes: ['invoices/*'], ttlMs: 600_000 })
    await mc.call('delete_invoice', { id: 'secret-invoice-id' })
    const receipt = g.receipts.all()[0]
    expect(receipt.inputHash).toMatch(/^[0-9a-f]{64}$/)
    expect(JSON.stringify(receipt)).not.toContain('secret-invoice-id')
  })
})

describe('guard — manifest', () => {
  it('signs the live tool surface and reports scope and method per tool', async () => {
    const { g } = await harness()
    const manifest = await g.manifest()
    expect(manifest.version).toBe('7h3-webmcp-manifest/1')
    expect(manifest.tools.map((t) => t.name).sort()).toEqual(['delete_invoice', 'list_invoices', 'pay_invoice'])
    const listed = manifest.tools.find((t) => t.name === 'list_invoices')!
    expect(listed.method).toBe('READ')
    expect(listed.scope).toBe('public')
    expect(manifest.tools.find((t) => t.name === 'pay_invoice')!.method).toBe('WRITE')
  })
})

describe('guard — direct invocation', () => {
  it('runs the identical guarded wrapper, refusing without a grant', async () => {
    const { g, calls } = await harness()
    const res = (await g.invoke('delete_invoice', { id: 'inv-1' })) as { ok: boolean; reason: string }
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('no-active-grant')
    expect(calls).toEqual([])
  })

  it('allows an invoked call once a grant covers it, and receipts it', async () => {
    const { g, calls } = await harness()
    await g.grant({ subject: 'agent', scopes: ['invoices/*'], ttlMs: 600_000 })
    const res = (await g.invoke('delete_invoice', { id: 'inv-1' })) as { ok: boolean }
    expect(res.ok).toBe(true)
    expect(calls).toEqual(['delete_invoice'])
    expect(g.receipts.all().at(-1)).toMatchObject({ tool: 'delete_invoice', outcome: 'allowed' })
  })

  it('receipts an unknown tool rather than throwing', async () => {
    const { g } = await harness()
    const res = (await g.invoke('no_such_tool')) as { ok: boolean; reason: string }
    expect(res.ok).toBe(false)
    expect(res.reason).toBe('unknown-tool')
    expect(g.receipts.all().at(-1)).toMatchObject({ outcome: 'refused', reason: 'unknown-tool' })
  })
})
