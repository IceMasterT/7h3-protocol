import { describe, it, expect, beforeAll } from 'vitest'
import {
  MAX_CART_LIFETIME_MS,
  MAX_INTENT_LIFETIME_MS,
  MAX_PAYMENT_LIFETIME_MS,
  MemorySpendLedger,
  cartDigest,
  issueCartMandate,
  issueIntentMandate,
  issuePaymentMandate,
  paymentApprovalAction,
  verifyPayment,
  type CartItem,
  type CartMandate,
  type IntentMandate,
  type PaymentMandate,
  type VerifyPaymentOptions,
} from './mandate'
import { issueApproval } from './approval'
import { MemoryReplayStore } from './replayStores'
import { generateEd25519KeypairBase64Url, signCanonicalPayloadEd25519 } from './protocol'
import { stableStringify } from './actionBinding'

const NOW = 1_800_000_000_000

type Keys = { publicKey: string; privateKey: string }
let payer: Keys
let merchant: Keys
let agent: Keys
let intruder: Keys
let approver: Keys

beforeAll(async () => {
  payer = await generateEd25519KeypairBase64Url()
  merchant = await generateEd25519KeypairBase64Url()
  agent = await generateEd25519KeypairBase64Url()
  intruder = await generateEd25519KeypairBase64Url()
  approver = await generateEd25519KeypairBase64Url()
})

const items: CartItem[] = [
  { sku: 'flight-123', description: 'Economy fare', category: 'travel', quantity: 1, unitMinor: 24_900 },
  { sku: 'bag-1', category: 'travel', quantity: 2, unitMinor: 3_500 },
]

const intent = (over: Partial<Parameters<typeof issueIntentMandate>[0]['constraints']> = {}, extra: Partial<Parameters<typeof issueIntentMandate>[0]> = {}) =>
  issueIntentMandate({
    payerPrivateKey: payer.privateKey,
    payer: 'alice',
    agent: 'agent.travel',
    constraints: { currency: 'USD', maxTotalMinor: 100_000, maxPerPurchaseMinor: 50_000, merchants: ['airline.example'], categories: ['travel'], ...over },
    lifetimeMs: 7 * 24 * 3_600_000,
    now: NOW,
    ...extra,
  })

const cart = (i: IntentMandate, over: Partial<Parameters<typeof issueCartMandate>[0]> = {}) =>
  issueCartMandate({ merchantPrivateKey: merchant.privateKey, merchant: 'airline.example', intentId: i.id, currency: 'USD', items, now: NOW, ...over })

const payment = (i: IntentMandate, c: CartMandate, over: Partial<Parameters<typeof issuePaymentMandate>[0]> = {}) =>
  issuePaymentMandate({ agentPrivateKey: agent.privateKey, agent: 'agent.travel', intent: i, cart: c, now: NOW, ...over })


/** Re-sign an edited copy of a payment mandate with the agent's real key: a validly signed mandate that breaks a rule. */
async function resignPayment(p: PaymentMandate, edit: Partial<PaymentMandate>): Promise<PaymentMandate> {
  const { signature: _s, ...rest } = p
  void _s
  const e = { ...rest, ...edit }
  const canon = stableStringify({
    version: e.version, kind: e.kind, id: e.id, intentId: e.intentId, cartId: e.cartId, cartDigest: e.cartDigest, merchant: e.merchant,
    agent: e.agent, amountMinor: e.amountMinor, currency: e.currency, issuedAt: e.issuedAt, expiresAt: e.expiresAt, keyId: e.keyId,
  })
  return { ...e, signature: await signCanonicalPayloadEd25519(canon, agent.privateKey) }
}

/** Re-sign an edited copy of a cart with the merchant's real key. */
async function resignCart(c: CartMandate, edit: Partial<CartMandate>): Promise<CartMandate> {
  const { signature: _s, ...rest } = c
  void _s
  const e = { ...rest, ...edit }
  const canon = stableStringify({
    version: e.version, kind: e.kind, id: e.id, intentId: e.intentId, merchant: e.merchant, currency: e.currency,
    items: e.items.map((x) => ({ sku: x.sku, description: x.description ?? null, category: x.category ?? null, quantity: x.quantity, unitMinor: x.unitMinor })),
    totalMinor: e.totalMinor, issuedAt: e.issuedAt, expiresAt: e.expiresAt, keyId: e.keyId,
  })
  return { ...e, signature: await signCanonicalPayloadEd25519(canon, merchant.privateKey) }
}

const registries = () => ({
  payerKeys: { getPublicKey: async (id: string) => (id === 'alice' ? payer.publicKey : null) },
  merchantKeys: { getPublicKey: async (id: string) => (id === 'airline.example' ? merchant.publicKey : null) },
  agentKeys: { getPublicKey: async (id: string) => (id === 'agent.travel' ? agent.publicKey : null) },
})

async function chain(constraints = {}) {
  const i = await intent(constraints)
  const c = await cart(i)
  const p = await payment(i, c)
  return { i, c, p }
}

const opts = (i: IntentMandate, c: CartMandate, p: PaymentMandate, over: Partial<VerifyPaymentOptions> = {}): VerifyPaymentOptions => ({
  intent: i,
  cart: c,
  payment: p,
  ...registries(),
  ledger: new MemorySpendLedger(),
  expectedPayer: 'alice',
  expectedMerchant: 'airline.example',
  now: NOW + 1000,
  ...over,
})
const run = async (over: (x: { i: IntentMandate; c: CartMandate; p: PaymentMandate }) => Partial<VerifyPaymentOptions> = () => ({}), constraints = {}) => {
  const x = await chain(constraints)
  return verifyPayment(opts(x.i, x.c, x.p, over(x)))
}
const reason = async (r: ReturnType<typeof run>) => {
  const v = await r
  return v.ok ? 'ok' : v.reason
}

describe('the happy path', () => {
  it('verifies intent, cart and payment and records the spend', async () => {
    const x = await chain()
    const ledger = new MemorySpendLedger()
    const r = await verifyPayment(opts(x.i, x.c, x.p, { ledger }))
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.spentMinor).toBe(24_900 + 2 * 3_500)
    expect(await ledger.spent(x.i.id)).toBe(31_900)
  })

  it('computes the cart total from its items, in integer minor units', async () => {
    const i = await intent()
    expect((await cart(i)).totalMinor).toBe(31_900)
  })
})

describe('issuing validates its inputs', () => {
  it('refuses fractional, negative, unsafe and non-positive money', async () => {
    await expect(intent({ maxTotalMinor: 100.5 })).rejects.toThrow()
    await expect(intent({ maxTotalMinor: 0 })).rejects.toThrow()
    await expect(intent({ maxTotalMinor: -5 })).rejects.toThrow()
    await expect(intent({ maxTotalMinor: 2 ** 60 })).rejects.toThrow()
    await expect(intent({ maxPerPurchaseMinor: 200_000 })).rejects.toThrow(/no larger/)
    const i = await intent()
    await expect(cart(i, { items: [{ sku: 'x', quantity: 1, unitMinor: 0.1 }] })).rejects.toThrow()
    await expect(cart(i, { items: [{ sku: 'x', quantity: 0, unitMinor: 100 }] })).rejects.toThrow()
    await expect(cart(i, { items: [{ sku: 'x', quantity: 1, unitMinor: -100 }] })).rejects.toThrow()
    await expect(cart(i, { items: [{ sku: 'x', quantity: 2 ** 40, unitMinor: 2 ** 40 }] })).rejects.toThrow()
    await expect(cart(i, { items: [] })).rejects.toThrow()
  })

  it('refuses bad currencies, identifiers, empty lists and over-long lifetimes', async () => {
    await expect(intent({ currency: 'usd' })).rejects.toThrow(/ISO 4217/)
    await expect(intent({ currency: 'DOLLARS' })).rejects.toThrow()
    await expect(intent({ merchants: [] })).rejects.toThrow()
    await expect(intent({ categories: ['has space'] })).rejects.toThrow()
    await expect(intent({}, { lifetimeMs: MAX_INTENT_LIFETIME_MS + 1 })).rejects.toThrow()
    await expect(intent({}, { payer: '' })).rejects.toThrow()
    const i = await intent()
    await expect(cart(i, { lifetimeMs: MAX_CART_LIFETIME_MS + 1 })).rejects.toThrow()
    await expect(payment(i, await cart(i), { lifetimeMs: MAX_PAYMENT_LIFETIME_MS + 1 })).rejects.toThrow()
  })
})

describe('tampering', () => {
  it('any edit to a signed mandate invalidates its signature', async () => {
    expect(await reason(run(({ i, c, p }) => ({ intent: { ...i, constraints: { ...i.constraints, maxTotalMinor: 10_000_000 } }, cart: c, payment: p })))).toBe('invalid-intent-signature')
    expect(await reason(run(({ c }) => ({ cart: { ...c, items: [{ ...c.items[0], unitMinor: 1 }, c.items[1]] } })))).toBe('invalid-cart-signature')
    expect(await reason(run(({ p }) => ({ payment: { ...p, amountMinor: 1 } })))).toBe('invalid-payment-signature')
    expect(await reason(run(({ c }) => ({ cart: { ...c, totalMinor: 1 } })))).toBe('invalid-cart-signature')
  })

  it('a signature made with the wrong kind of key is refused: a merchant cannot mint an intent', async () => {
    const forged = await intent({}, { payerPrivateKey: merchant.privateKey })
    const c = await cart(forged)
    expect(await verifyPayment(opts(forged, c, await payment(forged, c)))).toMatchObject({ ok: false, reason: 'invalid-intent-signature' })
    const i = await intent()
    const badCart = await cart(i, { merchantPrivateKey: agent.privateKey })
    expect(await verifyPayment(opts(i, badCart, await payment(i, badCart)))).toMatchObject({ ok: false, reason: 'invalid-cart-signature' })
    const c2 = await cart(i)
    const badPay = await payment(i, c2, { agentPrivateKey: intruder.privateKey })
    expect(await verifyPayment(opts(i, c2, badPay))).toMatchObject({ ok: false, reason: 'invalid-payment-signature' })
  })

  it('a merchant that signs a cart whose total does not match its items is caught', async () => {
    const i = await intent()
    const good = await cart(i)
    const { signature: _s, ...rest } = good
    void _s
    const lying = { ...rest, totalMinor: 1_00 }
    const canon = stableStringify({
      version: lying.version, kind: lying.kind, id: lying.id, intentId: lying.intentId, merchant: lying.merchant, currency: lying.currency,
      items: lying.items.map((x) => ({ sku: x.sku, description: x.description ?? null, category: x.category ?? null, quantity: x.quantity, unitMinor: x.unitMinor })),
      totalMinor: lying.totalMinor, issuedAt: lying.issuedAt, expiresAt: lying.expiresAt, keyId: lying.keyId,
    })
    const badCart: CartMandate = { ...lying, signature: await signCanonicalPayloadEd25519(canon, merchant.privateKey) }
    expect(await verifyPayment(opts(i, badCart, await payment(i, badCart)))).toMatchObject({ ok: false, reason: 'cart-total-wrong' })
  })

  it('a payment for a different amount than the cart is refused, and so is one bound to a different cart', async () => {
    const i = await intent()
    const c = await cart(i)
    const other = await cart(i, { items: [{ sku: 'flight-123', category: 'travel', quantity: 1, unitMinor: 1_000 }] })
    const p = await payment(i, c)
    expect(await verifyPayment(opts(i, other, p))).toMatchObject({ ok: false, reason: 'cart-mismatch' })
    // Agent signs a payment for less than the cart: the amount must equal the cart total.
    const { signature: _s, ...rest } = p
    void _s
    const low = { ...rest, amountMinor: 100 }
    const canon = stableStringify({ version: low.version, kind: low.kind, id: low.id, intentId: low.intentId, cartId: low.cartId, cartDigest: low.cartDigest, merchant: low.merchant, agent: low.agent, amountMinor: low.amountMinor, currency: low.currency, issuedAt: low.issuedAt, expiresAt: low.expiresAt, keyId: low.keyId })
    const lowPay: PaymentMandate = { ...low, signature: await signCanonicalPayloadEd25519(canon, agent.privateKey) }
    expect(await verifyPayment(opts(i, c, lowPay))).toMatchObject({ ok: false, reason: 'amount-mismatch' })
  })

  it('the cart digest changes with any signed byte', async () => {
    const i = await intent()
    const c = await cart(i)
    expect(await cartDigest(c)).toBe(await cartDigest({ ...c }))
    const flipped = (c.signature[0] === 'A' ? 'B' : 'A') + c.signature.slice(1) // always a different string
    expect(await cartDigest({ ...c, signature: flipped })).not.toBe(await cartDigest(c))
  })
})

describe('the chain must hang together', () => {
  it('rejects a mandate for another payer, merchant or agent', async () => {
    expect(await reason(run(() => ({ expectedPayer: 'bob' })))).toBe('payer-mismatch')
    expect(await reason(run(() => ({ expectedMerchant: 'other.example' })))).toBe('merchant-mismatch')
    const i = await intent()
    const c = await cart(i)
    const stolen = await payment(i, c, { agent: 'agent.other', agentPrivateKey: intruder.privateKey })
    expect(await verifyPayment(opts(i, c, stolen, { agentKeys: { getPublicKey: async () => intruder.publicKey } }))).toMatchObject({ ok: false, reason: 'agent-mismatch' })
  })

  it('rejects a cart or payment that belongs to a different intent', async () => {
    const i1 = await intent()
    const i2 = await intent()
    const c2 = await cart(i2)
    expect(await verifyPayment(opts(i1, c2, await payment(i1, c2)))).toMatchObject({ ok: false, reason: 'intent-mismatch' })
    const c1 = await cart(i1)
    const p1 = await payment(i1, c1)
    expect(await verifyPayment(opts(i1, await cart(i1), p1))).toMatchObject({ ok: false, reason: 'cart-mismatch' })
  })

  it('rejects mixed currencies', async () => {
    const i = await intent()
    const c = await cart(i, { currency: 'EUR' })
    expect(await verifyPayment(opts(i, c, await payment(i, c)))).toMatchObject({ ok: false, reason: 'currency-mismatch' })
  })

  it('rejects unknown signers', async () => {
    expect(await reason(run(() => ({ payerKeys: { getPublicKey: async () => null } })))).toBe('no-payer-key')
    expect(await reason(run(() => ({ merchantKeys: { getPublicKey: async () => null } })))).toBe('no-merchant-key')
    expect(await reason(run(() => ({ agentKeys: { getPublicKey: async () => null } })))).toBe('no-agent-key')
  })

  it('rejects malformed input without throwing', async () => {
    const x = await chain()
    expect(await verifyPayment(opts(null as never, x.c, x.p))).toMatchObject({ ok: false, reason: 'malformed' })
    expect(await verifyPayment(opts(x.i, { ...x.c, items: 'nope' as never }, x.p))).toMatchObject({ ok: false, reason: 'malformed' })
    expect(await verifyPayment(opts({ ...x.i, version: 'x' as never }, x.c, x.p))).toMatchObject({ ok: false, reason: 'unsupported-version' })
  })
})

describe('a validly signed payment that still breaks a rule', () => {
  it('a second cart with the same id but different content is caught by the digest', async () => {
    const i = await intent()
    const original = await cart(i)
    const p = await payment(i, original)
    const swapped = await resignCart(original, { items: [{ sku: 'flight-123', category: 'travel', quantity: 1, unitMinor: 1 }], totalMinor: 1 })
    expect(swapped.id).toBe(original.id)
    expect(await verifyPayment(opts(i, swapped, p))).toMatchObject({ ok: false, reason: 'cart-mismatch', detail: 'digest' })
  })

  it('a payment that names a different cart id than the one presented is refused even if the digest matches', async () => {
    const x = await chain()
    const wrongId = await resignPayment(x.p, { cartId: 'cart-somewhere-else' })
    expect(await verifyPayment(opts(x.i, x.c, wrongId))).toMatchObject({ ok: false, reason: 'cart-mismatch' })
  })

  it('a payment naming a different merchant than the cart and the processor is refused', async () => {
    const x = await chain()
    const rerouted = await resignPayment(x.p, { merchant: 'attacker.example' })
    expect(await verifyPayment(opts(x.i, x.c, rerouted))).toMatchObject({ ok: false, reason: 'merchant-mismatch' })
  })

  it('a payment mandate that outlives the maximum lifetime is refused', async () => {
    const x = await chain()
    const long = await resignPayment(x.p, { expiresAt: x.p.issuedAt + MAX_PAYMENT_LIFETIME_MS + 1 })
    expect(await verifyPayment(opts(x.i, x.c, long))).toMatchObject({ ok: false, reason: 'lifetime-too-long', detail: 'payment' })
  })
})

describe('lifetimes', () => {
  it('rejects expired, not-yet-valid and over-long mandates', async () => {
    const x = await chain()
    const at = (now: number) => verifyPayment(opts(x.i, x.c, x.p, { now }))
    expect(await at(NOW + 6 * 60_000)).toMatchObject({ ok: false, reason: 'payment-expired' })
    expect(await at(NOW + 20 * 60_000)).toMatchObject({ ok: false }) // payment (5 min) is the shortest-lived
    expect(await at(NOW - 5 * 60_000)).toMatchObject({ ok: false, reason: 'not-yet-valid' })
    const short = await issueIntentMandate({ payerPrivateKey: payer.privateKey, payer: 'alice', agent: 'agent.travel', constraints: { currency: 'USD', maxTotalMinor: 100_000 }, lifetimeMs: 1000, now: NOW })
    const c = await cart(short)
    expect(await verifyPayment(opts(short, c, await payment(short, c), { now: NOW + 2000 }))).toMatchObject({ ok: false, reason: 'intent-expired' })
    const shortCart = await cart(await intent(), { lifetimeMs: 1000 })
    const i = await intent()
    const sc = await cart(i, { lifetimeMs: 1000 })
    void shortCart
    expect(await verifyPayment(opts(i, sc, await payment(i, sc), { now: NOW + 2000 }))).toMatchObject({ ok: false, reason: 'cart-expired' })
  })
})

describe('the intent constraints', () => {
  it('enforces the merchant allow-list', async () => {
    expect(await reason(run(() => ({}), { merchants: ['other.example'] }))).toBe('merchant-not-allowed')
  })

  it('enforces categories, and an item with no category is not allowed', async () => {
    expect(await reason(run(() => ({}), { categories: ['groceries'] }))).toBe('category-not-allowed')
    const i = await intent()
    const c = await cart(i, { items: [{ sku: 'mystery', quantity: 1, unitMinor: 100 }] })
    expect(await verifyPayment(opts(i, c, await payment(i, c)))).toMatchObject({ ok: false, reason: 'category-not-allowed', detail: 'mystery' })
  })

  it('enforces the per-purchase limit', async () => {
    expect(await reason(run(() => ({}), { maxPerPurchaseMinor: 30_000 }))).toBe('exceeds-per-purchase-limit')
  })

  it('enforces the total limit for a single purchase', async () => {
    expect(await reason(run(() => ({}), { maxTotalMinor: 30_000, maxPerPurchaseMinor: undefined }))).toBe('exceeds-total-limit')
  })

  it('enforces the CUMULATIVE ceiling across purchases', async () => {
    const i = await intent({ maxTotalMinor: 70_000, maxPerPurchaseMinor: undefined })
    const ledger = new MemorySpendLedger()
    const pay = async () => {
      const c = await cart(i)
      return verifyPayment(opts(i, c, await payment(i, c), { ledger }))
    }
    expect((await pay()).ok).toBe(true) // 31,900
    expect((await pay()).ok).toBe(true) // 63,800
    expect(await pay()).toMatchObject({ ok: false, reason: 'exceeds-total-limit', detail: 'cumulative' }) // would be 95,700
    expect(await ledger.spent(i.id)).toBe(63_800)
  })

  it('two concurrent payments that together exceed the ceiling: exactly one succeeds', async () => {
    const i = await intent({ maxTotalMinor: 40_000, maxPerPurchaseMinor: undefined })
    const ledger = new MemorySpendLedger()
    const attempt = async () => {
      const c = await cart(i)
      return verifyPayment(opts(i, c, await payment(i, c), { ledger }))
    }
    const results = await Promise.all([attempt(), attempt(), attempt()])
    expect(results.filter((r) => r.ok).length).toBe(1)
    expect(await ledger.spent(i.id)).toBe(31_900)
  })

  it('charging the same payment twice counts once and is refused the second time', async () => {
    const x = await chain()
    const ledger = new MemorySpendLedger()
    expect((await verifyPayment(opts(x.i, x.c, x.p, { ledger }))).ok).toBe(true)
    expect(await verifyPayment(opts(x.i, x.c, x.p, { ledger }))).toMatchObject({ ok: false, reason: 'already-charged' })
    expect(await ledger.spent(x.i.id)).toBe(31_900)
  })

  it('a failed verification never records spend', async () => {
    const x = await chain({ merchants: ['other.example'] })
    const ledger = new MemorySpendLedger()
    await verifyPayment(opts(x.i, x.c, x.p, { ledger }))
    expect(await ledger.spent(x.i.id)).toBe(0)
  })
})

describe('human approval for large purchases', () => {
  const approverKeys = () => ({ getPublicKey: async (id: string) => (id === 'alice' ? approver.publicKey : null) })
  const grantFor = (p: PaymentMandate, over: Partial<Parameters<typeof issueApproval>[0]> = {}) =>
    issueApproval({ approverPrivateKey: approver.privateKey, approverId: 'alice', subject: 'agent.travel', action: paymentApprovalAction(p), now: NOW, ...over })
  const approvalOpts = (grant: Awaited<ReturnType<typeof grantFor>> | null, store = new MemoryReplayStore({ now: () => NOW })) => ({
    grant, approverKeys: approverKeys(), allowedApprovers: ['alice'], replayStore: store,
  })

  it('requires an approval above the threshold and none below it', async () => {
    const x = await chain({ requireApprovalAboveMinor: 20_000 })
    expect(await verifyPayment(opts(x.i, x.c, x.p))).toMatchObject({ ok: false, reason: 'approval-required' })
    const small = await chain({ requireApprovalAboveMinor: 50_000 })
    expect((await verifyPayment(opts(small.i, small.c, small.p))).ok).toBe(true)
  })

  it('accepts a valid grant for this payment and reports who approved', async () => {
    const x = await chain({ requireApprovalAboveMinor: 20_000 })
    const r = await verifyPayment(opts(x.i, x.c, x.p, { approval: approvalOpts(await grantFor(x.p)) }))
    expect(r).toMatchObject({ ok: true, approvedBy: 'alice' })
  })

  it('refuses a grant made for a different payment, agent, or by a non-approver', async () => {
    const x = await chain({ requireApprovalAboveMinor: 20_000 })
    const other = await chain({ requireApprovalAboveMinor: 20_000 })
    const wrongPayment = await grantFor(other.p)
    expect(await verifyPayment(opts(x.i, x.c, x.p, { approval: approvalOpts(wrongPayment) }))).toMatchObject({ ok: false, reason: 'approval-invalid', detail: 'action-mismatch' })
    const wrongAgent = await grantFor(x.p, { subject: 'agent.other' })
    expect(await verifyPayment(opts(x.i, x.c, x.p, { approval: approvalOpts(wrongAgent) }))).toMatchObject({ ok: false, reason: 'approval-invalid', detail: 'subject-mismatch' })
    const forged = await grantFor(x.p, { approverPrivateKey: intruder.privateKey })
    expect(await verifyPayment(opts(x.i, x.c, x.p, { approval: approvalOpts(forged) }))).toMatchObject({ ok: false, reason: 'approval-invalid', detail: 'invalid-signature' })
  })

  it('a failed approval gives the reservation back, so the ceiling is not eaten by refused payments', async () => {
    const x = await chain({ requireApprovalAboveMinor: 20_000 })
    const ledger = new MemorySpendLedger()
    await verifyPayment(opts(x.i, x.c, x.p, { ledger }))
    expect(await ledger.spent(x.i.id)).toBe(0)
    await verifyPayment(opts(x.i, x.c, x.p, { ledger, approval: approvalOpts(null) }))
    expect(await ledger.spent(x.i.id)).toBe(0)
    // ...including when a grant IS presented but is invalid.
    const forged = await grantFor(x.p, { approverPrivateKey: intruder.privateKey })
    expect(await verifyPayment(opts(x.i, x.c, x.p, { ledger, approval: approvalOpts(forged) }))).toMatchObject({ reason: 'approval-invalid' })
    expect(await ledger.spent(x.i.id)).toBe(0)
    // and the payment can still go through afterwards with a good grant.
    expect((await verifyPayment(opts(x.i, x.c, x.p, { ledger, approval: approvalOpts(await grantFor(x.p)) }))).ok).toBe(true)
  })

  it('a payment that would break the ceiling does not consume its approval', async () => {
    const i = await intent({ maxTotalMinor: 40_000, maxPerPurchaseMinor: undefined, requireApprovalAboveMinor: 20_000 })
    const ledger = new MemorySpendLedger()
    await ledger.reserve({ intentId: i.id, paymentId: 'earlier', amountMinor: 30_000, ceilingMinor: 40_000 })
    const c = await cart(i)
    const p = await payment(i, c)
    const store = new MemoryReplayStore({ now: () => NOW })
    const r = await verifyPayment(opts(i, c, p, { ledger, approval: approvalOpts(await grantFor(p), store) }))
    expect(r).toMatchObject({ ok: false, reason: 'exceeds-total-limit' })
    expect(store.size).toBe(0) // the approval was not spent
  })

  it('an approval is single use', async () => {
    const x = await chain({ requireApprovalAboveMinor: 20_000 })
    const store = new MemoryReplayStore({ now: () => NOW })
    const grant = await grantFor(x.p)
    expect((await verifyPayment(opts(x.i, x.c, x.p, { approval: approvalOpts(grant, store) }))).ok).toBe(true)
    expect(await verifyPayment(opts(x.i, x.c, x.p, { ledger: new MemorySpendLedger(), approval: approvalOpts(grant, store) }))).toMatchObject({
      ok: false,
      reason: 'approval-invalid',
      detail: 'already-used',
    })
  })
})

describe('MemorySpendLedger', () => {
  it('reserves, is idempotent per payment, respects the ceiling, and releases', async () => {
    const l = new MemorySpendLedger()
    const args = (paymentId: string, amountMinor: number) => ({ intentId: 'i', paymentId, amountMinor, ceilingMinor: 100 })
    expect(await l.reserve(args('a', 60))).toBe('reserved')
    expect(await l.reserve(args('a', 60))).toBe('duplicate')
    expect(await l.reserve(args('b', 41))).toBe('exceeds-ceiling')
    expect(await l.reserve(args('b', 40))).toBe('reserved')
    expect(await l.spent('i')).toBe(100)
    await l.release({ intentId: 'i', paymentId: 'a' })
    await l.release({ intentId: 'i', paymentId: 'a' }) // idempotent
    expect(await l.spent('i')).toBe(40)
    expect(await l.reserve(args('c', 60))).toBe('reserved')
  })

  it('keeps intents separate and rejects non-integer amounts', async () => {
    const l = new MemorySpendLedger()
    expect(await l.reserve({ intentId: 'x', paymentId: 'p', amountMinor: 90, ceilingMinor: 100 })).toBe('reserved')
    expect(await l.reserve({ intentId: 'y', paymentId: 'p', amountMinor: 90, ceilingMinor: 100 })).toBe('reserved')
    await expect(l.reserve({ intentId: 'z', paymentId: 'p', amountMinor: 1.5, ceilingMinor: 100 })).rejects.toThrow()
    expect(await l.spent('nothing')).toBe(0)
  })
})
