/**
 * Payment mandates: verifiable authority for an agent to spend someone's money.
 *
 * An agent that can pay is an agent that can be tricked into paying. A mandate chain
 * makes "the agent was allowed to buy this" something a merchant or payment processor
 * can check cryptographically, and makes the limits real:
 *
 *   1. **Intent mandate** — signed by the PAYER. Says which agent may spend, up to what
 *      total and per purchase, in which currency, at which merchants, in which
 *      categories, until when, and whether a human must approve large purchases.
 *   2. **Cart mandate** — signed by the MERCHANT. The exact items, quantities, unit
 *      prices and total being sold, bound to one intent. The agent cannot inflate a
 *      price the merchant did not sign, and the merchant cannot be bound to a price it
 *      did not quote.
 *   3. **Payment mandate** — signed by the AGENT. The final instruction to charge: it
 *      names the intent, the cart (by digest), the amount and the merchant.
 *
 * `verifyPayment` checks the whole chain and the arithmetic (it recomputes the cart
 * total rather than trusting it), enforces the intent's constraints, requires a human
 * approval when the intent says so, and records the spend in a {@link SpendLedger} so the
 * cumulative ceiling holds across many purchases and a payment cannot be charged twice.
 *
 * MODELLED ON, NOT COMPATIBLE WITH. The intent → cart → payment structure follows the
 * shape agentic-commerce protocols such as AP2 use, but these are 7h3's own signed
 * documents, not their wire formats or credentials. No payment rail is contacted; this
 * module decides whether a charge is authorized and leaves moving the money to you.
 *
 * All amounts are integers in minor units (cents). Floating point never touches money.
 */

import { signCanonicalPayloadEd25519, verifyCanonicalPayloadEd25519, randomHex, MAX_CLOCK_SKEW_MS } from './protocol'
import { sha256Hex, stableStringify } from './actionBinding'
import { verifyApproval, type ApprovalGrant, type ApproverKeyLookup } from './approval'
import type { KeyRegistry } from './keyRegistry'
import type { ReplayStore } from './replayStores'

export const MANDATE_VERSION = '7h3-mandate/1'
/** A cart is a quote: it should be acted on now. */
export const MAX_CART_LIFETIME_MS = 60 * 60_000
/** A payment mandate is an instruction to charge now. */
export const MAX_PAYMENT_LIFETIME_MS = 15 * 60_000
export const MAX_INTENT_LIFETIME_MS = 30 * 24 * 60 * 60_000

const CURRENCY = /^[A-Z]{3}$/
const NAME = /^[A-Za-z0-9@._:/#-]{1,256}$/

export interface IntentConstraints {
  /** ISO 4217 currency code. Every amount under this intent is in it. */
  currency: string
  /** Cumulative ceiling across ALL purchases under this intent, minor units. */
  maxTotalMinor: number
  /** Ceiling for a single purchase, minor units. */
  maxPerPurchaseMinor?: number
  /** Merchants the agent may pay. When omitted, any merchant the payment processor accepts. */
  merchants?: string[]
  /** Item categories the agent may buy. When set, every cart item must carry an allowed category. */
  categories?: string[]
  /** A purchase above this amount needs a human approval grant. */
  requireApprovalAboveMinor?: number
}

export interface IntentMandate {
  version: typeof MANDATE_VERSION
  kind: 'intent'
  id: string
  /** Whose money it is. */
  payer: string
  /** The agent that may spend it. */
  agent: string
  constraints: IntentConstraints
  issuedAt: number
  expiresAt: number
  keyId: string
  signature: string
}

export interface CartItem {
  sku: string
  description?: string
  category?: string
  quantity: number
  unitMinor: number
}

export interface CartMandate {
  version: typeof MANDATE_VERSION
  kind: 'cart'
  id: string
  intentId: string
  merchant: string
  currency: string
  items: CartItem[]
  totalMinor: number
  issuedAt: number
  expiresAt: number
  keyId: string
  signature: string
}

export interface PaymentMandate {
  version: typeof MANDATE_VERSION
  kind: 'payment'
  id: string
  intentId: string
  cartId: string
  /** SHA-256 of the cart's canonical form: binds the payment to those exact items and prices. */
  cartDigest: string
  merchant: string
  agent: string
  amountMinor: number
  currency: string
  issuedAt: number
  expiresAt: number
  keyId: string
  signature: string
}

const isMoney = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0
const isPositive = (n: unknown): n is number => isMoney(n) && n > 0

function checkedTotal(items: readonly CartItem[]): number | null {
  let total = 0
  for (const it of items) {
    if (!isPositive(it.quantity) || !isMoney(it.unitMinor)) return null
    const line = it.quantity * it.unitMinor
    if (!Number.isSafeInteger(line)) return null
    total += line
    if (!Number.isSafeInteger(total)) return null
  }
  return total
}

// ---------------------------------------------------------------------------
// Canonical forms and digests
// ---------------------------------------------------------------------------

const canonIntent = (m: Omit<IntentMandate, 'signature'>): string =>
  stableStringify({
    version: m.version,
    kind: m.kind,
    id: m.id,
    payer: m.payer,
    agent: m.agent,
    constraints: {
      currency: m.constraints.currency,
      maxTotalMinor: m.constraints.maxTotalMinor,
      maxPerPurchaseMinor: m.constraints.maxPerPurchaseMinor ?? null,
      merchants: m.constraints.merchants ?? null,
      categories: m.constraints.categories ?? null,
      requireApprovalAboveMinor: m.constraints.requireApprovalAboveMinor ?? null,
    },
    issuedAt: m.issuedAt,
    expiresAt: m.expiresAt,
    keyId: m.keyId,
  })

const canonCart = (m: Omit<CartMandate, 'signature'>): string =>
  stableStringify({
    version: m.version,
    kind: m.kind,
    id: m.id,
    intentId: m.intentId,
    merchant: m.merchant,
    currency: m.currency,
    items: m.items.map((i) => ({
      sku: i.sku,
      description: i.description ?? null,
      category: i.category ?? null,
      quantity: i.quantity,
      unitMinor: i.unitMinor,
    })),
    totalMinor: m.totalMinor,
    issuedAt: m.issuedAt,
    expiresAt: m.expiresAt,
    keyId: m.keyId,
  })

const canonPayment = (m: Omit<PaymentMandate, 'signature'>): string =>
  stableStringify({
    version: m.version,
    kind: m.kind,
    id: m.id,
    intentId: m.intentId,
    cartId: m.cartId,
    cartDigest: m.cartDigest,
    merchant: m.merchant,
    agent: m.agent,
    amountMinor: m.amountMinor,
    currency: m.currency,
    issuedAt: m.issuedAt,
    expiresAt: m.expiresAt,
    keyId: m.keyId,
  })

/** The digest a payment mandate commits to: SHA-256 of the cart's signed canonical form. */
export function cartDigest(cart: CartMandate): Promise<string> {
  const { signature, ...rest } = cart
  return sha256Hex(`${canonCart(rest)}.${signature}`)
}

// ---------------------------------------------------------------------------
// Issuing
// ---------------------------------------------------------------------------

function checkLifetime(ttlMs: number, max: number, what: string): void {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0 || ttlMs > max) throw new Error(`${what}: lifetime must be in (0, ${max}] ms`)
}

export async function issueIntentMandate(opts: {
  payerPrivateKey: string
  payer: string
  agent: string
  constraints: IntentConstraints
  lifetimeMs: number
  keyId?: string
  now?: number
}): Promise<IntentMandate> {
  checkLifetime(opts.lifetimeMs, MAX_INTENT_LIFETIME_MS, 'issueIntentMandate')
  if (!NAME.test(opts.payer) || !NAME.test(opts.agent)) throw new Error('issueIntentMandate: payer and agent are required identifiers')
  const c = opts.constraints
  if (!CURRENCY.test(c.currency)) throw new Error('issueIntentMandate: currency must be an ISO 4217 code such as USD')
  if (!isPositive(c.maxTotalMinor)) throw new Error('issueIntentMandate: maxTotalMinor must be a positive integer')
  if (c.maxPerPurchaseMinor !== undefined && (!isPositive(c.maxPerPurchaseMinor) || c.maxPerPurchaseMinor > c.maxTotalMinor)) {
    throw new Error('issueIntentMandate: maxPerPurchaseMinor must be a positive integer no larger than maxTotalMinor')
  }
  if (c.requireApprovalAboveMinor !== undefined && !isMoney(c.requireApprovalAboveMinor)) throw new Error('issueIntentMandate: requireApprovalAboveMinor must be a non-negative integer')
  for (const list of [c.merchants, c.categories]) {
    if (list !== undefined && (list.length === 0 || list.some((x) => !NAME.test(x)))) throw new Error('issueIntentMandate: merchants and categories must be non-empty lists of identifiers')
  }
  const now = opts.now ?? Date.now()
  const unsigned: Omit<IntentMandate, 'signature'> = {
    version: MANDATE_VERSION,
    kind: 'intent',
    id: `intent-${now}-${randomHex(8)}`,
    payer: opts.payer,
    agent: opts.agent,
    constraints: { ...c, ...(c.merchants ? { merchants: [...c.merchants] } : {}), ...(c.categories ? { categories: [...c.categories] } : {}) },
    issuedAt: now,
    expiresAt: now + opts.lifetimeMs,
    keyId: opts.keyId ?? `${opts.payer}-key`,
  }
  return { ...unsigned, signature: await signCanonicalPayloadEd25519(canonIntent(unsigned), opts.payerPrivateKey) }
}

export async function issueCartMandate(opts: {
  merchantPrivateKey: string
  merchant: string
  intentId: string
  currency: string
  items: CartItem[]
  lifetimeMs?: number
  keyId?: string
  now?: number
}): Promise<CartMandate> {
  const lifetime = opts.lifetimeMs ?? 15 * 60_000
  checkLifetime(lifetime, MAX_CART_LIFETIME_MS, 'issueCartMandate')
  if (!NAME.test(opts.merchant) || !NAME.test(opts.intentId)) throw new Error('issueCartMandate: merchant and intentId are required identifiers')
  if (!CURRENCY.test(opts.currency)) throw new Error('issueCartMandate: currency must be an ISO 4217 code')
  if (opts.items.length === 0 || opts.items.length > 200) throw new Error('issueCartMandate: 1..200 items are required')
  for (const it of opts.items) {
    if (!NAME.test(it.sku)) throw new Error('issueCartMandate: every item needs a sku')
    if (it.category !== undefined && !NAME.test(it.category)) throw new Error('issueCartMandate: invalid category')
  }
  const total = checkedTotal(opts.items)
  if (total === null) throw new Error('issueCartMandate: quantities must be positive integers and prices non-negative integers (minor units)')
  const now = opts.now ?? Date.now()
  const unsigned: Omit<CartMandate, 'signature'> = {
    version: MANDATE_VERSION,
    kind: 'cart',
    id: `cart-${now}-${randomHex(8)}`,
    intentId: opts.intentId,
    merchant: opts.merchant,
    currency: opts.currency,
    items: opts.items.map((i) => ({ ...i })),
    totalMinor: total,
    issuedAt: now,
    expiresAt: now + lifetime,
    keyId: opts.keyId ?? `${opts.merchant}-key`,
  }
  return { ...unsigned, signature: await signCanonicalPayloadEd25519(canonCart(unsigned), opts.merchantPrivateKey) }
}

export async function issuePaymentMandate(opts: {
  agentPrivateKey: string
  agent: string
  intent: IntentMandate
  cart: CartMandate
  lifetimeMs?: number
  keyId?: string
  now?: number
}): Promise<PaymentMandate> {
  const lifetime = opts.lifetimeMs ?? 5 * 60_000
  checkLifetime(lifetime, MAX_PAYMENT_LIFETIME_MS, 'issuePaymentMandate')
  const now = opts.now ?? Date.now()
  const unsigned: Omit<PaymentMandate, 'signature'> = {
    version: MANDATE_VERSION,
    kind: 'payment',
    id: `pay-${now}-${randomHex(8)}`,
    intentId: opts.intent.id,
    cartId: opts.cart.id,
    cartDigest: await cartDigest(opts.cart),
    merchant: opts.cart.merchant,
    agent: opts.agent,
    amountMinor: opts.cart.totalMinor,
    currency: opts.cart.currency,
    issuedAt: now,
    expiresAt: now + lifetime,
    keyId: opts.keyId ?? `${opts.agent}-key`,
  }
  return { ...unsigned, signature: await signCanonicalPayloadEd25519(canonPayment(unsigned), opts.agentPrivateKey) }
}

// ---------------------------------------------------------------------------
// Spend ledger
// ---------------------------------------------------------------------------

export type ReserveOutcome = 'reserved' | 'duplicate' | 'exceeds-ceiling'

/**
 * Where cumulative spend is recorded. `reserve` MUST be atomic per intent: two
 * concurrent payments must not both pass a ceiling only one of them fits under. It must
 * also be idempotent per `paymentId`: presenting the same payment twice reserves once.
 * {@link MemorySpendLedger} is atomic within one process; a replicated deployment needs a
 * store with a real atomic check-and-add (a database transaction, a Redis script).
 */
export interface SpendLedger {
  reserve(args: { intentId: string; paymentId: string; amountMinor: number; ceilingMinor: number }): Promise<ReserveOutcome>
  /** Give a reservation back, e.g. when the charge failed downstream. Idempotent. */
  release(args: { intentId: string; paymentId: string }): Promise<void>
  spent(intentId: string): Promise<number>
}

export class MemorySpendLedger implements SpendLedger {
  private readonly byIntent = new Map<string, Map<string, number>>()

  async reserve(args: { intentId: string; paymentId: string; amountMinor: number; ceilingMinor: number }): Promise<ReserveOutcome> {
    if (!isMoney(args.amountMinor) || !isPositive(args.ceilingMinor)) throw new Error('MemorySpendLedger: amounts must be non-negative integers')
    let payments = this.byIntent.get(args.intentId)
    if (!payments) {
      payments = new Map()
      this.byIntent.set(args.intentId, payments)
    }
    if (payments.has(args.paymentId)) return 'duplicate'
    let total = args.amountMinor
    for (const v of payments.values()) total += v
    if (!Number.isSafeInteger(total) || total > args.ceilingMinor) return 'exceeds-ceiling'
    payments.set(args.paymentId, args.amountMinor)
    return 'reserved'
  }

  async release(args: { intentId: string; paymentId: string }): Promise<void> {
    this.byIntent.get(args.intentId)?.delete(args.paymentId)
  }

  async spent(intentId: string): Promise<number> {
    let total = 0
    for (const v of this.byIntent.get(intentId)?.values() ?? []) total += v
    return total
  }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export type PaymentFailure =
  | 'malformed'
  | 'unsupported-version'
  | 'no-payer-key'
  | 'no-merchant-key'
  | 'no-agent-key'
  | 'invalid-intent-signature'
  | 'invalid-cart-signature'
  | 'invalid-payment-signature'
  | 'intent-expired'
  | 'cart-expired'
  | 'payment-expired'
  | 'not-yet-valid'
  | 'lifetime-too-long'
  | 'payer-mismatch'
  | 'agent-mismatch'
  | 'merchant-mismatch'
  | 'intent-mismatch'
  | 'cart-mismatch'
  | 'currency-mismatch'
  | 'cart-total-wrong'
  | 'amount-mismatch'
  | 'merchant-not-allowed'
  | 'category-not-allowed'
  | 'exceeds-per-purchase-limit'
  | 'exceeds-total-limit'
  | 'approval-required'
  | 'approval-invalid'
  | 'already-charged'

export type PaymentVerifyResult =
  | { ok: true; intent: IntentMandate; cart: CartMandate; payment: PaymentMandate; spentMinor: number; approvedBy?: string }
  | { ok: false; reason: PaymentFailure; detail?: string }

export interface VerifyPaymentOptions {
  intent: IntentMandate
  cart: CartMandate
  payment: PaymentMandate
  /** Public keys of payers, merchants and agents (separate registries: a merchant key never signs an intent). */
  payerKeys: Pick<KeyRegistry, 'getPublicKey'>
  merchantKeys: Pick<KeyRegistry, 'getPublicKey'>
  agentKeys: Pick<KeyRegistry, 'getPublicKey'>
  /** Where the spend is recorded. Required: without it the cumulative ceiling is not enforced. */
  ledger: SpendLedger
  /** The payer this processor is acting for. */
  expectedPayer: string
  /** The merchant being paid. */
  expectedMerchant: string
  /** A human approval for this payment, when the intent requires one. */
  approval?: {
    grant: ApprovalGrant | null
    approverKeys: ApproverKeyLookup
    allowedApprovers: readonly string[]
    replayStore?: ReplayStore
  }
  now?: number
  clockSkewMs?: number
}

/** The action a human approval for a payment is bound to. */
export function paymentApprovalAction(payment: PaymentMandate): { method: string; path: string; bodySha256: string } {
  // Reuses the approval module's action shape: the approver signs THIS payment and nothing else.
  return { method: 'PAY', path: `/mandate/${payment.id}`, bodySha256: payment.cartDigest }
}

function shape(intent: IntentMandate, cart: CartMandate, payment: PaymentMandate): boolean {
  return (
    intent?.kind === 'intent' &&
    cart?.kind === 'cart' &&
    payment?.kind === 'payment' &&
    typeof intent.signature === 'string' &&
    typeof cart.signature === 'string' &&
    typeof payment.signature === 'string' &&
    typeof intent.constraints === 'object' &&
    intent.constraints !== null &&
    Array.isArray(cart.items) &&
    Number.isSafeInteger(intent.issuedAt) &&
    Number.isSafeInteger(intent.expiresAt) &&
    Number.isSafeInteger(cart.issuedAt) &&
    Number.isSafeInteger(cart.expiresAt) &&
    Number.isSafeInteger(payment.issuedAt) &&
    Number.isSafeInteger(payment.expiresAt) &&
    isMoney(cart.totalMinor) &&
    isMoney(payment.amountMinor) &&
    CURRENCY.test(intent.constraints.currency) &&
    isPositive(intent.constraints.maxTotalMinor)
  )
}

export async function verifyPayment(opts: VerifyPaymentOptions): Promise<PaymentVerifyResult> {
  const { intent, cart, payment } = opts
  const fail = (reason: PaymentFailure, detail?: string): PaymentVerifyResult => ({ ok: false, reason, ...(detail ? { detail } : {}) })
  if (!shape(intent, cart, payment)) return fail('malformed')
  if (intent.version !== MANDATE_VERSION || cart.version !== MANDATE_VERSION || payment.version !== MANDATE_VERSION) return fail('unsupported-version')

  const now = opts.now ?? Date.now()
  const skew = opts.clockSkewMs ?? MAX_CLOCK_SKEW_MS

  // --- lifetimes ---
  if (intent.expiresAt <= intent.issuedAt || intent.expiresAt - intent.issuedAt > MAX_INTENT_LIFETIME_MS) return fail('lifetime-too-long', 'intent')
  if (cart.expiresAt <= cart.issuedAt || cart.expiresAt - cart.issuedAt > MAX_CART_LIFETIME_MS) return fail('lifetime-too-long', 'cart')
  if (payment.expiresAt <= payment.issuedAt || payment.expiresAt - payment.issuedAt > MAX_PAYMENT_LIFETIME_MS) return fail('lifetime-too-long', 'payment')
  if (intent.issuedAt > now + skew || cart.issuedAt > now + skew || payment.issuedAt > now + skew) return fail('not-yet-valid')
  if (now >= intent.expiresAt) return fail('intent-expired')
  if (now >= cart.expiresAt) return fail('cart-expired')
  if (now >= payment.expiresAt) return fail('payment-expired')

  // --- who is who ---
  if (intent.payer !== opts.expectedPayer) return fail('payer-mismatch')
  if (cart.merchant !== opts.expectedMerchant || payment.merchant !== opts.expectedMerchant) return fail('merchant-mismatch')
  if (payment.agent !== intent.agent) return fail('agent-mismatch')

  // --- the chain hangs together ---
  if (cart.intentId !== intent.id || payment.intentId !== intent.id) return fail('intent-mismatch')
  if (payment.cartId !== cart.id) return fail('cart-mismatch')
  if (cart.currency !== intent.constraints.currency || payment.currency !== intent.constraints.currency) return fail('currency-mismatch')

  // --- signatures ---
  const payerKey = await opts.payerKeys.getPublicKey(intent.payer)
  if (!payerKey) return fail('no-payer-key')
  const merchantKey = await opts.merchantKeys.getPublicKey(cart.merchant)
  if (!merchantKey) return fail('no-merchant-key')
  const agentKey = await opts.agentKeys.getPublicKey(payment.agent)
  if (!agentKey) return fail('no-agent-key')
  {
    const { signature, ...rest } = intent
    if (!(await verifyCanonicalPayloadEd25519(canonIntent(rest), signature, payerKey))) return fail('invalid-intent-signature')
  }
  {
    const { signature, ...rest } = cart
    if (!(await verifyCanonicalPayloadEd25519(canonCart(rest), signature, merchantKey))) return fail('invalid-cart-signature')
  }
  {
    const { signature, ...rest } = payment
    if (!(await verifyCanonicalPayloadEd25519(canonPayment(rest), signature, agentKey))) return fail('invalid-payment-signature')
  }

  // --- the money: recompute, never trust ---
  const computed = checkedTotal(cart.items)
  if (computed === null || computed !== cart.totalMinor) return fail('cart-total-wrong')
  if (payment.cartDigest !== (await cartDigest(cart))) return fail('cart-mismatch', 'digest')
  if (payment.amountMinor !== cart.totalMinor) return fail('amount-mismatch')

  // --- the intent's constraints ---
  const c = intent.constraints
  if (c.merchants && !c.merchants.includes(cart.merchant)) return fail('merchant-not-allowed')
  if (c.categories) {
    for (const item of cart.items) {
      if (item.category === undefined || !c.categories.includes(item.category)) return fail('category-not-allowed', item.sku)
    }
  }
  if (c.maxPerPurchaseMinor !== undefined && payment.amountMinor > c.maxPerPurchaseMinor) return fail('exceeds-per-purchase-limit')
  if (payment.amountMinor > c.maxTotalMinor) return fail('exceeds-total-limit')

  // --- record the spend atomically, then ask for the human ---
  // Reserving first means a payment that would break the ceiling never spends (consumes) a human
  // approval. If the approval then fails, the reservation is handed back.
  const outcome = await opts.ledger.reserve({
    intentId: intent.id,
    paymentId: payment.id,
    amountMinor: payment.amountMinor,
    ceilingMinor: c.maxTotalMinor,
  })
  if (outcome === 'duplicate') return fail('already-charged')
  if (outcome === 'exceeds-ceiling') return fail('exceeds-total-limit', 'cumulative')

  let approvedBy: string | undefined
  if (c.requireApprovalAboveMinor !== undefined && payment.amountMinor > c.requireApprovalAboveMinor) {
    const release = async (): Promise<void> => opts.ledger.release({ intentId: intent.id, paymentId: payment.id })
    if (!opts.approval || opts.approval.grant === null) {
      await release()
      return fail('approval-required')
    }
    const result = await verifyApproval(opts.approval.grant, {
      approverKeys: opts.approval.approverKeys,
      allowedApprovers: opts.approval.allowedApprovers,
      subject: payment.agent,
      action: paymentApprovalAction(payment),
      replayStore: opts.approval.replayStore,
      now,
      clockSkewMs: skew,
    })
    if (!result.ok) {
      await release()
      return fail('approval-invalid', result.reason)
    }
    approvedBy = result.grant.approver
  }
  return { ok: true, intent, cart, payment, spentMinor: await opts.ledger.spent(intent.id), ...(approvedBy ? { approvedBy } : {}) }
}
