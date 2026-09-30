# Payment mandates

An agent that can pay is an agent that can be tricked into paying. A mandate chain makes
"the agent was allowed to buy this" something a merchant or payment processor can check
cryptographically, and makes the limits real.

Status: TypeScript reference implementation (`@7h3/protocol`).

**Modelled on, not compatible with.** The intent → cart → payment structure follows the
shape agentic-commerce protocols such as AP2 use. These are 7h3's own signed documents,
not those protocols' wire formats or credentials, and no payment rail is contacted. The
module decides whether a charge is **authorized**; moving the money is yours.

All amounts are integers in **minor units** (cents). Floating point never touches money.

## The chain

| Mandate | Signed by | Says |
|---|---|---|
| **Intent** | the **payer** | which agent may spend, in what currency, up to what cumulative total and per purchase, at which merchants, in which item categories, until when, and whether a human must approve large purchases |
| **Cart** | the **merchant** | the exact items, quantities, unit prices and total being sold, bound to one intent |
| **Payment** | the **agent** | the instruction to charge: names the intent, the cart (by digest), the amount and the merchant |

The agent cannot inflate a price the merchant did not sign, and the merchant cannot be bound
to a price it did not quote. The three registries are separate (`payerKeys`, `merchantKeys`,
`agentKeys`): a merchant key never signs an intent.

```ts
import { issueIntentMandate, issueCartMandate, issuePaymentMandate, verifyPayment, MemorySpendLedger } from '@7h3/protocol'

// Payer, once:
const intent = await issueIntentMandate({
  payerPrivateKey, payer: 'alice', agent: 'agent.travel',
  constraints: { currency: 'USD', maxTotalMinor: 100_000, maxPerPurchaseMinor: 50_000,
                 merchants: ['airline.example'], categories: ['travel'], requireApprovalAboveMinor: 30_000 },
  lifetimeMs: 7 * 24 * 3_600_000,
})
// Merchant, per quote:
const cart = await issueCartMandate({ merchantPrivateKey, merchant: 'airline.example', intentId: intent.id, currency: 'USD', items })
// Agent, to buy:
const payment = await issuePaymentMandate({ agentPrivateKey, agent: 'agent.travel', intent, cart })

// Processor:
const result = await verifyPayment({
  intent, cart, payment, payerKeys, merchantKeys, agentKeys, ledger,
  expectedPayer: 'alice', expectedMerchant: 'airline.example',
  approval: { grant, approverKeys, allowedApprovers: ['alice'] }, // when the intent requires one
})
```

## What `verifyPayment` enforces

- **Signatures** from the right party on each of the three mandates; **the chain hangs
  together**: same intent, cart and payment ids, same currency, the payment's agent is the
  intent's agent, the merchant is the one the processor expects.
- **The money is recomputed, never trusted.** The cart total must equal the sum of
  `quantity × unitMinor`; the payment amount must equal the cart total; the payment commits
  to the cart's digest, so a second validly signed cart with the same id cannot be swapped in.
- **The intent's constraints**: merchant allow-list; every item must carry an allowed
  category (an item with no category is not allowed when categories are set); per-purchase
  and total limits.
- **The cumulative ceiling** across all purchases, through a `SpendLedger`: the reservation
  is atomic, so two concurrent payments that together exceed the ceiling cannot both
  succeed, and it is idempotent per payment id, so presenting the same payment twice
  charges once.
- **Human approval for large purchases.** When `requireApprovalAboveMinor` is set and the
  amount exceeds it, an approval grant ([`APPROVAL_AND_PROVENANCE.md`](./APPROVAL_AND_PROVENANCE.md))
  bound to exactly this payment (`paymentApprovalAction`) is required. The spend is reserved
  first, so a payment that would break the ceiling never consumes an approval; if the
  approval then fails, the reservation is given back.
- **Short lifetimes**: intents up to 30 days, carts up to 1 hour, payment mandates up to 15
  minutes. Anything longer is refused even if validly signed.

A failed verification records no spend.

## The ledger

`MemorySpendLedger` is atomic within one process. A replicated processor needs a store with
a real atomic check-and-add and per-payment idempotency (a database transaction, a Redis
script): implement the three-method `SpendLedger` interface on top of it. Call `release`
if the charge fails downstream so the reservation does not eat the ceiling.

## Not covered

- Moving money, refunds, disputes and chargebacks.
- Identity proofing of the payer: the intent proves that the holder of the payer key
  authorized it, not who that person is.
- Crypto-native payment protocols (for example x402). Their signatures are over different
  primitives; a mandate can still gate whether the agent may initiate such a payment.
