# Install: WebMCP

**Signed, capability-scoped, receipted tools for browser agents.**

[WebMCP](https://webmachinelearning.github.io/webmcp/) lets a page hand an AI
agent real capability on a live, signed-in session via
`document.modelContext.registerTool`. This package adds the authorization layer
underneath it — **a refusal is a failed signature or an uncovered scope, not a
judgement call.**

> **Live demo:** <https://7h3-webmcp-ledger.tech-b1a.workers.dev>

---

## 1. Install

> **Note:** `@7h3/protocol-webmcp` is not yet on npm. Install from source until
> it is published; the API below is final and will not change on publish.

```bash
git clone https://github.com/IceMasterT/7h3-protocol.git
cd 7h3-protocol && npm install && npm run build:protocol
```

Then reference it from your app. With a bundler, alias the package to the
source — both it and the core are pure Web Crypto with zero dependencies, so
they bundle for the browser unchanged:

```ts
// vite.config.ts
import { fileURLToPath } from 'node:url'

export default {
  resolve: {
    alias: [
      { find: /^@7h3\/protocol-webmcp$/, replacement: fileURLToPath(new URL('../7h3-protocol/sdk/webmcp/src/index.ts', import.meta.url)) },
      { find: /^@7h3\/protocol$/,        replacement: fileURLToPath(new URL('../7h3-protocol/src/index.ts', import.meta.url)) },
    ],
  },
}
```

Once published, this becomes:

```bash
npm install @7h3/protocol-webmcp @7h3/protocol
```

## 2. Two platform rules that bite first

- **HTTPS only.** WebMCP requires a secure context. `localhost` counts.
- **Top-level page only.** Tools registered inside an iframe — same-origin or
  cross-origin — are **not discoverable**. Register in the top-level document.

## 3. Generate the scaffold (optional)

```bash
npx 7h3 add --framework webmcp --sender your-origin.example
```

## 4. Wrap your tools

`guard.registerTool` takes the exact `document.modelContext.registerTool`
descriptor plus three optional fields — `scope`, `limit`, `confirm`. Your
handler and the schema an agent sees are unchanged.

```ts
import { guard, isWebMcpSupported } from '@7h3/protocol-webmcp'
import { generateEd25519KeypairBase64Url } from '@7h3/protocol'

if (isWebMcpSupported()) {
  const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
  const g = guard({ origin: 'shop.example', privateKey, publicKey })

  // Unguarded read: no scope, so no grant required.
  await g.registerTool({
    name: 'search_products',
    description: 'Search the product catalog',
    inputSchema: { type: 'object', properties: { query: { type: 'string' } }, additionalProperties: false },
    annotations: { readOnlyHint: true },
    execute: async ({ query }) => searchProducts(String(query)),
  })

  // Guarded write: scope gates it, limit is a ceiling the site never exceeds.
  await g.registerTool({
    name: 'place_order',
    description: 'Place an order for the current cart',
    inputSchema: {
      type: 'object',
      properties: { cartId: { type: 'string' }, amountCents: { type: 'number' } },
      required: ['cartId', 'amountCents'],
      additionalProperties: false,
    },
    annotations: { destructiveHint: true },
    scope: 'orders/place',
    limit: { field: 'amountCents', max: 500_00 },
    execute: async ({ cartId }) => placeOrder(String(cartId)),
  })
}
```

## 5. Let the human grant authority

Never grant automatically. Wire this to a consent control in your own UI:

```ts
await g.grant({
  subject: 'browser-agent',
  scopes: ['orders/place'],
  caps: { amountCents: 100_00 },  // ceiling bound INSIDE the signed token
  ttlMs: 10 * 60_000,             // authority lapses on its own
})

g.revoke(grantId)   // takes effect on the very next call
```

Grants are **held page-side by default** — the token never passes through the
agent, so a prompt-injected one cannot exfiltrate it.

## 6. Adopting into an app that already has WebMCP tools

```diff
+import { guard } from '@7h3/protocol-webmcp'
+
+const g = guard({ origin: 'shop.example', privateKey, publicKey })

-await document.modelContext.registerTool({
+await g.registerTool({
   name: 'place_order',
   description: 'Place an order for the current cart',
   inputSchema: { /* unchanged */ },
+  scope: 'orders/place',
+  limit: { field: 'amountCents', max: 500_00 },
   execute: async ({ cartId }) => placeOrder(cartId),   // unchanged
 })
```

Tools left on `document.modelContext` keep working, so you can adopt one tool
at a time.

## 7. Publish a signed tool manifest (recommended)

OpenAI's own guidance says *"a tool's name or claim that it only reads data
isn't proof of what it does."* A manifest signed by your origin key is that
proof.

Sign at **deploy time**, from a declarative tool table, using a key the browser
never sees:

```ts
import { manifestEntry, signManifest } from '@7h3/protocol-webmcp'

const entries = await Promise.all(TOOL_DEFS.map(manifestEntry))
const manifest = await signManifest({ origin, entries, privateKey, keyId })
// serve at /.well-known/7h3-webmcp-manifest.json
// serve the public key at /.well-known/7h3-keys.json
```

Then verify the live surface against it in the page:

```ts
const verified = await verifyManifest(manifest, originPublicKey)
const diff = await diffAgainstManifest(g.registeredTools(), manifest)
// → { ok: false, added: ['list_invoices_fast'], removed: [], modified: [] }
```

That catches a lookalike tool injected by a third-party script or XSS.

## 8. Read the receipts

Every call is recorded — allowed *and* refused — on a hash-chained,
Ed25519-signed log. Inputs are hashed, not stored.

```ts
const result = await verifyChain(g.receipts.all(), publicKey)
// → { ok: false, brokenAt: 3, reason: 'bad-signature' }

g.on((event) => {
  if (event.type === 'call') console.log(event.receipt.outcome, event.receipt.tool)
})
```

## Refusal reasons

| Reason | Meaning |
|---|---|
| `no-active-grant` | Nothing authorizes this scope |
| `scope-not-covered` | The active grant does not reach this tool |
| `grant-expired` / `grant-revoked` | Authority lapsed or was withdrawn |
| `grant-invalid-signature` | The grant does not verify |
| `limit-exceeded` | Value exceeds the authorized ceiling |
| `replayed-call` | This nonce was already used |
| `confirmation-denied` | A human declined |

Refusals are returned as structured data, not thrown, so an agent can read
*why* and call your `request_access`-style tool to ask for authority.

## Testing without a WebMCP browser

`g.invoke(name, input)` runs the **identical** guarded wrapper — there is no
path that skips `decide()` — so you can exercise a tool surface in any browser
or in tests.

## What this does not protect against

Stated plainly, because overselling a security boundary is worse than not
having one:

- It **cannot** stop a compromised agent acting *inside* a scope it was
  legitimately granted. Grant narrowly and briefly.
- It is **not** an anti-prompt-injection system. It makes a successful
  injection bounded and auditable instead of unbounded and invisible. Keep the
  probabilistic defenses too.
- A **compromised page** is out of scope — script on your own origin can
  register its own tools. That is what the signed manifest is for: it makes the
  tampering *detectable*, not impossible.

Full API and threat model: [`sdk/webmcp/README.md`](../../sdk/webmcp/README.md)
