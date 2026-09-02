# @7h3/protocol-webmcp

**WebMCP gives agents hands. This gives those hands a signature, a scope, and a receipt.**

A deterministic authorization layer for [WebMCP](https://webmachinelearning.github.io/webmcp/)
(`document.modelContext`) tool calls, built on the [7h3 Protocol](https://github.com/IceMasterT/7h3-protocol)
signing, capability and replay primitives. Pure Web Crypto, zero dependencies,
runs unchanged in a page, a Worker, or a test process.

---

## The gap this fills

WebMCP lets a page hand an agent real, authenticated, signed-in capability. The
guidance around it is candid about what that costs — and about what it does not
solve.

Chrome's [agent security guidance](https://developer.chrome.com/docs/agents/security)
is entirely **probabilistic**: prompt-injection classifiers, "spotlighting"
untrusted content, critic LLMs. It is explicitly silent on authentication,
authorization and provenance.

OpenAI's site-tools guidance is blunter:

> Website-provided tool definitions and results are untrusted content.
> **A tool's name or claim that it only reads data isn't proof of what it does.**

> Use your application's **existing** authentication, authorization, and input validation.

But no site has an existing authorization model for *delegated agent action* —
"this agent, these tools, this ceiling, for the next ten minutes". So the advice
bottoms out on something that mostly doesn't exist yet.

This package is that missing layer, and it is deterministic. **A refusal here is
a failed signature or an uncovered scope, not a judgement call.** You cannot
prompt-inject your way past a signature check.

It complements the probabilistic defenses rather than replacing them: classifiers
decide what an agent *should* do; this bounds what it *can* do.

---

## Install

```bash
npm install @7h3/protocol-webmcp @7h3/protocol
```

## Use

`registerTool` keeps the exact WebMCP signature and adds three optional fields —
`scope`, `limit`, `confirm`. Existing tools need one import and one wrapper.

```js
import { guard } from '@7h3/protocol-webmcp'

const g = guard({ origin: 'ledger.example', privateKey, publicKey })

await g.registerTool({
  name: 'pay_invoice',
  description: 'Pay an open invoice from the operating account.',
  inputSchema: {
    type: 'object',
    properties: { id: { type: 'string' }, amountCents: { type: 'number' } },
    required: ['id', 'amountCents'],
    additionalProperties: false,
  },
  annotations: { destructiveHint: true },
  scope: 'money/pay_invoice',              // ← capability required
  limit: { field: 'amountCents', max: 2_000_00 }, // ← ceiling the site never exceeds
  execute: async ({ id }) => ledger.payInvoice(id),
})

// The human consents, in the page, to a scoped and expiring grant:
await g.grant({
  subject: 'chatgpt-agent',
  scopes: ['money/pay_invoice'],
  caps: { amountCents: 50_00 },  // bound *inside* the signed token
  ttlMs: 10 * 60_000,
})
```

For reference, the underlying WebMCP call this wraps:

```javascript
document.modelContext.registerTool({
  name: "search_products",
  description: "Search the product catalog",
  inputSchema: { /* ... */ },
  execute: async (input) => { /* ... */ }
});
```

---

## Adopting it in an app that already has WebMCP tools

A guarded tool is shape-compatible with an unguarded one, so adoption is an
import, a constructor, and one field per tool you want to protect:

```diff
+import { guard } from '@7h3/protocol-webmcp'
+
+const g = guard({ origin: 'shop.example', privateKey, publicKey })

-await document.modelContext.registerTool({
+await g.registerTool({
   name: 'place_order',
   description: 'Place an order for the current cart',
   inputSchema: { /* unchanged */ },
   annotations: { destructiveHint: true },
+  scope: 'orders/place',
+  limit: { field: 'amountCents', max: 500_00 },
   execute: async ({ cartId }) => placeOrder(cartId),   // unchanged
 })
```

Your handler does not change, and neither does the schema an agent sees. Tools
you leave on `document.modelContext` keep working exactly as before, so you can
adopt one tool at a time.

Or generate it. The repo's MCP server ships a WebMCP scaffold target:

```
7h3_scaffold framework="webmcp" sender="shop.example"
```

```bash
claude mcp add 7h3-protocol -- npx -y @7h3/protocol-mcp
```

---

## Three primitives

### 1. Signed tool manifests — provenance

The page signs its own tool surface: name, description, input schema and
annotations of every tool. Serve it at a well-known path and anyone can check
that the tools an agent sees are the tools the origin published.

```js
const manifest = await g.manifest()          // Ed25519-signed, with a surface digest
await verifyManifest(manifest, originPubKey) // { ok: true }

// Catches the tool-surface poisoning class of attack:
await diffAgainstManifest(liveTools, manifest)
// → { ok: false, added: ['list_invoices_v2'], removed: [], modified: [] }
```

An injected lookalike tool, a silently reworded description, or a removed tool
all change the surface. This turns "a tool's claim" into something checkable.

**Two keys, deliberately.** The *origin identity key* is long-lived, lives on the
deploy machine, and signs the manifest — only its public half is served. The
*session key* is generated in the browser per visitor and signs that visitor's
grants and receipts. Conflating them would mean shipping a private key in the
bundle, which is exactly the mistake a signing layer must not make.

Sign at deploy time from a declarative tool table, with no handlers in scope —
`manifestEntry` accepts a `ToolSurface`, which is a tool minus its `execute`:

```js
const entries = await Promise.all(TOOL_DEFS.map(manifestEntry))
const manifest = await signManifest({ origin, entries, privateKey, keyId })
// → serve at /.well-known/7h3-webmcp-manifest.json, public key at /.well-known/7h3-keys.json
```

The page then fetches both, verifies the manifest under the published key, and
diffs it against the tools actually registered. Anyone can run the same check
from outside the page.

### 2. Capability-scoped execution — authorization

Grants are **page-held by default**: the token never passes through the agent, so
a prompt-injected agent cannot exfiltrate it. Serializing a chain into the
reserved `__7h3_grant` input supports deliberate cross-agent delegation.

Numeric ceilings are encoded as reserved `caps/<field>/<max>` scopes, so a spend
cap is **bound inside the signed token** rather than trusted from page state. A
grant can tighten a tool's ceiling; it can never loosen it.

Refusals are structured, not thrown, so an agent can read *why* and ask the human
for authority:

| Reason | Meaning |
|---|---|
| `no-active-grant` | nothing authorizes this scope |
| `scope-not-covered` | the active grant does not reach this tool |
| `grant-expired` / `grant-revoked` | authority lapsed or was withdrawn |
| `grant-invalid-signature` | the grant does not verify |
| `limit-exceeded` | the value exceeds the authorized ceiling |
| `replayed-call` | this nonce was already used |
| `confirmation-denied` | a human declined |

### 3. Hash-chained receipts — audit

Every call is recorded, **allowed and refused**. Each receipt carries the hash of
its predecessor, so the log is tamper-evident as a whole rather than entry by
entry — deletion and reordering are detectable, which independently-signed
entries cannot catch. Inputs are hashed, not stored, so a receipt proves *what*
happened without disclosing the payload.

```js
const result = await verifyChain(g.receipts.all(), publicKey)
// → { ok: false, brokenAt: 3, reason: 'bad-signature' }
```

---

## Honest threat model

This is worth stating plainly, because overselling a security boundary is worse
than not having one.

- **What it does.** Bounds what an agent can do to what a human explicitly, and
  verifiably, authorized — and makes every attempt provable after the fact.
  Enforcement is cryptographic and runs before your handler.
- **What it does not do.** It cannot stop a fully compromised agent acting
  *inside* a scope it was legitimately granted. If you grant `money/**` with a
  $10,000 cap, a hijacked agent can spend $10,000. Grant narrowly and briefly.
- **It is not an anti-prompt-injection system.** It is the layer that makes a
  successful prompt injection *bounded and auditable* rather than unbounded and
  invisible. Keep the probabilistic defenses too.
- **Page-held grants are not bearer tokens** — that is the default and the safer
  mode. Explicitly delegated `__7h3_grant` chains *are* bearer credentials within
  their scope and TTL, in the same sense as OAuth scopes or macaroons.
- **A compromised page is out of scope.** Script running in your origin can
  register its own tools; that is what the signed manifest is for — it makes the
  tampering *detectable*, not impossible.

---

## API

| Export | Purpose |
|---|---|
| `guard(options)` | Create a `ToolGuard` |
| `.registerTool(tool, opts?)` | WebMCP registration, wrapped |
| `.grant(request)` | Issue a scoped, expiring capability |
| `.revoke(grantId)` | Withdraw authority; effective on the next call |
| `.activeGrants()` | Unexpired, unrevoked grants |
| `.manifest()` | Sign the current tool surface |
| `.invoke(name, input)` | Run a tool through the identical wrapper (tests, non-WebMCP browsers) |
| `.receipts` | The hash-chained `ReceiptLog` |
| `.on(listener)` | Subscribe to registrations, grants, and calls |
| `verifyChain(entries, key)` | Verify a receipt chain, reporting the first break |
| `verifyManifest(m, key)` | Verify a signed manifest |
| `diffAgainstManifest(live, m)` | Detect injected, modified or removed tools |
| `isWebMcpSupported()` | Feature-detect `document.modelContext` |

## Testing

```bash
npm test   # from the repo root; 46 tests cover this package
```

Covering refusal on every path, expiry, revocation, ceiling tightening, replay,
receipt tamper detection (edit / delete / reorder / forge) and surface poisoning.

## License

Apache-2.0
