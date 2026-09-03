# Testing the live demo

**Live URL:** <https://7h3-webmcp-ledger.tech-b1a.workers.dev>

This is a WebMCP application. **Every route registers tools on
`document.modelContext` — 19 across four routes**, including the landing page,
so an agent has real work to do wherever it lands. Each tool is wrapped in a
cryptographic guard, which is what the project is actually about: WebMCP gives
an agent hands, and this gives those hands a signature, a scope, and a receipt.

| Route | WebMCP tools registered | What the agent can do there |
|---|---|---|
| [`/`](https://7h3-webmcp-ledger.tech-b1a.workers.dev/) — Hub | **3** — `list_demos`, `explain_7h3`, `open_demo` | Discover the site and navigate it unaided |
| [`/ledger`](https://7h3-webmcp-ledger.tech-b1a.workers.dev/ledger) — Ledger | **10** — 3 read, 7 write | Run a business console: invoice, pay, refund, wire, export |
| [`/compare`](https://7h3-webmcp-ledger.tech-b1a.workers.dev/compare) — Same attack, twice | **4** — all guarded | Attack the same books with and without the guard |
| [`/verify`](https://7h3-webmcp-ledger.tech-b1a.workers.dev/verify) — Verify it yourself | **2** | Produce receipts, then break them by hand |

**WebMCP is native — there is nothing to install.** It ships inside Chrome 149+
behind a flag, and inside the ChatGPT desktop app's browser as **site tools**.
No Web Store extension, no add-on, no shim. Part 1 gets you connected in about a
minute.

> **Part 1 is the main event** — an agent discovering and calling these tools is
> the whole submission. Part 2 exists only so a judge whose browser won't
> cooperate is never blocked; it drives the *identical* guarded wrapper.

---

# Part 1 — Drive it with a real agent

## A. ChatGPT desktop app (site tools)

### Requirements

| | |
|---|---|
| App | **ChatGPT desktop**, latest version |
| Model | **GPT-5.6 Sol** or **GPT-5.6 Terra** — *Luna has WebMCP disabled* |
| Workspace | **Not** Enterprise or Edu |
| Setting | Settings → Browser → Permissions → **Enable site tools** = on |

### Step 1 — The agent discovers the site by itself

1. Open the ChatGPT desktop app.
2. Open **<https://7h3-webmcp-ledger.tech-b1a.workers.dev/>** in the app's
   built-in browser — not an external one.
3. Click **Site tools** in the address bar → **Available site tools**.
   **3 tools**: `list_demos`, `explain_7h3`, `open_demo`.
4. Ask:

   > What demos are on this page, and open the one that shows the attack.

   The agent calls `list_demos`, reads the catalog, then calls `open_demo` — and
   you land on `/compare` without having typed a URL. Ask *"what does this
   protocol actually add to WebMCP?"* and it answers from `explain_7h3` rather
   than from its own guesswork.

   `open_demo` accepts only a path that is literally one of the three published
   demos. Hand it anything else and it throws instead of navigating — even
   navigation is a checked capability.

### Step 2 — Ten tools, and a refusal that isn't a judgement call

Navigate to **`/ledger`** and re-open **Site tools**: now **10 tools**, 3 read
and 7 write. Then ask, in order:

**1.** > Pay invoice INV-1043 for me.

→ Refused: **`no-active-grant`**. Nothing authorizes `money/pay_invoice` yet.
The model didn't decline — a signature check failed before the handler ran.

**2.** Click **Bookkeeper · pay ≤ $50** in the page, then ask again.

→ Succeeds. The grant now shows `caps/amountCents/5000`: the ceiling is signed
*into* the capability token, not held in page state.

**3.** > Also pay INV-1042.  *(that one is $1,850)*

→ Refused: **`limit-exceeded — amountCents=185000 exceeds the authorized
ceiling of 5000`**. The agent has a valid grant and still cannot exceed it.

**4.** > Delete invoice INV-1041.

→ Refused: **`scope-not-covered`**. The grant covers payments, not deletions.

**5.** > Ask the owner for permission to settle the overdue invoices.

→ The agent calls `request_access` and *you* approve or deny **in the page**.
Approve, and its retry succeeds. This is the part that only WebMCP makes
possible: agent and human negotiating scope on the same live page, with the
approval minting the grant.

**6.** Click **Verify chain**, then **Simulate tampering**, then **Inject a
poisoned tool** → `UNPUBLISHED TOOL: list_invoices_fast`. A lookalike tool
registered at runtime — exactly what an injected script or XSS payload would do
— fails the diff against the signed manifest.

### Step 3 — Let the agent run the attack

Navigate to **`/compare`** (4 registered tools) and ask:

> Use the site tools to pay INV-1042, wire $900 to XX-9931-OFFSHORE, delete
> INV-1041, and export every customer.

Every one comes back refused, each naming its own reason. Then press **Run the
attack on both** to see those same four calls land against an unguarded copy of
the books.

### Tips

- Grant **only** Bookkeeper for step 3. If Full admin is also active the refusal
  correctly reports the $1,000 ceiling instead of $50 — accurate, but it muddies
  the beat.
- **Reload between runs.** All state is in memory, so a refresh is a clean slate.
- Do the poisoned-tool step **last**; the injected tool stays registered until
  you reload.
- If a tool is listed but never called, ask more directly: *"Use the pay_invoice
  tool to pay INV-1043."*
- **Replay last call** only reports `replayed-call` after a call that
  *succeeded* — scope and limit checks run before the replay check.

## B. Chrome 149+ (built-in flag)

1. Check `chrome://version` — you need **149 or later**.
2. Go to `chrome://flags/#enable-webmcp-testing`, set **Enabled**, relaunch.
3. Open **<https://7h3-webmcp-ledger.tech-b1a.workers.dev/>**.

The header pill should read **"WebMCP detected"**. Confirm in DevTools:

```js
typeof document.modelContext                // 'object'
typeof document.modelContext.registerTool   // 'function'
window.isSecureContext                      // true
```

Then run the same script as section A.

### Calling the tools directly from the console

Chrome can expose a testing surface, so you can invoke the registered tools
yourself without an agent attached. Launch Chrome with:

```
--enable-features=WebMCPTesting,DevToolsWebMCPSupport
```

which exposes `navigator.modelContextTesting` for listing and invoking every
tool the page registered — the guarded wrappers, not the raw handlers.

---

# Part 2 — If you can't get a WebMCP browser

Not a stripped-down mode: these pages register the same WebMCP tools, and the
in-page controls call the same wrapper (`guard.invoke`) the agent's tool call
reaches. **There is no code path that skips `decide()`.** The only thing missing
is the agent doing the asking.

## `/compare` — Same attack, twice

One click, about two seconds, and the clearest single answer to *"what does the
guard actually prevent?"*

The page runs one compromised agent's four actions against **two identical
copies of the same books** — one wired straight to its handlers the way most
apps ship, one behind the guard. Same tools, same inputs, same order.

Click **Run the attack on both**. The actions are `pay_invoice` ($1,850),
`wire_funds` ($900 to `XX-9931-OFFSHORE`), `delete_invoice`, and
`export_customers`.

| | Unguarded | Guarded |
|---|---|---|
| Attacks succeeded | **4 of 4** | **0 of 4** |
| Outstanding balance | $2,317.50 → **$47.50** | $2,317.50 |
| Invoices remaining | 5 → **4** | 5 |
| Customer records exposed | **4** | 0 |
| Signed receipts written | **0** | 4 |

The last row is the quiet one: the unguarded side keeps **no record that any of
it happened**.

## `/verify` — Verify it yourself

For anyone who shouldn't have to trust a UI.

**§1 — the signed grant.** Note `caps/amountCents/5000` in the scope list: the
$50 ceiling is signed *into* the token, so raising it invalidates the signature.

**§2 — the receipt chain.** Three entries — one allowed, two refused — each
carrying `prevHash`, the SHA-256 of the entry before it. The chain is an
editable textarea; edit it by hand or use the buttons.

| Click | Expect |
|---|---|
| **Verify chain** (unmodified) | `chain intact · 3 receipt(s) verified` |
| **Flip a refusal to allowed** | `BROKEN at receipt #1 · bad-signature` |
| **Delete a receipt** | `BROKEN at receipt #1 · seq-mismatch: expected 1, got 2` |
| **Reset** | back to intact |

Deletion is the instructive case: **each surviving receipt still verifies on its
own.** Only the chain notices the gap — which is exactly why receipts are linked
rather than merely signed.

**§3 — the published manifest.** Click **Fetch and verify the manifest**:

```
verified under 7h3-webmcp-ledger-origin-k1 — 10 tools
```

---

# Part 3 — Verifying provenance from outside the page

The manifest is signed at deploy time by a key the browser never holds, and
served as a static file:

```bash
curl https://7h3-webmcp-ledger.tech-b1a.workers.dev/.well-known/7h3-webmcp-manifest.json
curl https://7h3-webmcp-ledger.tech-b1a.workers.dev/.well-known/7h3-keys.json
```

It covers the Ledger's ten tools — 3 read, 7 write — with a `surfaceDigest` over
the per-tool digests, signed under `7h3-webmcp-ledger-origin-k1`. The key
document publishes the matching public key, so the signature can be checked
without trusting the page that served it.

To check it yourself against the published package rather than this repo:

```bash
npm i @7h3/protocol-webmcp
```

```js
// check.mjs
import { verifyManifest } from '@7h3/protocol-webmcp'
const B = 'https://7h3-webmcp-ledger.tech-b1a.workers.dev'
const m = await (await fetch(`${B}/.well-known/7h3-webmcp-manifest.json`)).json()
const kd = await (await fetch(`${B}/.well-known/7h3-keys.json`)).json()
const k = kd.keys.find((x) => x.keyId === m.keyId)
console.log(m.tools.length, 'tools →', await verifyManifest(m, k.publicKey))
```

```bash
node check.mjs
```

Expected output:

```
10 tools → { ok: true }
```

---

## What to look for

| Signal | Where |
|---|---|
| **3 tools** in ChatGPT's Site tools on `/`, **10** on `/ledger` | WebMCP registration |
| The agent calling `list_demos` then `open_demo` unprompted | WebMCP discovery |
| `no-active-grant`, `scope-not-covered`, `limit-exceeded` | Refusals, in the receipt feed |
| `caps/amountCents/5000` inside the grant | `/ledger` active grants, `/verify` §1 |
| `UNPUBLISHED TOOL: list_invoices_fast` | `/ledger` → **Inject a poisoned tool** |
| `4 of 4` vs `0 of 4` | `/compare` |
| `chain intact · 3 receipt(s) verified` | `/verify` → **Verify chain** |
| `BROKEN at receipt #1 · bad-signature` | `/verify` → **Flip a refusal to allowed** |
| `BROKEN at receipt #1 · seq-mismatch` | `/verify` → **Delete a receipt** |
| `verified under 7h3-webmcp-ledger-origin-k1 — 10 tools` | `/verify` → manifest |

Every call — allowed **and** refused — is appended to a hash-chained,
Ed25519-signed receipt log. Inputs are hashed, not stored.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| No **Site tools** entry in ChatGPT | Wrong model (use Sol or Terra), site tools disabled in Settings, or an Enterprise/Edu workspace |
| Site tools list is empty | The page hadn't finished loading — registration is async. Reload |
| "no WebMCP agent here" in Chrome | Flag not enabled, or Chrome older than 149. The tools are registered regardless; nothing is attached to call them |
| Looking for an extension to install | There isn't one, by design — WebMCP is built into the browser |
| Tools listed but never called | The agent chose not to. Ask directly: *"Use the pay_invoice tool to pay INV-1043."* |
| Everything refused on `/ledger` | No grant is active — click a preset under **Grant access** |
| Nothing works after a while | Grants expire (2–10 min by design). Issue a new one |
| `/compare` shows `3 of 4` unguarded | You ran it twice; the first run already paid and deleted those records, so the repeats fail on their own. Reload for a clean `4 of 4` |
